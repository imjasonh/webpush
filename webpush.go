// Package webpush provides functionality to send Web Push API notifications
// using VAPID authentication.
package webpush

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

// Subscription represents a Web Push subscription from a client.
type Subscription struct {
	Endpoint string `json:"endpoint"`
	Keys     Keys   `json:"keys"`
}

// Keys contains the client's encryption keys.
type Keys struct {
	P256dh string `json:"p256dh"` // Client's ECDH public key
	Auth   string `json:"auth"`   // Client's authentication secret
}

// Options configures the web push notification.
type Options struct {
	TTL     int    // Time-to-live in seconds (default 2419200 = 4 weeks)
	Urgency string // Urgency level: very-low, low, normal, high
	Topic   string // Topic for message replacement
}

// Signer provides VAPID signing functionality.
type Signer interface {
	// Sign signs the given data and returns the signature.
	Sign(ctx context.Context, data []byte) ([]byte, error)
	// PublicKey returns the ECDSA public key in uncompressed format.
	PublicKey() []byte
}

// Client sends web push notifications.
type Client struct {
	signer     Signer
	httpClient *http.Client
	subject    string // VAPID subject (mailto: or https: URL)
}

// NewClient creates a new web push client.
func NewClient(signer Signer, subject string) *Client {
	return &Client{
		signer:     signer,
		httpClient: http.DefaultClient,
		subject:    subject,
	}
}

// WithHTTPClient sets a custom HTTP client.
func (c *Client) WithHTTPClient(httpClient *http.Client) *Client {
	c.httpClient = httpClient
	return c
}

// Send sends a web push notification to the given subscription.
func (c *Client) Send(ctx context.Context, sub *Subscription, payload []byte, opts *Options) error {
	if opts == nil {
		opts = &Options{}
	}
	if opts.TTL == 0 {
		opts.TTL = 2419200 // 4 weeks default
	}

	// Encrypt the payload
	encrypted, err := encrypt(sub, payload)
	if err != nil {
		return fmt.Errorf("encrypting payload: %w", err)
	}

	// Create the VAPID header
	vapidHeader, err := c.createVAPIDHeader(ctx, sub.Endpoint)
	if err != nil {
		return fmt.Errorf("creating VAPID header: %w", err)
	}

	// Create and send the request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sub.Endpoint, bytes.NewReader(encrypted.ciphertext))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", vapidHeader)
	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("TTL", strconv.Itoa(opts.TTL))

	if opts.Urgency != "" {
		req.Header.Set("Urgency", opts.Urgency)
	}
	if opts.Topic != "" {
		req.Header.Set("Topic", opts.Topic)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("push service returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

type encryptedPayload struct {
	ciphertext []byte
}

// encrypt encrypts the payload using RFC 8291 message encryption.
func encrypt(sub *Subscription, plaintext []byte) (*encryptedPayload, error) {
	// Decode subscription keys
	p256dhBytes, err := base64.RawURLEncoding.DecodeString(sub.Keys.P256dh)
	if err != nil {
		return nil, fmt.Errorf("decoding p256dh: %w", err)
	}

	authBytes, err := base64.RawURLEncoding.DecodeString(sub.Keys.Auth)
	if err != nil {
		return nil, fmt.Errorf("decoding auth: %w", err)
	}

	// Parse client's public key
	clientPubKey, err := ecdh.P256().NewPublicKey(p256dhBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing client public key: %w", err)
	}

	// Generate ephemeral key pair for encryption
	serverPrivKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating server key: %w", err)
	}
	serverPubKey := serverPrivKey.PublicKey()

	// Perform ECDH to get shared secret
	sharedSecret, err := serverPrivKey.ECDH(clientPubKey)
	if err != nil {
		return nil, fmt.Errorf("computing shared secret: %w", err)
	}

	// Generate salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}

	// Derive keys using HKDF per RFC 8291
	prkInfo := append([]byte("WebPush: info\x00"), clientPubKey.Bytes()...)
	prkInfo = append(prkInfo, serverPubKey.Bytes()...)

	// IKM = HKDF-Extract(auth_secret, ecdh_secret)
	prkHKDF := hkdf.New(sha256.New, sharedSecret, authBytes, prkInfo)
	prk := make([]byte, 32)
	if _, err := io.ReadFull(prkHKDF, prk); err != nil {
		return nil, fmt.Errorf("deriving PRK: %w", err)
	}

	// Derive content encryption key
	cekInfo := []byte("Content-Encoding: aes128gcm\x00")
	cekHKDF := hkdf.New(sha256.New, prk, salt, cekInfo)
	cek := make([]byte, 16)
	if _, err := io.ReadFull(cekHKDF, cek); err != nil {
		return nil, fmt.Errorf("deriving CEK: %w", err)
	}

	// Derive nonce
	nonceInfo := []byte("Content-Encoding: nonce\x00")
	nonceHKDF := hkdf.New(sha256.New, prk, salt, nonceInfo)
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(nonceHKDF, nonce); err != nil {
		return nil, fmt.Errorf("deriving nonce: %w", err)
	}

	// Encrypt using AES-128-GCM
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	// Add padding delimiter (0x02 for last record)
	padded := append(plaintext, 0x02)

	ciphertext := gcm.Seal(nil, nonce, padded, nil)

	// Build the aes128gcm payload header
	// Format: salt (16) || rs (4) || idlen (1) || keyid (65 for P-256 uncompressed)
	recordSize := uint32(len(ciphertext) + 86) // header + ciphertext
	header := make([]byte, 0, 86)
	header = append(header, salt...)
	header = binary.BigEndian.AppendUint32(header, recordSize)
	header = append(header, byte(len(serverPubKey.Bytes())))
	header = append(header, serverPubKey.Bytes()...)

	return &encryptedPayload{
		ciphertext: append(header, ciphertext...),
	}, nil
}

// createVAPIDHeader creates the VAPID Authorization header.
func (c *Client) createVAPIDHeader(ctx context.Context, endpoint string) (string, error) {
	// Parse the endpoint to get the origin for the audience
	parsedURL, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parsing endpoint: %w", err)
	}
	audience := parsedURL.Scheme + "://" + parsedURL.Host

	// Create JWT header and claims
	header := map[string]string{
		"typ": "JWT",
		"alg": "ES256",
	}

	claims := map[string]interface{}{
		"aud": audience,
		"exp": time.Now().Add(12 * time.Hour).Unix(),
		"sub": c.subject,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshaling header: %w", err)
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshaling claims: %w", err)
	}

	// Build the signing input
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Hash the signing input
	hash := sha256.Sum256([]byte(signingInput))

	// Sign with ECDSA
	signature, err := c.signer.Sign(ctx, hash[:])
	if err != nil {
		return "", fmt.Errorf("signing JWT: %w", err)
	}

	// Build the JWT
	jwt := signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)

	// Get public key in URL-safe base64
	pubKeyB64 := base64.RawURLEncoding.EncodeToString(c.signer.PublicKey())

	return "vapid t=" + jwt + ", k=" + pubKeyB64, nil
}

// ParseSubscription parses a subscription from JSON.
func ParseSubscription(data []byte) (*Subscription, error) {
	var sub Subscription
	if err := json.Unmarshal(data, &sub); err != nil {
		return nil, fmt.Errorf("unmarshaling subscription: %w", err)
	}
	if sub.Endpoint == "" {
		return nil, errors.New("subscription endpoint is required")
	}
	if sub.Keys.P256dh == "" {
		return nil, errors.New("subscription p256dh key is required")
	}
	if sub.Keys.Auth == "" {
		return nil, errors.New("subscription auth key is required")
	}
	// Validate endpoint is HTTPS
	if !strings.HasPrefix(sub.Endpoint, "https://") {
		return nil, errors.New("subscription endpoint must use HTTPS")
	}
	return &sub, nil
}
