package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
)

// KMSSigner implements the Signer interface using Google Cloud KMS.
type KMSSigner struct {
	client    *kms.KeyManagementClient
	keyName   string
	publicKey []byte // uncompressed format
}

// NewKMSSigner creates a new KMS-backed signer.
// keyName should be in the format:
// projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{key}/cryptoKeyVersions/{version}
func NewKMSSigner(ctx context.Context, keyName string) (*KMSSigner, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating KMS client: %w", err)
	}

	// Fetch the public key
	resp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: keyName,
	})
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("getting public key: %w", err)
	}

	// Parse the PEM-encoded public key
	block, _ := pem.Decode([]byte(resp.Pem))
	if block == nil {
		client.Close()
		return nil, fmt.Errorf("failed to parse public key PEM")
	}

	pubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	ecdsaPubKey, ok := pubKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		client.Close()
		return nil, fmt.Errorf("key is not ECDSA")
	}

	if ecdsaPubKey.Curve != elliptic.P256() {
		client.Close()
		return nil, fmt.Errorf("key must be P-256 curve")
	}

	// Convert to uncompressed format
	pubKey := elliptic.Marshal(ecdsaPubKey.Curve, ecdsaPubKey.X, ecdsaPubKey.Y)

	return &KMSSigner{
		client:    client,
		keyName:   keyName,
		publicKey: pubKey,
	}, nil
}

// Sign signs the given data using KMS and returns the signature in IEEE P1363 format.
func (s *KMSSigner) Sign(ctx context.Context, data []byte) ([]byte, error) {
	// KMS expects the hash directly for ECDSA signing
	resp, err := s.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: s.keyName,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: data,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("signing with KMS: %w", err)
	}

	// KMS returns DER-encoded signature, convert to IEEE P1363 format
	return derToP1363(resp.Signature)
}

// PublicKey returns the ECDSA public key in uncompressed format.
func (s *KMSSigner) PublicKey() []byte {
	return s.publicKey
}

// Close closes the underlying KMS client.
func (s *KMSSigner) Close() error {
	return s.client.Close()
}

// derToP1363 converts a DER-encoded ECDSA signature to IEEE P1363 format.
func derToP1363(der []byte) ([]byte, error) {
	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return nil, fmt.Errorf("parsing DER signature: %w", err)
	}

	// Convert to IEEE P1363 format (r || s, each 32 bytes for P-256)
	result := make([]byte, 64)
	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()
	copy(result[32-len(rBytes):32], rBytes)
	copy(result[64-len(sBytes):64], sBytes)

	return result, nil
}
