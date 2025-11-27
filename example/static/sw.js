self.addEventListener('push', function(event) {
    console.log('Push event received:', event);
    let data = { title: 'Notification', body: '' };

    if (event.data) {
        try {
            data = event.data.json();
            console.log('Push data:', data);
        } catch (e) {
            data.body = event.data.text();
            console.log('Push text:', data.body);
        }
    }

    console.log('About to create notification options');
    const options = {
        body: data.body || '',
        icon: data.icon || '',
        badge: data.badge || '',
        data: data.data || {},
        requireInteraction: true,
        tag: 'push-notification-' + Date.now()
    };

    console.log('Showing notification with title:', data.title, 'options:', options);
    event.waitUntil(
        self.registration.showNotification(data.title || 'Notification', options)
            .then(() => console.log('Notification shown successfully'))
            .catch(err => console.error('Failed to show notification:', err))
    );
});

self.addEventListener('notificationclick', function(event) {
    event.notification.close();
    
    if (event.notification.data && event.notification.data.url) {
        event.waitUntil(
            clients.openWindow(event.notification.data.url)
        );
    }
});

// Handle subscription change events (triggered when VAPID key changes)
self.addEventListener('pushsubscriptionchange', function(event) {
    console.log('Push subscription changed:', event);
    
    // Notify all clients that they need to resubscribe
    event.waitUntil(
        self.clients.matchAll({ type: 'window' }).then(function(clients) {
            clients.forEach(function(client) {
                client.postMessage({
                    type: 'SUBSCRIPTION_CHANGED',
                    message: 'Push subscription has changed. Please resubscribe.'
                });
            });
        })
    );
});
