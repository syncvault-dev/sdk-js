# @syncvault/sdk

Zero-knowledge sync SDK for Node.js and browsers.

## Installation

```bash
npm install @syncvault/sdk
```

## Quick Start (OAuth Flow - Recommended)

```javascript
import { SyncVault } from '@syncvault/sdk';

const vault = new SyncVault({
  appToken: 'your_app_token',
  redirectUri: 'http://localhost:3000/callback',
  serverUrl: 'https://api.syncvault.io' // optional
});

// Step 1: Redirect user to authorize
const authUrl = vault.getAuthUrl();
window.location.href = authUrl;

// Step 2: After redirect, exchange code for token
// The user will be redirected to: http://localhost:3000/callback?code=xxx
const urlParams = new URLSearchParams(window.location.search);
const code = urlParams.get('code');

// User must provide their encryption password
const password = prompt('Enter your encryption password:');
const user = await vault.exchangeCode(code, password);

// Step 3: Use the SDK
await vault.put('data.json', { hello: 'world' });
const data = await vault.get('data.json');
```

## Quick Start (Direct Auth)

```javascript
import { SyncVault } from '@syncvault/sdk';

const vault = new SyncVault({
  appToken: 'your_app_token',
  serverUrl: 'https://api.syncvault.io' // optional
});

// Authenticate user directly
await vault.auth('username', 'password');

// Store data (automatically encrypted)
await vault.put('notes/my-note.json', { 
  title: 'Hello', 
  content: 'World' 
});

// Retrieve data (automatically decrypted)
const note = await vault.get('notes/my-note.json');
```

## API Reference

### Constructor

```javascript
new SyncVault({
  appToken: string,      // Required: Your app token from developer dashboard
  serverUrl?: string,    // Optional: API URL (default: https://api.syncvault.dev)
  redirectUri?: string   // Required for OAuth flow
})
```

### OAuth Methods

#### `vault.getAuthUrl(state?)`
Generate OAuth authorization URL. Redirect users here to start the flow.

#### `vault.exchangeCode(code, password)`
Exchange authorization code for access token. Call this after user returns with the code.

#### `vault.setAuth(token, password)`
Manually set authentication state (e.g., from stored session).

### Direct Auth Methods

#### `vault.auth(username, password)`
Authenticate user directly. Requires valid app token.

#### `vault.register(username, password)`
Register new user. Requires valid app token.

### Data Methods

#### `vault.put(path, data)`
Store encrypted data at the given path.

#### `vault.get(path)`
Retrieve and decrypt data from the given path.

#### `vault.list()`
List all files for this app.

#### `vault.delete(path)`
Delete a file.

### Metadata Methods (Preferences)

Metadata is unencrypted data for app preferences like theme, timezone, language. Use it for settings that don't need encryption and are needed for app logic.

#### `vault.getMetadata()`
Get preferences for the current user.

#### `vault.setMetadata(metadata)`
Set preferences (replaces all existing).

#### `vault.updateMetadata(metadata)`
Update preferences (merges with existing).

```javascript
// Example: Store user preferences
await vault.setMetadata({
  theme: 'dark',
  timezone: 'UTC',
  language: 'en'
});

// Read preferences
const prefs = await vault.getMetadata();
console.log(prefs.theme); // 'dark'

// Update specific fields
await vault.updateMetadata({ language: 'es' });
```

### Entitlements Methods

Entitlements are read-only data set by the developer's backend. Use them for subscription status, feature flags, etc. Users can read but not modify entitlements.

#### `vault.getEntitlements()`
Get entitlements for the current user.

```javascript
// Read entitlements (set by developer backend)
const entitlements = await vault.getEntitlements();
console.log(entitlements.plan); // 'premium'
console.log(entitlements.features); // ['advanced', 'export']
```

### Quota Methods

#### `vault.getQuota()`
Get user's storage quota information.

```javascript
const quota = await vault.getQuota();
console.log(quota.quotaBytes);   // 10485760 (10MB) or null if unlimited
console.log(quota.usedBytes);    // 1048576 (1MB)
console.log(quota.unlimited);    // false
```

### State Methods

#### `vault.isAuthenticated()`
Check if user is authenticated.

#### `vault.logout()`
Clear authentication state.

#### `vault.getUser()`
Get current user info.

## App Permissions

Apps can request specific permissions when created:
- `read` - Read user data
- `write` - Create and update user data
- `delete` - Delete user data

Users see these permissions during OAuth authorization.

## Encryption

All data is encrypted client-side using AES-256-GCM with a key derived from the user's password using PBKDF2 (100,000 iterations). The server never sees unencrypted data.

Note: Metadata (preferences) and entitlements are NOT encrypted - use them only for non-sensitive settings and subscription status.

## Setting Entitlements (Developer Backend)

Entitlements can only be set from your backend using both the app token and secret token:

```javascript
// On your backend (e.g., after payment webhook)
await fetch(`https://api.syncvault.dev/api/entitlements/${userId}`, {
  method: 'PUT',
  headers: {
    'Content-Type': 'application/json',
    'X-App-Token': process.env.SYNCVAULT_APP_TOKEN,
    'X-Secret-Token': process.env.SYNCVAULT_SECRET_TOKEN
  },
  body: JSON.stringify({
    entitlements: {
      plan: 'premium',
      features: ['advanced', 'export'],
      expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()
    }
  })
});
```

Never expose the secret token in client-side code.

## Offline Sync

The SDK supports offline-first sync with local caching and automatic retry.

### Basic Usage

```javascript
import { SyncVault, createOfflineClient } from '@syncvault/sdk';

const baseClient = new SyncVault({ appToken: 'your_token' });
const vault = createOfflineClient(baseClient, {
  retryInterval: 30000,  // Retry every 30 seconds
  maxRetries: 10,        // Max retries per operation
  autoSync: true         // Auto-sync when online
});

// Initialize (loads cache from storage)
await vault.init();

// Authenticate
await vault.auth('username', 'password');

// Put - queues if offline, syncs when online
await vault.put('data.json', { hello: 'world' });

// Get - returns cached data if offline
const data = await vault.get('data.json');

// Check pending operations
if (vault.hasPendingChanges()) {
  console.log('Pending:', vault.pendingCount());
}
```

### Callbacks

```javascript
vault.onSyncSuccess = (op) => {
  console.log('Synced:', op.path);
};

vault.onSyncError = (op, error) => {
  console.log('Failed:', op.path, error);
};
```

### Manual Sync Control

```javascript
// Manually trigger sync
await vault.syncPending();

// Stop auto-sync
vault.stopAutoSync();

// Clear cache/queue
await vault.getStore().clearCache();
await vault.getStore().clearQueue();
```

### Custom Storage (React Native, etc.)

```javascript
const customStorage = {
  async get(key) {
    return AsyncStorage.getItem(key).then(JSON.parse);
  },
  async set(key, value) {
    await AsyncStorage.setItem(key, JSON.stringify(value));
  },
  async remove(key) {
    await AsyncStorage.removeItem(key);
  }
};

const vault = createOfflineClient(baseClient, { storage: customStorage });
```
