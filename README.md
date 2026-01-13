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

### Metadata Methods

App metadata is unencrypted data stored server-side. Use it for app-specific logic like subscription status, feature flags, or user preferences that don't need encryption.

#### `vault.getMetadata()`
Get app metadata for the current user.

#### `vault.setMetadata(metadata)`
Set app metadata (replaces all existing metadata).

#### `vault.updateMetadata(metadata)`
Update app metadata (merges with existing metadata).

```javascript
// Example: Store subscription status
await vault.setMetadata({
  subscriptionActive: true,
  subscriptionExpiresAt: '2026-12-31',
  plan: 'premium'
});

// Read metadata
const meta = await vault.getMetadata();
console.log(meta.subscriptionActive); // true

// Update specific fields
await vault.updateMetadata({ lastLogin: new Date().toISOString() });
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

Note: Metadata is NOT encrypted - use it only for non-sensitive app logic.
