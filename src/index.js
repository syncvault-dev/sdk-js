import { encrypt, decrypt, prepareAuthPassword, decryptFromServer } from './crypto.js';

export { encrypt, decrypt, decryptFromServer };

const DEFAULT_SERVER = 'https://api.syncvault.dev';

export class SyncVaultError extends Error {
  constructor(message, statusCode, data) {
    super(message);
    this.name = 'SyncVaultError';
    this.statusCode = statusCode;
    this.data = data;
  }
}

export class SyncVault {
  constructor(options = {}) {
    if (!options.appToken) {
      throw new Error('appToken is required');
    }

    this.appToken = options.appToken;
    this.serverUrl = options.serverUrl || DEFAULT_SERVER;
    this.redirectUri = options.redirectUri || null;
    this.token = null;
    this.password = null;
  }

  /**
   * Generate OAuth authorization URL
   * Redirect users to this URL to start the OAuth flow
   */
  getAuthUrl(state = null) {
    if (!this.redirectUri) {
      throw new Error('redirectUri is required for OAuth flow');
    }

    const params = new URLSearchParams({
      app_token: this.appToken,
      redirect_uri: this.redirectUri
    });

    if (state) {
      params.set('state', state);
    }

    return `${this.serverUrl}/api/oauth/authorize?${params}`;
  }

  /**
   * Exchange authorization code for access token (OAuth flow)
   * Call this after user is redirected back with the code
   */
  async exchangeCode(code, password) {
    const response = await this._request('/api/oauth/token', {
      method: 'POST',
      body: JSON.stringify({
        code,
        app_token: this.appToken,
        redirect_uri: this.redirectUri
      })
    });

    this.token = response.access_token;
    this.password = password;

    return response.user;
  }

  /**
   * Authenticate user with SyncVault (direct auth - requires valid app token)
   */
  async auth(username, password) {
    const authPassword = await prepareAuthPassword(password);
    const response = await this._request('/api/user/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password: authPassword })
    });

    this.token = response.token;
    this.password = password;

    return response.user;
  }

  /**
   * Register a new user (direct auth - requires valid app token)
   */
  async register(username, password) {
    const authPassword = await prepareAuthPassword(password);
    const response = await this._request('/api/user/auth/register', {
      method: 'POST',
      body: JSON.stringify({ username, password: authPassword })
    });

    this.token = response.token;
    this.password = password;

    return response.user;
  }

  /**
   * Set authentication state manually (e.g., from stored session)
   */
  setAuth(token, password) {
    this.token = token;
    this.password = password;
  }

  /**
   * Store encrypted data
   * @param {string} path - File path
   * @param {any} data - Data to encrypt and store
   * @param {Object} options - Optional settings
   * @param {number} options.updatedAt - Timestamp for LWW conflict resolution
   */
  async put(path, data, options = {}) {
    this._checkAuth();

    const encrypted = await encrypt(data, this.password);
    const body = { path, data: encrypted };
    
    if (options.updatedAt) {
      body.updatedAt = new Date(options.updatedAt).toISOString();
    }

    const response = await this._request('/api/sync/put', {
      method: 'POST',
      body: JSON.stringify(body)
    });

    return response;
  }

  /**
   * Retrieve and decrypt data
   */
  async get(path) {
    this._checkAuth();

    const response = await this._request(`/api/sync/get?path=${encodeURIComponent(path)}`);

    return decrypt(response.data, this.password);
  }

  /**
   * List all files
   */
  async list() {
    this._checkAuth();

    const response = await this._request('/api/sync/list');

    return response.files;
  }

  /**
   * Delete a file
   */
  async delete(path) {
    this._checkAuth();

    const response = await this._request('/api/sync/delete', {
      method: 'POST',
      body: JSON.stringify({ path })
    });

    return response;
  }

  /**
   * Get app metadata for current user (unencrypted, server-side data)
   */
  async getMetadata() {
    this._checkAuth();

    const response = await this._request('/api/sync/metadata');
    return response.metadata;
  }

  /**
   * Set app metadata for current user (replaces all metadata)
   */
  async setMetadata(metadata) {
    this._checkAuth();

    const response = await this._request('/api/sync/metadata', {
      method: 'POST',
      body: JSON.stringify({ metadata })
    });

    return response.metadata;
  }

  /**
   * Update app metadata for current user (merges with existing)
   */
  async updateMetadata(metadata) {
    this._checkAuth();

    const response = await this._request('/api/sync/metadata', {
      method: 'PATCH',
      body: JSON.stringify({ metadata })
    });

    return response.metadata;
  }

  /**
   * Get entitlements for current user (read-only, set by developer's backend)
   * Entitlements are used for subscription status, feature flags, etc.
   */
  async getEntitlements() {
    this._checkAuth();

    const response = await this._request('/api/sync/entitlements');
    return response.entitlements;
  }

  /**
   * Get user storage quota info for the current app
   */
  async getQuota() {
    this._checkAuth();

    return this._request('/api/sync/quota');
  }

  // --- Shared Vaults ---

  /**
   * Get all shared vaults the user has access to in this app
   */
  async getSharedVaults() {
    this._checkAuth();

    return this._request('/api/sync/shared/vaults');
  }

  /**
   * List files in a shared vault
   */
  async listShared(vaultId) {
    this._checkAuth();

    const response = await this._request(`/api/sync/shared/${vaultId}/list`);
    return response.files;
  }

  /**
   * Store encrypted data in a shared vault
   */
  async putShared(vaultId, path, data, sharedPassword) {
    this._checkAuth();

    const encrypted = await encrypt(data, sharedPassword || this.password);

    return this._request(`/api/sync/shared/${vaultId}/put`, {
      method: 'POST',
      body: JSON.stringify({ path, data: encrypted })
    });
  }

  /**
   * Retrieve and decrypt data from a shared vault
   */
  async getShared(vaultId, path, sharedPassword) {
    this._checkAuth();

    const response = await this._request(`/api/sync/shared/${vaultId}/get?path=${encodeURIComponent(path)}`);
    return decrypt(response.data, sharedPassword || this.password);
  }

  /**
   * Delete a file from a shared vault
   */
  async deleteShared(vaultId, path) {
    this._checkAuth();

    return this._request(`/api/sync/shared/${vaultId}/delete`, {
      method: 'POST',
      body: JSON.stringify({ path })
    });
  }

  /**
   * Check if user is authenticated
   */
  isAuthenticated() {
    return this.token !== null && this.password !== null;
  }

  /**
   * Clear authentication state
   */
  logout() {
    this.token = null;
    this.password = null;
  }

  /**
   * Get current user info
   */
  async getUser() {
    this._checkAuth();

    return this._request('/api/user/auth/me');
  }

  _checkAuth() {
    if (!this.token || !this.password) {
      throw new Error('Not authenticated. Call auth() or register() first.');
    }
  }

  async _request(path, options = {}) {
    const url = `${this.serverUrl}${path}`;

    const headers = {
      'Content-Type': 'application/json',
      'X-App-Token': this.appToken
    };

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const response = await fetch(url, {
      ...options,
      headers: {
        ...headers,
        ...options.headers
      }
    });

    const data = await response.json();

    if (!response.ok) {
      throw new SyncVaultError(
        data.error || 'Request failed',
        response.status,
        data
      );
    }

    return data;
  }
}

/**
 * Server-side client for app backends to write data on behalf of users.
 * Requires server_write OAuth scope to be granted by users.
 * 
 * Data is encrypted with the user's public key (RSA-OAEP),
 * so only the user can decrypt it with their private key.
 */
export class SyncVaultServer {
  constructor(options = {}) {
    if (!options.appToken) {
      throw new Error('appToken is required');
    }
    if (!options.secretToken) {
      throw new Error('secretToken is required for server-side operations');
    }

    this.appToken = options.appToken;
    this.secretToken = options.secretToken;
    this.serverUrl = options.serverUrl || DEFAULT_SERVER;
  }

  /**
   * Get user's public key for encryption
   */
  async getUserPublicKey(userId) {
    return this._request(`/api/server/user/${userId}/public-key`);
  }

  /**
   * Encrypt data with user's public key (RSA-OAEP + AES-GCM hybrid)
   */
  async encryptForUser(data, publicKeyPem) {
    // Parse PEM to get raw key bytes
    const pemBody = publicKeyPem
      .replace(/-----BEGIN PUBLIC KEY-----/, '')
      .replace(/-----END PUBLIC KEY-----/, '')
      .replace(/\s+/g, '');
    const publicKeyBuffer = Uint8Array.from(atob(pemBody), c => c.charCodeAt(0));
    
    const publicKey = await crypto.subtle.importKey(
      'spki',
      publicKeyBuffer,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['encrypt']
    );

    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(JSON.stringify(data));
    
    // Generate random AES key
    const aesKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt']
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptedData = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      dataBuffer
    );

    // Web Crypto returns ciphertext with authTag appended
    // We need to separate them for our format
    const encryptedArray = new Uint8Array(encryptedData);
    const authTag = encryptedArray.slice(-16);
    const ciphertext = encryptedArray.slice(0, -16);

    const rawAesKey = await crypto.subtle.exportKey('raw', aesKey);
    const encryptedAesKey = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      publicKey,
      rawAesKey
    );

    // Pack: encryptedAesKey (256 bytes) + iv (12 bytes) + authTag (16 bytes) + ciphertext
    const result = new Uint8Array(
      encryptedAesKey.byteLength + iv.byteLength + authTag.byteLength + ciphertext.byteLength
    );
    let offset = 0;
    result.set(new Uint8Array(encryptedAesKey), offset);
    offset += encryptedAesKey.byteLength;
    result.set(iv, offset);
    offset += iv.byteLength;
    result.set(authTag, offset);
    offset += authTag.byteLength;
    result.set(ciphertext, offset);

    return btoa(String.fromCharCode(...result));
  }

  /**
   * Write pre-encrypted data to user's storage
   */
  async putForUser(userId, path, encryptedData) {
    return this._request(`/api/server/user/${userId}/put`, {
      method: 'POST',
      body: JSON.stringify({ path, data: encryptedData })
    });
  }

  /**
   * Encrypt and store data for user in one call
   */
  async writeForUser(userId, path, data) {
    const { publicKey } = await this.getUserPublicKey(userId);
    const encrypted = await this.encryptForUser(data, publicKey);
    return this.putForUser(userId, path, encrypted);
  }

  /**
   * List files in user's storage for this app
   */
  async listForUser(userId) {
    return this._request(`/api/server/user/${userId}/list`);
  }

  async _request(path, options = {}) {
    const url = `${this.serverUrl}${path}`;

    const headers = {
      'Content-Type': 'application/json',
      'X-App-Token': this.appToken,
      'X-Secret-Token': this.secretToken
    };

    const response = await fetch(url, {
      ...options,
      headers: {
        ...headers,
        ...options.headers
      }
    });

    const responseData = await response.json();

    if (!response.ok) {
      throw new SyncVaultError(
        responseData.error || 'Request failed',
        response.status,
        responseData
      );
    }

    return responseData;
  }
}

export { OfflineSyncVault, OfflineStore, createOfflineClient } from './offline.js';
