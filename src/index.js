import { encrypt, decrypt, prepareAuthPassword } from './crypto.js';

const DEFAULT_SERVER = 'https://api.syncvault.dev';

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
   */
  async put(path, data) {
    this._checkAuth();

    const encrypted = await encrypt(data, this.password);

    const response = await this._request('/api/sync/put', {
      method: 'POST',
      body: JSON.stringify({ path, data: encrypted })
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
      throw new Error(data.error || 'Request failed');
    }

    return data;
  }
}

export { encrypt, decrypt } from './crypto.js';
