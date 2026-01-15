import { encrypt, decrypt } from './crypto.js';

const DEFAULT_STORE_NAME = 'syncvault-offline';
const CACHE_KEY = 'cache';
const QUEUE_KEY = 'queue';

/**
 * Storage adapter interface
 */
class MemoryStorage {
  constructor() {
    this.data = new Map();
  }
  
  async get(key) {
    return this.data.get(key) || null;
  }
  
  async set(key, value) {
    this.data.set(key, value);
  }
  
  async remove(key) {
    this.data.delete(key);
  }
}

/**
 * LocalStorage adapter (browser)
 */
class LocalStorageAdapter {
  constructor(prefix = DEFAULT_STORE_NAME) {
    this.prefix = prefix;
  }
  
  async get(key) {
    const item = localStorage.getItem(`${this.prefix}:${key}`);
    return item ? JSON.parse(item) : null;
  }
  
  async set(key, value) {
    localStorage.setItem(`${this.prefix}:${key}`, JSON.stringify(value));
  }
  
  async remove(key) {
    localStorage.removeItem(`${this.prefix}:${key}`);
  }
}

/**
 * Offline store for caching and queue management
 */
export class OfflineStore {
  constructor(storage = null) {
    this.storage = storage || this._detectStorage();
    this.cache = {};
    this.queue = [];
    this.loaded = false;
  }
  
  _detectStorage() {
    if (typeof localStorage !== 'undefined') {
      return new LocalStorageAdapter();
    }
    return new MemoryStorage();
  }
  
  async load() {
    if (this.loaded) return;
    
    const cache = await this.storage.get(CACHE_KEY);
    const queue = await this.storage.get(QUEUE_KEY);
    
    this.cache = cache || {};
    this.queue = queue || [];
    this.loaded = true;
  }
  
  async persist() {
    await this.storage.set(CACHE_KEY, this.cache);
    await this.storage.set(QUEUE_KEY, this.queue);
  }
  
  getCached(path) {
    return this.cache[path] || null;
  }
  
  async setCache(path, data) {
    this.cache[path] = {
      path,
      data,
      updatedAt: Date.now()
    };
    await this.persist();
  }
  
  async removeCache(path) {
    delete this.cache[path];
    await this.persist();
  }
  
  async queueOperation(op) {
    op.id = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    op.createdAt = Date.now();
    op.retries = 0;
    this.queue.push(op);
    await this.persist();
  }
  
  getPendingOperations() {
    return [...this.queue];
  }
  
  async removeOperation(id) {
    this.queue = this.queue.filter(op => op.id !== id);
    await this.persist();
  }
  
  async incrementRetry(id) {
    const op = this.queue.find(op => op.id === id);
    if (op) {
      op.retries++;
      await this.persist();
    }
  }
  
  hasPendingOperations() {
    return this.queue.length > 0;
  }
  
  async clearQueue() {
    this.queue = [];
    await this.persist();
  }
  
  async clearCache() {
    this.cache = {};
    await this.persist();
  }
}

/**
 * Check if error is network-related
 */
function isNetworkError(error) {
  if (!error) return false;
  const msg = error.message?.toLowerCase() || '';
  return (
    error.name === 'TypeError' ||
    msg.includes('network') ||
    msg.includes('failed to fetch') ||
    msg.includes('load failed') ||
    msg.includes('offline') ||
    msg.includes('timeout') ||
    msg.includes('econnrefused') ||
    msg.includes('enotfound')
  );
}

/**
 * Offline-capable SyncVault client
 */
export class OfflineSyncVault {
  constructor(baseClient, options = {}) {
    this.client = baseClient;
    this.store = new OfflineStore(options.storage);
    this.retryInterval = options.retryInterval || 30000;
    this.maxRetries = options.maxRetries || 10;
    this.autoSync = options.autoSync !== false;
    
    this.onSyncSuccess = null;
    this.onSyncError = null;
    
    this._syncTimer = null;
    this._initialized = false;
  }
  
  async init() {
    if (this._initialized) return;
    await this.store.load();
    this._initialized = true;
    
    if (this.autoSync) {
      this.startAutoSync();
    }
  }
  
  /**
   * Proxy auth methods to base client
   */
  async auth(username, password) {
    await this.init();
    return this.client.auth(username, password);
  }
  
  async register(username, password) {
    await this.init();
    return this.client.register(username, password);
  }
  
  setAuth(token, password) {
    this.client.setAuth(token, password);
  }
  
  getAuthUrl(state) {
    return this.client.getAuthUrl(state);
  }
  
  async exchangeCode(code, password) {
    return this.client.exchangeCode(code, password);
  }
  
  isAuthenticated() {
    return this.client.isAuthenticated();
  }
  
  logout() {
    this.client.logout();
  }
  
  /**
   * Put with offline support
   */
  async put(path, data) {
    await this.init();
    
    const encrypted = await encrypt(data, this.client.password);
    
    try {
      const result = await this.client.put(path, data);
      await this.store.setCache(path, encrypted);
      return result;
    } catch (error) {
      if (isNetworkError(error)) {
        await this.store.setCache(path, encrypted);
        await this.store.queueOperation({
          type: 'put',
          path,
          data: encrypted
        });
        return { queued: true, path };
      }
      throw error;
    }
  }
  
  /**
   * Get with offline fallback
   */
  async get(path) {
    await this.init();
    
    try {
      const result = await this.client.get(path);
      // Update cache with fresh data
      const encrypted = await encrypt(result, this.client.password);
      await this.store.setCache(path, encrypted);
      return result;
    } catch (error) {
      if (isNetworkError(error)) {
        const cached = this.store.getCached(path);
        if (cached) {
          return decrypt(cached.data, this.client.password);
        }
        throw new Error('Offline and no cached data available');
      }
      throw error;
    }
  }
  
  /**
   * Delete with offline support
   */
  async delete(path) {
    await this.init();
    
    try {
      const result = await this.client.delete(path);
      await this.store.removeCache(path);
      return result;
    } catch (error) {
      if (isNetworkError(error)) {
        await this.store.removeCache(path);
        await this.store.queueOperation({
          type: 'delete',
          path
        });
        return { queued: true, path };
      }
      throw error;
    }
  }
  
  /**
   * List files (no offline caching for list)
   */
  async list() {
    return this.client.list();
  }
  
  /**
   * Proxy metadata/entitlements (no offline for these)
   */
  async getMetadata() {
    return this.client.getMetadata();
  }
  
  async setMetadata(metadata) {
    return this.client.setMetadata(metadata);
  }
  
  async updateMetadata(metadata) {
    return this.client.updateMetadata(metadata);
  }
  
  async getEntitlements() {
    return this.client.getEntitlements();
  }
  
  async getQuota() {
    return this.client.getQuota();
  }
  
  async getUser() {
    return this.client.getUser();
  }
  
  /**
   * Start automatic sync of pending operations
   */
  startAutoSync() {
    if (this._syncTimer) return;
    
    this._syncTimer = setInterval(() => {
      this.syncPending();
    }, this.retryInterval);
    
    // Also listen for online event in browser
    if (typeof window !== 'undefined') {
      window.addEventListener('online', () => this.syncPending());
    }
  }
  
  /**
   * Stop automatic sync
   */
  stopAutoSync() {
    if (this._syncTimer) {
      clearInterval(this._syncTimer);
      this._syncTimer = null;
    }
  }
  
  /**
   * Manually sync pending operations
   */
  async syncPending() {
    const ops = this.store.getPendingOperations();
    
    for (const op of ops) {
      if (op.retries >= this.maxRetries) {
        await this.store.removeOperation(op.id);
        if (this.onSyncError) {
          this.onSyncError(op, new Error('Max retries exceeded'));
        }
        continue;
      }
      
      try {
        if (op.type === 'put') {
          await this._syncPut(op);
        } else if (op.type === 'delete') {
          await this._syncDelete(op);
        }
        
        await this.store.removeOperation(op.id);
        if (this.onSyncSuccess) {
          this.onSyncSuccess(op);
        }
      } catch (error) {
        if (isNetworkError(error)) {
          await this.store.incrementRetry(op.id);
        } else {
          await this.store.removeOperation(op.id);
          if (this.onSyncError) {
            this.onSyncError(op, error);
          }
        }
      }
    }
  }
  
  async _syncPut(op) {
    await this.client._request('/api/sync/put', {
      method: 'POST',
      body: JSON.stringify({ path: op.path, data: op.data })
    });
  }
  
  async _syncDelete(op) {
    await this.client._request('/api/sync/delete', {
      method: 'POST',
      body: JSON.stringify({ path: op.path })
    });
  }
  
  /**
   * Check if there are pending changes
   */
  hasPendingChanges() {
    return this.store.hasPendingOperations();
  }
  
  /**
   * Get number of pending operations
   */
  pendingCount() {
    return this.store.getPendingOperations().length;
  }
  
  /**
   * Get the offline store for direct access
   */
  getStore() {
    return this.store;
  }
}

/**
 * Create an offline-capable client
 */
export function createOfflineClient(baseClient, options = {}) {
  return new OfflineSyncVault(baseClient, options);
}
