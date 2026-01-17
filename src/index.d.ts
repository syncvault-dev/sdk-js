export interface SyncVaultOptions {
  appToken: string;
  serverUrl?: string;
  redirectUri?: string;
}

export interface User {
  id: string;
  username: string;
  createdAt?: string;
}

export interface FileInfo {
  path: string;
  updatedAt: string;
}

export interface PutResponse {
  path: string;
  updatedAt: string;
}

export interface DeleteResponse {
  deleted: boolean;
  path: string;
}

export type Metadata = Record<string, unknown>;

export type Entitlements = Record<string, unknown>;

export interface QuotaInfo {
  quotaBytes: number | null;
  usedBytes: number;
  unlimited: boolean;
}

export interface SharedVault {
  id: string;
  name: string;
  ownerId: string;
  ownerUsername: string;
  memberCount: number;
  isOwner: boolean;
  createdAt: string;
}

export interface PutOptions {
  updatedAt?: number | Date;
}

export declare class SyncVault {
  constructor(options: SyncVaultOptions);
  
  // OAuth flow
  getAuthUrl(state?: string): string;
  exchangeCode(code: string, password: string): Promise<User>;
  setAuth(token: string, password: string): void;
  
  // Direct auth (requires valid app token)
  auth(username: string, password: string): Promise<User>;
  register(username: string, password: string): Promise<User>;
  
  // Data operations
  put<T = unknown>(path: string, data: T, options?: PutOptions): Promise<PutResponse>;
  get<T = unknown>(path: string): Promise<T>;
  list(): Promise<FileInfo[]>;
  delete(path: string): Promise<DeleteResponse>;
  
  // Metadata operations (unencrypted, for app preferences like theme, timezone)
  getMetadata<T extends Metadata = Metadata>(): Promise<T>;
  setMetadata<T extends Metadata = Metadata>(metadata: T): Promise<T>;
  updateMetadata<T extends Metadata = Metadata>(metadata: Partial<T>): Promise<T>;
  
  // Entitlements (read-only, set by developer's backend for subscriptions, feature flags)
  getEntitlements<T extends Entitlements = Entitlements>(): Promise<T>;
  
  // Quota info
  getQuota(): Promise<QuotaInfo>;
  
  // Shared vaults
  getSharedVaults(): Promise<SharedVault[]>;
  listShared(vaultId: string): Promise<FileInfo[]>;
  putShared<T = unknown>(vaultId: string, path: string, data: T, sharedPassword?: string): Promise<PutResponse>;
  getShared<T = unknown>(vaultId: string, path: string, sharedPassword?: string): Promise<T>;
  deleteShared(vaultId: string, path: string): Promise<DeleteResponse>;
  
  // State
  isAuthenticated(): boolean;
  logout(): void;
  getUser(): Promise<User>;
}

export declare function encrypt(data: unknown, password: string): Promise<string>;
export declare function decrypt<T = unknown>(encryptedBase64: string, password: string): Promise<T>;

// Offline sync types
export interface PendingOperation {
  id: string;
  type: 'put' | 'delete';
  path: string;
  data?: string;
  updatedAt?: number;
  createdAt: number;
  retries: number;
}

export interface CacheEntry {
  path: string;
  data: string;
  updatedAt: number;
}

export interface OfflineStorage {
  get(key: string): Promise<unknown | null>;
  set(key: string, value: unknown): Promise<void>;
  remove(key: string): Promise<void>;
}

export interface OfflineOptions {
  storage?: OfflineStorage;
  retryInterval?: number;
  maxRetries?: number;
  autoSync?: boolean;
}

export declare class OfflineStore {
  constructor(storage?: OfflineStorage | null);
  load(): Promise<void>;
  persist(): Promise<void>;
  getCached(path: string): CacheEntry | null;
  setCache(path: string, data: string): Promise<void>;
  removeCache(path: string): Promise<void>;
  queueOperation(op: Partial<PendingOperation>): Promise<void>;
  getPendingOperations(): PendingOperation[];
  removeOperation(id: string): Promise<void>;
  incrementRetry(id: string): Promise<void>;
  hasPendingOperations(): boolean;
  clearQueue(): Promise<void>;
  clearCache(): Promise<void>;
}

export declare class OfflineSyncVault {
  constructor(baseClient: SyncVault, options?: OfflineOptions);
  
  onSyncSuccess: ((op: PendingOperation) => void) | null;
  onSyncError: ((op: PendingOperation, error: Error) => void) | null;
  
  init(): Promise<void>;
  
  // Auth (proxied to base client)
  auth(username: string, password: string): Promise<User>;
  register(username: string, password: string): Promise<User>;
  setAuth(token: string, password: string): void;
  getAuthUrl(state?: string): string;
  exchangeCode(code: string, password: string): Promise<User>;
  isAuthenticated(): boolean;
  logout(): void;
  
  // Data operations with offline support
  put<T = unknown>(path: string, data: T): Promise<PutResponse | { queued: boolean; path: string }>;
  get<T = unknown>(path: string): Promise<T>;
  delete(path: string): Promise<DeleteResponse | { queued: boolean; path: string }>;
  list(): Promise<FileInfo[]>;
  
  // Metadata/entitlements (no offline caching)
  getMetadata<T extends Metadata = Metadata>(): Promise<T>;
  setMetadata<T extends Metadata = Metadata>(metadata: T): Promise<T>;
  updateMetadata<T extends Metadata = Metadata>(metadata: Partial<T>): Promise<T>;
  getEntitlements<T extends Entitlements = Entitlements>(): Promise<T>;
  getQuota(): Promise<QuotaInfo>;
  getUser(): Promise<User>;
  
  // Sync control
  startAutoSync(): void;
  stopAutoSync(): void;
  syncPending(): Promise<void>;
  hasPendingChanges(): boolean;
  pendingCount(): number;
  getStore(): OfflineStore;
}

export declare function createOfflineClient(baseClient: SyncVault, options?: OfflineOptions): OfflineSyncVault;
