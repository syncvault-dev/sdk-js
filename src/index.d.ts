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
  put<T = unknown>(path: string, data: T): Promise<PutResponse>;
  get<T = unknown>(path: string): Promise<T>;
  list(): Promise<FileInfo[]>;
  delete(path: string): Promise<DeleteResponse>;
  
  // Metadata operations (unencrypted server-side data)
  getMetadata<T extends Metadata = Metadata>(): Promise<T>;
  setMetadata<T extends Metadata = Metadata>(metadata: T): Promise<T>;
  updateMetadata<T extends Metadata = Metadata>(metadata: Partial<T>): Promise<T>;
  
  // State
  isAuthenticated(): boolean;
  logout(): void;
  getUser(): Promise<User>;
}

export declare function encrypt(data: unknown, password: string): Promise<string>;
export declare function decrypt<T = unknown>(encryptedBase64: string, password: string): Promise<T>;
