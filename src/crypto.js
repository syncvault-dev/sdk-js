/**
 * Cryptographic utilities for SyncVault SDK
 * Uses Web Crypto API (works in Node.js 18+ and browsers)
 */

const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const KEY_LENGTH = 256;
const ITERATIONS = 100000;

/**
 * Prepare password for authentication (hashing)
 * This ensures the server never sees the raw password used for encryption
 */
export async function prepareAuthPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Derive encryption key from password using PBKDF2
 */
export async function deriveKey(password, salt) {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: ITERATIONS,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: KEY_LENGTH },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Generate a random salt
 */
export function generateSalt() {
  return crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
}

/**
 * Encrypt data using AES-256-GCM
 * Returns: salt (16 bytes) + iv (12 bytes) + ciphertext
 */
export async function encrypt(data, password) {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(JSON.stringify(data));

  const salt = generateSalt();
  const key = await deriveKey(password, salt);
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    dataBuffer
  );

  // Combine salt + iv + ciphertext
  const combined = new Uint8Array(
    SALT_LENGTH + IV_LENGTH + ciphertext.byteLength
  );
  combined.set(salt, 0);
  combined.set(iv, SALT_LENGTH);
  combined.set(new Uint8Array(ciphertext), SALT_LENGTH + IV_LENGTH);

  return bufferToBase64(combined);
}

/**
 * Decrypt data using AES-256-GCM
 */
export async function decrypt(encryptedBase64, password) {
  const combined = base64ToBuffer(encryptedBase64);

  const salt = combined.slice(0, SALT_LENGTH);
  const iv = combined.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const ciphertext = combined.slice(SALT_LENGTH + IV_LENGTH);

  const key = await deriveKey(password, salt);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );

  const decoder = new TextDecoder();
  return JSON.parse(decoder.decode(decrypted));
}

/**
 * Convert Uint8Array to base64 string
 */
function bufferToBase64(buffer) {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(buffer).toString('base64');
  }
  // Browser fallback
  let binary = '';
  for (let i = 0; i < buffer.byteLength; i++) {
    binary += String.fromCharCode(buffer[i]);
  }
  return btoa(binary);
}

/**
 * Convert base64 string to Uint8Array
 */
function base64ToBuffer(base64) {
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(base64, 'base64'));
  }
  // Browser fallback
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Decrypt data that was encrypted by an app server using hybrid encryption.
 * The server encrypts an AES key with RSA-OAEP, then encrypts the data with AES-GCM.
 * 
 * Format: encryptedAESKey (256 bytes) + iv (12 bytes) + authTag (16 bytes) + ciphertext
 * 
 * @param {string} encryptedBase64 - Base64 encoded encrypted package
 * @param {string} privateKeyBase64 - User's RSA private key in base64 (PKCS8 format)
 */
export async function decryptFromServer(encryptedBase64, privateKeyBase64) {
  try {
    const combined = base64ToBuffer(encryptedBase64);
    
    const RSA_KEY_SIZE = 256;
    const AES_IV_LENGTH = 12;
    const AUTH_TAG_LENGTH = 16;
    
    const minLength = RSA_KEY_SIZE + AES_IV_LENGTH + AUTH_TAG_LENGTH;
    if (combined.length < minLength) {
      throw new Error(`Invalid encrypted data: too short (${combined.length} bytes, need ${minLength})`);
    }
    
    const encryptedAESKey = combined.slice(0, RSA_KEY_SIZE);
    const iv = combined.slice(RSA_KEY_SIZE, RSA_KEY_SIZE + AES_IV_LENGTH);
    const authTag = combined.slice(RSA_KEY_SIZE + AES_IV_LENGTH, RSA_KEY_SIZE + AES_IV_LENGTH + AUTH_TAG_LENGTH);
    const ciphertext = combined.slice(RSA_KEY_SIZE + AES_IV_LENGTH + AUTH_TAG_LENGTH);
    
    const privateKeyBuffer = base64ToBuffer(privateKeyBase64);
    
    const privateKey = await crypto.subtle.importKey(
      'pkcs8',
      privateKeyBuffer,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['decrypt']
    );
    
    const rawAESKey = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      privateKey,
      encryptedAESKey
    );
    
    const aesKey = await crypto.subtle.importKey(
      'raw',
      rawAESKey,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );
    
    const ciphertextWithTag = new Uint8Array(ciphertext.length + AUTH_TAG_LENGTH);
    ciphertextWithTag.set(ciphertext, 0);
    ciphertextWithTag.set(authTag, ciphertext.length);
    
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      ciphertextWithTag
    );
    
    const decoder = new TextDecoder();
    return JSON.parse(decoder.decode(decrypted));
  } catch (err) {
    console.error('[SDK decryptFromServer] Error:', err.message);
    throw err;
  }
}
