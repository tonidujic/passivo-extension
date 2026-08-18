import { arrayBufferToBase64 } from './encoding'

export async function deriveAuthAndEncryptionKeys(password, salt) {
  const enc = new TextEncoder()
  const passwordBytes = enc.encode(password)

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    passwordBytes,
    { name: 'PBKDF2' },
    false,
    ['deriveBits'],
  )

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    512,
  )

  const bytes = new Uint8Array(derivedBits)

  const authKeyBytes = bytes.slice(0, 32)

  const encryptionKeyBytes = bytes.slice(32, 64)

  const authKey = await crypto.subtle.importKey(
    'raw',
    authKeyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    true,
    ['sign'],
  )

  const encryptionKey = await crypto.subtle.importKey(
    'raw',
    encryptionKeyBytes,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt'],
  )

  return {
    authKey,
    encryptionKey,
  }
}

export async function generateUserKeyPair() {
  const { publicKey, privateKey } = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt'],
  )

  return { publicKey, privateKey }
}

export async function exportAuthKey(authKey) {
  const rawAuthKey = await crypto.subtle.exportKey('raw', authKey)

  return arrayBufferToBase64(rawAuthKey)
}

export async function generateKey() {
  const key = crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ])

  return key
}
