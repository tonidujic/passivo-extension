import { base64ToArrayBuffer, arrayBufferToBase64, uint8ArrayToBase64 } from './encoding'
export async function encryptPrivateKey(privKey, encryptionKey) {
  const exportedPrivateKey = await crypto.subtle.exportKey('pkcs8', privKey)

  const iv = crypto.getRandomValues(new Uint8Array(12))

  const privateKey = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    encryptionKey,
    exportedPrivateKey,
  )

  return { privateKey, iv }
}

export async function encryptCredential(cred, publicKey) {
  const encodedCredential = new TextEncoder().encode(cred)
  const credential = await crypto.subtle.encrypt(
    {
      name: 'RSA-OAEP',
    },
    publicKey,
    encodedCredential,
  )

  return credential
}

export async function decryptCredential(encryptedCredential, privateKey) {
  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'RSA-OAEP',
    },

    privateKey,

    base64ToArrayBuffer(encryptedCredential),
  )

  return new TextDecoder().decode(decrypted)
}

export async function generateDeviceKey() {
  return await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },

    true,

    ['encrypt', 'decrypt'],
  )
}

export async function exportDeviceKey(deviceKey) {
  const raw = await crypto.subtle.exportKey('raw', deviceKey)

  return arrayBufferToBase64(raw)
}

export async function encryptPrivateKeyForDevice(privateKey, deviceKey) {
  const exportedPrivateKey = await crypto.subtle.exportKey('pkcs8', privateKey)

  const iv = crypto.getRandomValues(new Uint8Array(12))

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },

    deviceKey,

    exportedPrivateKey,
  )

  return {
    privateKeyForDevice: arrayBufferToBase64(encrypted),

    devicePrivateKeyIv: uint8ArrayToBase64(iv),
  }
}
export async function importDeviceKey(deviceKeyBase64) {
  return await crypto.subtle.importKey(
    'raw',

    base64ToArrayBuffer(deviceKeyBase64),

    { name: 'AES-GCM' },

    true,

    ['encrypt', 'decrypt'],
  )
}

export async function decryptPrivateKeyForDevice(encryptedPrivateKeyForDevice, iv, deviceKey) {
  return await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',

      iv: base64ToArrayBuffer(iv),
    },

    deviceKey,

    base64ToArrayBuffer(encryptedPrivateKeyForDevice),
  )
}

export async function encryptData(value, publicKey) {
  const encodedValue = new TextEncoder().encode(value)
  return await crypto.subtle.encrypt(
    {
      name: 'RSA-OAEP',
    },
    publicKey,
    encodedValue,
  )
}

export async function decryptData(value, privateKey) {
  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'RSA-OAEP',
    },
    privateKey,
    base64ToArrayBuffer(value),
  )
  return new TextDecoder().decode(decrypted)
}

export async function encryptAESKey(value, publicKey) {
  const key = await crypto.subtle.exportKey('raw', value)

  return await crypto.subtle.encrypt(
    {
      name: 'RSA-OAEP',
    },
    publicKey,
    key,
  )
}

export async function encryptFile(value, key) {
  const fileBuffer = await value.arrayBuffer()
  const iv = crypto.getRandomValues(new Uint8Array(12))

  const file = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    key,
    fileBuffer,
  )
  return { file, iv }
}
