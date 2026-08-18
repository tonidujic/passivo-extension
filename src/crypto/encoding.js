export function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer)
  let binary = ''

  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }

  return btoa(binary)
}

export function base64ToArrayBuffer(base64) {
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }

  return bytes.buffer
}

export function uint8ArrayToBase64(uint8Array) {
  return arrayBufferToBase64(uint8Array.buffer)
}

export function base64ToUint8Array(base64) {
  return new Uint8Array(base64ToArrayBuffer(base64))
}

export async function exportPublicKeyToBase64(publicKey) {
  const exported = await crypto.subtle.exportKey('spki', publicKey)

  return arrayBufferToBase64(exported)
}

export async function exportPrivateKeyToBase64(privateKey) {
  const exported = await crypto.subtle.exportKey('pkcs8', privateKey)

  return arrayBufferToBase64(exported)
}
