import '#q-app/bex/content'
import { base64ToArrayBuffer, arrayBufferToBase64 } from './crypto/encoding.js'
import {
  decryptCredential,
  decryptData,
  encryptCredential,
  encryptData,
} from './crypto/encryption.js'

let passivoButton = null
let generateButton = null
let isSavingSignupPassword = false
let signupCheckInterval = null
let currentInput = null

const PENDING_SIGNUP_KEY = 'passivoPendingSignup'

function hasExtensionContext() {
  return Boolean(typeof chrome !== 'undefined' && chrome?.runtime?.id && chrome?.storage?.local)
}

function isExtensionContextError(err) {
  const message = String(err?.message || '').toLowerCase()

  return (
    message.includes('extension context invalidated') ||
    message.includes('context invalidated') ||
    message.includes('receiving end does not exist')
  )
}

async function storageGet(keys) {
  if (!hasExtensionContext()) return null

  try {
    return await chrome.storage.local.get(keys)
  } catch (err) {
    if (isExtensionContextError(err)) return null
    throw err
  }
}

async function storageSet(values) {
  if (!hasExtensionContext()) return false

  try {
    await chrome.storage.local.set(values)
    return true
  } catch (err) {
    if (isExtensionContextError(err)) return false
    throw err
  }
}

async function storageRemove(keys) {
  if (!hasExtensionContext()) return false

  try {
    await chrome.storage.local.remove(keys)
    return true
  } catch (err) {
    if (isExtensionContextError(err)) return false
    throw err
  }
}

async function storageClear() {
  if (!hasExtensionContext()) return

  try {
    await chrome.storage.local.clear()
  } catch (err) {
    if (!isExtensionContextError(err)) throw err
  }
}

function sendExtensionMessage(message) {
  if (!hasExtensionContext() || !chrome?.runtime?.sendMessage) return false

  try {
    chrome.runtime.sendMessage(message)
    return true
  } catch (err) {
    if (!isExtensionContextError(err)) {
      console.error('Passivo message error:', err)
    }

    return false
  }
}

async function sendBackgroundRequest(message) {
  if (!hasExtensionContext() || !chrome?.runtime?.sendMessage) {
    throw new Error('Passivo extension is not available. Refresh the page.')
  }

  try {
    const response = await chrome.runtime.sendMessage(message)

    if (!response) {
      throw new Error('Passivo background service did not respond.')
    }

    return response
  } catch (err) {
    if (isExtensionContextError(err)) {
      throw new Error('Passivo extension was reloaded. Refresh this page and try again.')
    }

    throw err
  }
}

function isPassivoOwnPage() {
  const hostname = window.location.hostname
  const port = window.location.port

  return (
    hostname === 'passivo.site' ||
    hostname === 'www.passivo.site' ||
    (hostname === 'localhost' && (port === '9000' || port === '9001')) ||
    (hostname === '127.0.0.1' && (port === '9000' || port === '9001'))
  )
}

function normalizeWebsite(value) {
  return String(value || '')
    .replace(/^https?:\/\//i, '')
    .replace(/^www\./i, '')
    .split('/')[0]
    .split('?')[0]
    .split('#')[0]
    .trim()
    .toLowerCase()
}

function websitesMatch(a, b) {
  const siteA = normalizeWebsite(a)
  const siteB = normalizeWebsite(b)

  if (!siteA || !siteB) return false

  return siteA === siteB || siteA.endsWith(`.${siteB}`) || siteB.endsWith(`.${siteA}`)
}

function isSignupPage(input = null) {
  const url = window.location.href.toLowerCase()

  const container = input?.closest?.('form') || input?.closest?.('[role="main"]') || document.body

  const text = String(container?.innerText || '').toLowerCase()

  const isLoginUrl =
    url.includes('/login') ||
    url.includes('login.php') ||
    url.includes('/signin') ||
    url.includes('/sign-in')

  const isSignupUrl =
    url.includes('/signup') ||
    url.includes('/sign-up') ||
    url.includes('/register') ||
    url.includes('/registration') ||
    url.includes('/create-account')

  const hasSignupFields =
    text.includes('create your account') ||
    text.includes('confirm password') ||
    text.includes('repeat password') ||
    text.includes('first name') ||
    text.includes('last name') ||
    text.includes('terms of service')

  const hasSignupButton =
    text.includes('sign up') ||
    text.includes('signup') ||
    text.includes('register') ||
    text.includes('create account')

  const hasLoginText =
    text.includes('log in') || text.includes('login') || text.includes('forgot password')

  if (isLoginUrl && !isSignupUrl) return false

  if (hasLoginText && !hasSignupFields && !isSignupUrl) return false

  return isSignupUrl || hasSignupFields || hasSignupButton
}

async function getPrivateKey(savedPrivateKey) {
  if (!savedPrivateKey) {
    throw new Error('Passivo private key is missing.')
  }

  const privateKeyBuffer = base64ToArrayBuffer(savedPrivateKey)

  return await crypto.subtle.importKey(
    'pkcs8',
    privateKeyBuffer,
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256',
    },
    false,
    ['decrypt'],
  )
}

async function getPublicKey(savedPublicKey) {
  if (!savedPublicKey) {
    throw new Error('Passivo public key is missing.')
  }

  const publicKeyBuffer = base64ToArrayBuffer(savedPublicKey)

  return await crypto.subtle.importKey(
    'spki',
    publicKeyBuffer,
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256',
    },
    false,
    ['encrypt'],
  )
}

async function createPendingSignupCredential(username, password) {
  const savedInfo = await storageGet(['publicKey'])

  if (!savedInfo?.publicKey) {
    return false
  }

  const publicKey = await getPublicKey(savedInfo.publicKey)

  const currentWebsite = normalizeWebsite(window.location.hostname)
  const websiteName = currentWebsite.split('.')[0]

  const title = `Lozinka za ${websiteName}`

  const encryptedCredential = await encryptCredential(password, publicKey)
  const encryptedWebsite = await encryptData(currentWebsite, publicKey)
  const encryptedUsername = await encryptData(username || '', publicKey)
  const encryptedTitle = await encryptData(title, publicKey)

  return await storageSet({
    [PENDING_SIGNUP_KEY]: {
      title: arrayBufferToBase64(encryptedTitle),
      website: arrayBufferToBase64(encryptedWebsite),
      username: arrayBufferToBase64(encryptedUsername),
      credential: arrayBufferToBase64(encryptedCredential),
      favorite: false,
      hostname: currentWebsite,
      urlBeforeSignup: window.location.href,
      ownerPublicKey: savedInfo.publicKey,
      createdAt: Date.now(),
    },
  })
}

async function getPendingSignupCredential() {
  const result = await storageGet(PENDING_SIGNUP_KEY)

  return result?.[PENDING_SIGNUP_KEY] || null
}

async function removePendingSignupCredential() {
  await storageRemove(PENDING_SIGNUP_KEY)
}

async function savePendingSignupCredential(pending) {
  const savedInfo = await storageGet(['token', 'publicKey'])

  if (!savedInfo?.token || !savedInfo?.publicKey) {
    return 'not-logged-in'
  }

  if (pending.ownerPublicKey && pending.ownerPublicKey !== savedInfo.publicKey) {
    await removePendingSignupCredential()

    return 'account-mismatch'
  }

  const response = await sendBackgroundRequest({
    type: 'SAVE_PASSIVO_PASSWORD',
    token: savedInfo.token,
    payload: {
      title: pending.title,
      website: pending.website,
      username: pending.username,
      credential: pending.credential,
      favorite: false,
    },
  })

  if (!response.ok) {
    if (response.status === 401) {
      return 'not-logged-in'
    }

    throw new Error(response.error || 'Passivo could not save this password.')
  }

  return 'saved'
}

function injectPassivoUiStyles() {
  if (document.getElementById('passivo-ui-styles')) {
    return
  }

  const style = document.createElement('style')

  style.id = 'passivo-ui-styles'

  style.textContent = `
    .passivo-modal-overlay {
      position: fixed !important;
      inset: 0 !important;
      z-index: 2147483647 !important;
      pointer-events: none !important;

      font-family:
        Inter,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif !important;
    }

    .passivo-modal {
      position: absolute !important;

      top: 20px !important;
      right: 20px !important;

      width: 320px !important;

      box-sizing: border-box !important;

      padding: 18px !important;

      pointer-events: auto !important;

      background: rgba(255, 255, 255, 0.98) !important;

      border: 1px solid rgba(15, 23, 42, 0.10) !important;

      border-radius: 16px !important;

      box-shadow:
        0 18px 45px rgba(15, 23, 42, 0.13),
        0 2px 8px rgba(15, 23, 42, 0.05) !important;

      backdrop-filter: blur(14px) !important;

      -webkit-backdrop-filter: blur(14px) !important;

      animation: passivoPanelIn 0.2s ease !important;
    }

    .passivo-brand {
      margin: 0 0 14px !important;

      color: #111827 !important;

      font-size: 22px !important;

      line-height: 1 !important;

      font-weight: 800 !important;

      letter-spacing: -0.65px !important;
    }

    .passivo-title {
      margin: 0 !important;

      color: #111827 !important;

      font-size: 16px !important;

      line-height: 1.3 !important;

      font-weight: 750 !important;

      letter-spacing: -0.2px !important;
    }

    .passivo-description {
      margin: 5px 0 0 !important;

      color: #64748b !important;

      font-size: 12px !important;

      line-height: 1.5 !important;

      font-weight: 400 !important;
    }

    .passivo-site {
      margin: 12px 0 0 !important;

      padding: 9px 10px !important;

      overflow: hidden !important;

      background: #f8fafc !important;

      border: 1px solid #eef1f4 !important;

      border-radius: 9px !important;

      color: #475569 !important;

      font-size: 11px !important;

      line-height: 1.25 !important;

      font-weight: 600 !important;

      white-space: nowrap !important;

      text-overflow: ellipsis !important;
    }

    .passivo-actions {
      display: flex !important;

      justify-content: flex-end !important;

      gap: 8px !important;

      margin: 14px 0 0 !important;
    }

    .passivo-btn {
      height: 35px !important;

      min-height: 35px !important;

      box-sizing: border-box !important;

      padding: 0 13px !important;

      border-radius: 9px !important;

      font-family:
        Inter,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif !important;

      font-size: 11.5px !important;

      line-height: 1 !important;

      font-weight: 700 !important;

      cursor: pointer !important;

      transition:
        background 0.15s ease,
        border-color 0.15s ease,
        transform 0.15s ease,
        box-shadow 0.15s ease !important;
    }

    .passivo-btn:hover {
      transform: translateY(-1px) !important;
    }

    .passivo-cancel {
      background: #ffffff !important;

      color: #64748b !important;

      border: 1px solid #e2e8f0 !important;

      box-shadow: none !important;
    }

    .passivo-cancel:hover {
      background: #f8fafc !important;

      color: #334155 !important;
    }

    .passivo-save {
      background: #eaf7ef !important;

      color: #187844 !important;

      border: 1px solid #cde9d7 !important;

      box-shadow: none !important;
    }

    .passivo-save:hover {
      background: #def2e5 !important;

      color: #116a39 !important;

      border-color: #bce0c8 !important;

      box-shadow: 0 4px 10px rgba(22, 163, 74, 0.08) !important;
    }

    .passivo-toast {
      position: fixed !important;

      top: 20px !important;
      right: 20px !important;

      z-index: 2147483647 !important;

      width: 292px !important;

      box-sizing: border-box !important;

      padding: 12px 13px !important;

      display: flex !important;

      align-items: center !important;

      gap: 10px !important;

      background: rgba(255, 255, 255, 0.98) !important;

      border: 1px solid rgba(15, 23, 42, 0.10) !important;

      border-radius: 13px !important;

      box-shadow:
        0 14px 35px rgba(15, 23, 42, 0.12),
        0 2px 7px rgba(15, 23, 42, 0.04) !important;

      color: #111827 !important;

      font-family:
        Inter,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif !important;

      backdrop-filter: blur(14px) !important;

      -webkit-backdrop-filter: blur(14px) !important;

      animation: passivoPanelIn 0.2s ease !important;
    }

    .passivo-toast-brand {
      flex: 0 0 auto !important;

      color: #111827 !important;

      font-size: 13px !important;

      font-weight: 800 !important;

      padding-right: 10px !important;

      border-right: 1px solid #e5e7eb !important;
    }

    .passivo-toast-text {
      flex: 1 !important;

      min-width: 0 !important;
    }

    .passivo-toast-title {
      margin: 0 0 1px !important;

      color: #111827 !important;

      font-size: 11.5px !important;

      line-height: 1.3 !important;

      font-weight: 750 !important;
    }

    .passivo-toast-message {
      margin: 0 !important;

      color: #64748b !important;

      font-size: 9.8px !important;

      line-height: 1.4 !important;

      font-weight: 400 !important;
    }

    .passivo-toast-status {
      width: 20px !important;

      height: 20px !important;

      display: flex !important;

      align-items: center !important;

      justify-content: center !important;

      flex: 0 0 20px !important;

      border-radius: 999px !important;

      background: #eaf7ef !important;

      border: 1px solid #cde9d7 !important;

      color: #187844 !important;

      font-size: 10px !important;

      line-height: 1 !important;

      font-weight: 800 !important;
    }

    .passivo-toast-warning .passivo-toast-status {
      background: #fff7e6 !important;

      border-color: #f6d596 !important;

      color: #b66a00 !important;
    }

    .passivo-toast-error .passivo-toast-status {
      background: #fef2f2 !important;

      border-color: #fecaca !important;

      color: #dc2626 !important;
    }

    .passivo-toast-out {
      animation: passivoPanelOut 0.18s ease forwards !important;
    }

    @keyframes passivoPanelIn {
      from {
        opacity: 0;

        transform: translateY(-7px) scale(0.985);
      }

      to {
        opacity: 1;

        transform: translateY(0) scale(1);
      }
    }

    @keyframes passivoPanelOut {
      from {
        opacity: 1;

        transform: translateY(0) scale(1);
      }

      to {
        opacity: 0;

        transform: translateY(-5px) scale(0.99);
      }
    }

    @media (max-width: 500px) {
      .passivo-modal,
      .passivo-toast {
        top: 12px !important;

        right: 12px !important;

        left: 12px !important;

        width: auto !important;
      }
    }
  `

  document.head.appendChild(style)
}

function showPassivoConfirm({
  title = 'Save password to Passivo?',
  description = 'Securely store this login in your vault.',
  website = window.location.hostname,
} = {}) {
  injectPassivoUiStyles()

  return new Promise((resolve) => {
    document.querySelector('.passivo-modal-overlay')?.remove()

    const overlay = document.createElement('div')

    overlay.className = 'passivo-modal-overlay'

    const modal = document.createElement('div')

    modal.className = 'passivo-modal'

    const brand = document.createElement('div')

    brand.className = 'passivo-brand'

    brand.textContent = 'Passivo'

    const titleElement = document.createElement('div')

    titleElement.className = 'passivo-title'

    titleElement.textContent = title

    const descriptionElement = document.createElement('div')

    descriptionElement.className = 'passivo-description'

    descriptionElement.textContent = description

    const site = document.createElement('div')

    site.className = 'passivo-site'

    site.textContent = normalizeWebsite(website)

    const actions = document.createElement('div')

    actions.className = 'passivo-actions'

    const cancelButton = document.createElement('button')

    cancelButton.type = 'button'

    cancelButton.className = 'passivo-btn passivo-cancel'

    cancelButton.textContent = 'Not now'

    const saveButton = document.createElement('button')

    saveButton.type = 'button'

    saveButton.className = 'passivo-btn passivo-save'

    saveButton.textContent = 'Save password'

    actions.appendChild(cancelButton)

    actions.appendChild(saveButton)

    modal.appendChild(brand)

    modal.appendChild(titleElement)

    modal.appendChild(descriptionElement)

    modal.appendChild(site)

    modal.appendChild(actions)

    overlay.appendChild(modal)

    let closed = false

    const close = (result) => {
      if (closed) {
        return
      }

      closed = true

      document.removeEventListener('keydown', handleEscape)

      document.removeEventListener('mousedown', handleOutsideClick, true)

      overlay.remove()

      resolve(result)
    }

    const handleEscape = (event) => {
      if (event.key === 'Escape') {
        close(false)
      }
    }

    const handleOutsideClick = (event) => {
      if (!modal.contains(event.target)) {
        close(false)
      }
    }

    cancelButton.addEventListener('click', () => {
      close(false)
    })

    saveButton.addEventListener('click', () => {
      close(true)
    })

    document.addEventListener('keydown', handleEscape)

    setTimeout(() => {
      document.addEventListener('mousedown', handleOutsideClick, true)
    }, 0)

    document.body.appendChild(overlay)

    saveButton.focus()
  })
}

function showPassivoToast(message, type = 'success') {
  injectPassivoUiStyles()

  document.querySelector('.passivo-toast')?.remove()

  const toast = document.createElement('div')

  toast.className = `passivo-toast passivo-toast-${type}`

  const brand = document.createElement('div')

  brand.className = 'passivo-toast-brand'

  brand.textContent = 'Passivo'

  const text = document.createElement('div')

  text.className = 'passivo-toast-text'

  const toastTitle = document.createElement('div')

  toastTitle.className = 'passivo-toast-title'

  if (type === 'success') {
    toastTitle.textContent = 'Password saved'
  } else if (type === 'warning') {
    toastTitle.textContent = 'Passivo'
  } else {
    toastTitle.textContent = 'Something went wrong'
  }

  const toastMessage = document.createElement('div')

  toastMessage.className = 'passivo-toast-message'

  toastMessage.textContent = message

  const status = document.createElement('div')

  status.className = 'passivo-toast-status'

  status.textContent = type === 'success' ? '✓' : type === 'warning' ? '!' : '×'

  text.appendChild(toastTitle)

  text.appendChild(toastMessage)

  toast.appendChild(brand)

  toast.appendChild(text)

  toast.appendChild(status)

  document.body.appendChild(toast)

  setTimeout(() => {
    toast.classList.add('passivo-toast-out')

    setTimeout(() => {
      toast.remove()
    }, 180)
  }, 2600)
}

async function offerPendingPasswordSave() {
  if (isSavingSignupPassword) {
    return
  }

  const pending = await getPendingSignupCredential()

  if (!pending) {
    return
  }

  const age = Date.now() - Number(pending.createdAt || 0)

  if (!pending.createdAt || age > 5 * 60 * 1000) {
    await removePendingSignupCredential()

    return
  }

  const currentHostname = normalizeWebsite(window.location.hostname)

  if (!websitesMatch(currentHostname, pending.hostname)) {
    return
  }

  const shouldSave = await showPassivoConfirm({
    title: 'Save password to Passivo?',
    description: 'Securely store this login in your vault.',
    website: pending.hostname,
  })

  if (!shouldSave) {
    await removePendingSignupCredential()

    return
  }

  isSavingSignupPassword = true

  try {
    const saveResult = await savePendingSignupCredential(pending)

    if (saveResult === 'saved') {
      await removePendingSignupCredential()

      showPassivoToast('Securely stored in your vault.', 'success')

      return
    }

    if (saveResult === 'account-mismatch') {
      showPassivoToast('This password belongs to another Passivo account.', 'error')

      return
    }

    showPassivoToast('Log in to Passivo to save this password.', 'warning')

    sendExtensionMessage({
      type: 'OPEN_PASSIVO_LOGIN',
    })
  } catch (err) {
    if (isExtensionContextError(err)) {
      return
    }

    console.error('Passivo pending signup save error:', err)

    showPassivoToast(err?.message || 'Passivo could not save this password.', 'error')
  } finally {
    isSavingSignupPassword = false
  }
}

function generateStrongPassword(length = 18) {
  const chars =
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789!@#$%^&*()_+-=[]{};:,.<>?'

  let password = ''

  for (let i = 0; i < length; i++) {
    password += chars[Math.floor(Math.random() * chars.length)]
  }

  return password
}

function isPasswordInput(el) {
  return Boolean(el && el.tagName === 'INPUT' && (el.type || '').toLowerCase() === 'password')
}

function isLoginInput(el) {
  if (!el || el.tagName !== 'INPUT') {
    return false
  }

  const type = el.type?.toLowerCase() || ''
  const name = el.name?.toLowerCase() || ''
  const id = el.id?.toLowerCase() || ''
  const placeholder = el.placeholder?.toLowerCase() || ''
  const autocomplete = el.autocomplete?.toLowerCase() || ''

  if (type === 'password' || type === 'email') {
    return true
  }

  if (type === 'text' || type === 'tel') {
    return (
      name.includes('email') ||
      name.includes('user') ||
      name.includes('login') ||
      name.includes('phone') ||
      id.includes('email') ||
      id.includes('user') ||
      id.includes('login') ||
      id.includes('phone') ||
      placeholder.includes('email') ||
      placeholder.includes('mobile') ||
      placeholder.includes('phone') ||
      placeholder.includes('username') ||
      autocomplete.includes('username') ||
      autocomplete.includes('email')
    )
  }

  return false
}

function removeButton({ passivo = true, generate = true } = {}) {
  if (passivo && passivoButton) {
    passivoButton.remove()

    passivoButton = null
  }

  if (generate && generateButton) {
    generateButton.remove()

    generateButton = null
  }
}

function createButton(input, buttonContent, type = 'passivo') {
  currentInput = input

  const rect = input.getBoundingClientRect()

  const button = document.createElement('button')

  button.type = 'button'

  button.innerText = buttonContent

  button.style.position = 'fixed'

  button.style.top = `${rect.bottom + 6}px`

  button.style.left = `${rect.left}px`

  button.style.zIndex = '2147483647'

  button.style.padding = '8px 14px'

  button.style.background = '#ffffff'

  button.style.color = '#1f9d4a'

  button.style.border = '1px solid rgba(31, 157, 74, 0.45)'

  button.style.borderRadius = '12px'

  button.style.fontSize = '13px'

  button.style.fontWeight = '700'

  button.style.cursor = 'pointer'

  button.style.transition = 'all 0.15s ease'

  button.style.boxShadow = '0 4px 10px rgba(31, 157, 74, 0.16)'

  if (type === 'generate') {
    generateButton = button
  } else {
    passivoButton = button
  }

  return button
}

function setInputValue(input, value) {
  if (!input) {
    return
  }

  const nativeSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set

  if (nativeSetter) {
    nativeSetter.call(input, value)
  } else {
    input.value = value
  }

  try {
    input.dispatchEvent(
      new InputEvent('input', {
        bubbles: true,
        inputType: 'insertText',
        data: value,
      }),
    )
  } catch {
    input.dispatchEvent(
      new Event('input', {
        bubbles: true,
      }),
    )
  }

  input.dispatchEvent(
    new Event('change', {
      bubbles: true,
    }),
  )
}

function findUsernameInput() {
  const selectors = [
    'input[type="email"]',
    'input[autocomplete="username"]',
    'input[autocomplete="email"]',
    'input[name*="email" i]',
    'input[name*="user" i]',
    'input[name*="login" i]',
    'input[name*="phone" i]',
    'input[id*="email" i]',
    'input[id*="user" i]',
    'input[id*="login" i]',
    'input[id*="phone" i]',
    'input[type="tel"]',
  ]

  for (const selector of selectors) {
    const input = document.querySelector(selector)

    if (input) {
      return input
    }
  }

  return null
}

async function decryptWebsiteCompat(encryptedWebsite, privateKey) {
  if (!encryptedWebsite) {
    return null
  }

  try {
    return await decryptData(encryptedWebsite, privateKey)
  } catch {
    try {
      return await decryptCredential(encryptedWebsite, privateKey)
    } catch {
      console.warn('Passivo: one saved website could not be decrypted.')

      return null
    }
  }
}

function extractPasswordItems(payload) {
  const possibleResult =
    payload?.data?.result?.result ??
    payload?.data?.result ??
    payload?.result?.result ??
    payload?.result ??
    payload?.data ??
    payload ??
    []

  if (Array.isArray(possibleResult)) {
    return possibleResult
  }

  return []
}

async function findCredentialForCurrentWebsite(privateKey, token) {
  const currentWebsite = normalizeWebsite(window.location.hostname)

  const response = await sendBackgroundRequest({
    type: 'GET_PASSIVO_PASSWORDS',
    token,
  })

  if (!response.ok) {
    if (response.status === 401) {
      await storageRemove(['token', 'privateKey', 'publicKey'])

      sendExtensionMessage({
        type: 'OPEN_PASSIVO_LOGIN',
      })
    }

    throw new Error(
      response.error || `Could not load passwords${response.status ? ` (${response.status})` : ''}`,
    )
  }

  const items = extractPasswordItems(response.data)

  for (const item of items) {
    const rawWebsite = await decryptWebsiteCompat(item.website, privateKey)

    if (!rawWebsite) {
      continue
    }

    const decryptedWebsite = normalizeWebsite(rawWebsite)

    if (websitesMatch(decryptedWebsite, currentWebsite)) {
      return item
    }
  }

  return null
}

async function fillCredentials() {
  const savedInfo = await storageGet(['token', 'privateKey'])

  if (!savedInfo) {
    return
  }

  if (!savedInfo.token || !savedInfo.privateKey) {
    sendExtensionMessage({
      type: 'OPEN_PASSIVO_LOGIN',
    })

    return
  }

  if (!currentInput || !document.contains(currentInput)) {
    return
  }

  let privateKey

  try {
    privateKey = await getPrivateKey(savedInfo.privateKey)
  } catch (err) {
    console.error('Passivo private key import failed:', err)

    showPassivoToast('Log in to Passivo again to restore your encryption key.', 'error')

    return
  }

  let matchedItem

  try {
    matchedItem = await findCredentialForCurrentWebsite(privateKey, savedInfo.token)
  } catch (err) {
    console.error('Passivo password fetch failed:', err)

    showPassivoToast(err?.message || 'Passivo could not load saved passwords.', 'error')

    return
  }

  if (!matchedItem) {
    showPassivoToast('No saved Passivo credential was found for this website.', 'warning')

    return
  }

  let username
  let password

  try {
    username = await decryptData(matchedItem.username, privateKey)

    password = await decryptCredential(matchedItem.credential, privateKey)
  } catch (err) {
    console.error('Passivo credential decrypt failed:', err)

    showPassivoToast('Passivo found this credential but could not decrypt it.', 'error')

    return
  }

  const passwordInput = document.querySelector('input[type="password"]')

  const usernameInput = findUsernameInput()

  if (currentInput.type === 'password') {
    setInputValue(currentInput, password)

    if (usernameInput && usernameInput !== currentInput) {
      setInputValue(usernameInput, username)
    }
  } else {
    setInputValue(currentInput, username)

    if (passwordInput) {
      setInputValue(passwordInput, password)
    }
  }

  removeButton({
    passivo: true,
    generate: false,
  })
}

async function fillGeneratedPassword() {
  const generatedPassword = generateStrongPassword()

  const passwordInputs = document.querySelectorAll('input[type="password"]')

  passwordInputs.forEach((input) => {
    setInputValue(input, generatedPassword)
  })

  if (isSignupPage(currentInput)) {
    try {
      const username = findUsernameInput()?.value?.trim() || ''

      const staged = await createPendingSignupCredential(username, generatedPassword)

      if (!staged) {
        sendExtensionMessage({
          type: 'OPEN_PASSIVO_LOGIN',
        })
      }
    } catch (err) {
      if (!isExtensionContextError(err)) {
        console.error('Passivo could not stage generated password:', err)
      }
    }
  }

  removeButton({
    passivo: true,
    generate: true,
  })
}

function showPassivoButton(input) {
  removeButton({
    passivo: true,
    generate: false,
  })

  const button = createButton(input, 'Use Passivo', 'passivo')

  button.addEventListener('mousedown', async (event) => {
    event.preventDefault()

    event.stopPropagation()

    try {
      await fillCredentials()
    } catch (err) {
      if (isExtensionContextError(err)) {
        return
      }

      console.error('Passivo autofill error:', err)

      showPassivoToast(err?.message || 'Passivo autofill failed.', 'error')
    }
  })

  document.body.appendChild(button)
}

function showGenerateButton(input) {
  removeButton({
    passivo: true,
    generate: true,
  })

  const button = createButton(input, 'Passivo strong password', 'generate')

  button.addEventListener('mousedown', async (event) => {
    event.preventDefault()

    event.stopPropagation()

    try {
      await fillGeneratedPassword()
    } catch (err) {
      console.error('Passivo password generator error:', err)

      showPassivoToast(err?.message || 'Password generation failed.', 'error')
    }
  })

  document.body.appendChild(button)
}

document.addEventListener('focusin', async (event) => {
  if (isPassivoOwnPage()) {
    return
  }

  try {
    const input = event.target

    if (!isLoginInput(input)) {
      return
    }

    currentInput = input

    if (isSignupPage(input)) {
      if (isPasswordInput(input)) {
        showGenerateButton(input)

        return
      }

      removeButton({
        passivo: true,
        generate: true,
      })

      return
    }

    const savedInfo = await storageGet(['token', 'privateKey'])

    if (!savedInfo) {
      return
    }

    if (!savedInfo.token || !savedInfo.privateKey) {
      showPassivoButton(input)

      return
    }

    let privateKey

    try {
      privateKey = await getPrivateKey(savedInfo.privateKey)
    } catch (err) {
      console.error('Passivo private key error:', err)

      showPassivoButton(input)

      return
    }

    let matchedItem

    try {
      matchedItem = await findCredentialForCurrentWebsite(privateKey, savedInfo.token)
    } catch (err) {
      console.error('Passivo credential search error:', err)

      return
    }

    if (matchedItem) {
      showPassivoButton(input)

      return
    }

    removeButton({
      passivo: true,
      generate: true,
    })
  } catch (err) {
    if (isExtensionContextError(err)) {
      return
    }

    console.error('Passivo focus handler error:', err)
  }
})

document.addEventListener('click', (event) => {
  if (passivoButton && event.target !== passivoButton && event.target !== currentInput) {
    removeButton({
      passivo: true,
      generate: true,
    })
  }
})

document.addEventListener('submit', handleSignupAttempt, true)

document.addEventListener('mousedown', handleSignupAttempt, true)

document.addEventListener('click', handleSignupAttempt, true)

window.addEventListener(
  'scroll',
  () => {
    removeButton({
      passivo: true,
      generate: true,
    })
  },
  true,
)

window.addEventListener('resize', () => {
  removeButton({
    passivo: true,
    generate: true,
  })
})

window.addEventListener('message', async (event) => {
  if (event.source !== window) {
    return
  }

  if (event.data?.source !== 'PASSIVO_APP') {
    return
  }

  if (event.data?.type !== 'PASSIVO_LOGOUT') {
    return
  }

  await storageClear()
})

if (typeof chrome !== 'undefined' && chrome?.storage?.onChanged) {
  chrome.storage.onChanged.addListener(async (changes, areaName) => {
    if (areaName !== 'local') {
      return
    }

    if (!changes.token && !changes.privateKey) {
      return
    }

    try {
      const savedInfo = await storageGet(['token', 'privateKey'])

      if (!savedInfo?.token || !savedInfo?.privateKey) {
        return
      }

      if (changes.token?.newValue) {
        await restorePendingSignupAfterNavigation()
      }

      if (!currentInput || !document.contains(currentInput)) {
        return
      }

      await fillCredentials()
    } catch (err) {
      if (isExtensionContextError(err)) {
        return
      }

      console.error('Passivo autofill after login error:', err)
    }
  })
}

async function handleSignupAttempt(event) {
  if (isPassivoOwnPage()) {
    return
  }

  if (!isSignupPage(event.target)) {
    return
  }

  if (isSavingSignupPassword) {
    return
  }

  const button = event.target.closest?.('button, input[type="submit"], input[type="button"]')

  if (event.type === 'mousedown' || event.type === 'click') {
    if (!button) {
      return
    }

    const buttonText = `${button.innerText || ''} ${button.value || ''}`.toLowerCase()

    const buttonType = button.type?.toLowerCase()

    const isSignupButton =
      buttonType === 'submit' ||
      buttonText.includes('sign up') ||
      buttonText.includes('signup') ||
      buttonText.includes('register') ||
      buttonText.includes('create account') ||
      buttonText.includes('join') ||
      buttonText.includes('get started') ||
      buttonText.includes('continue')

    if (!isSignupButton) {
      return
    }
  }

  const username = findUsernameInput()?.value?.trim() || ''

  const passwordInputs = [...document.querySelectorAll('input[type="password"]')]

  const passwords = passwordInputs.map((input) => input.value).filter(Boolean)

  if (!passwords.length) {
    return
  }

  const password = passwords[0]

  if (passwords.length > 1 && passwords.some((value) => value !== password)) {
    return
  }

  try {
    const staged = await createPendingSignupCredential(username, password)

    if (!staged) {
      return
    }

    checkSignupResultAndSave()
  } catch (err) {
    if (isExtensionContextError(err)) {
      return
    }

    console.error('Passivo signup staging error:', err)
  }
}

function looksLikeSignupFailed() {
  const text = String(document.body?.innerText || '').toLowerCase()

  return (
    text.includes('invalid email or password') ||
    text.includes('email already exists') ||
    text.includes('email is already registered') ||
    text.includes('email already registered') ||
    text.includes('username already exists') ||
    text.includes('passwords do not match') ||
    text.includes('registration failed') ||
    text.includes('signup failed') ||
    text.includes('sign up failed') ||
    text.includes('could not create account')
  )
}

function looksLikeSignupSucceeded() {
  const url = window.location.href.toLowerCase()

  const text = String(document.body?.innerText || '').toLowerCase()

  return (
    url.includes('dashboard') ||
    url.includes('/account') ||
    url.includes('/profile') ||
    url.includes('/home') ||
    url.includes('/vault') ||
    url.includes('/welcome') ||
    url.includes('/verify') ||
    url.includes('/confirmation') ||
    text.includes('logout') ||
    text.includes('log out') ||
    text.includes('welcome') ||
    text.includes('my account') ||
    text.includes('account created') ||
    text.includes('successfully registered') ||
    text.includes('registration complete') ||
    text.includes('thanks for signing up') ||
    text.includes('check your email') ||
    text.includes('check your inbox') ||
    text.includes('verify your email')
  )
}

function checkSignupResultAndSave() {
  if (signupCheckInterval) {
    return
  }

  let attempts = 0

  const stopChecking = () => {
    if (signupCheckInterval) {
      clearInterval(signupCheckInterval)

      signupCheckInterval = null
    }
  }

  signupCheckInterval = setInterval(async () => {
    attempts += 1

    try {
      const pending = await getPendingSignupCredential()

      if (!pending) {
        stopChecking()

        return
      }

      const age = Date.now() - Number(pending.createdAt || 0)

      if (!pending.createdAt || age > 5 * 60 * 1000) {
        await removePendingSignupCredential()

        stopChecking()

        return
      }

      if (looksLikeSignupFailed()) {
        await removePendingSignupCredential()

        stopChecking()

        return
      }

      const currentHostname = normalizeWebsite(window.location.hostname)

      if (!websitesMatch(currentHostname, pending.hostname)) {
        stopChecking()

        return
      }

      const urlChanged = window.location.href !== pending.urlBeforeSignup

      if (urlChanged || looksLikeSignupSucceeded()) {
        stopChecking()

        await offerPendingPasswordSave()

        return
      }

      if (attempts >= 60) {
        stopChecking()
      }
    } catch (err) {
      stopChecking()

      if (isExtensionContextError(err)) {
        return
      }

      console.error('Passivo signup detection error:', err)
    }
  }, 1000)
}

async function restorePendingSignupAfterNavigation() {
  if (isPassivoOwnPage()) {
    return
  }

  try {
    const pending = await getPendingSignupCredential()

    if (!pending) {
      return
    }

    const age = Date.now() - Number(pending.createdAt || 0)

    if (!pending.createdAt || age > 5 * 60 * 1000) {
      await removePendingSignupCredential()

      return
    }

    const currentHostname = normalizeWebsite(window.location.hostname)

    if (!websitesMatch(currentHostname, pending.hostname)) {
      return
    }

    if (looksLikeSignupFailed()) {
      await removePendingSignupCredential()

      return
    }

    const urlChanged = window.location.href !== pending.urlBeforeSignup

    if (urlChanged || looksLikeSignupSucceeded()) {
      await offerPendingPasswordSave()
    }
  } catch (err) {
    if (isExtensionContextError(err)) {
      return
    }

    console.error('Passivo pending signup restore error:', err)
  }
}

setTimeout(() => {
  restorePendingSignupAfterNavigation()
}, 1200)
