import '#q-app/bex/background'

const API_BASE_URL = 'https://passivo-backend.onrender.com/api'

const PASSIVO_APP_URL = chrome.runtime.getURL('www/index.html')

async function readJsonSafe(response) {
  try {
    return await response.json()
  } catch {
    return null
  }
}

async function apiRequest(path, { method = 'GET', token, body } = {}) {
  if (!token || typeof token !== 'string') {
    return {
      ok: false,
      status: 401,
      error: 'Passivo session token is missing.',
    }
  }

  try {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      method,

      headers: {
        Authorization: `Bearer ${token}`,

        ...(body
          ? {
              'Content-Type': 'application/json',
            }
          : {}),
      },

      ...(body
        ? {
            body: JSON.stringify(body),
          }
        : {}),
    })

    const data = await readJsonSafe(response)

    if (!response.ok) {
      return {
        ok: false,

        status: response.status,

        error:
          data?.message ||
          data?.error ||
          `Passivo API request failed with status ${response.status}.`,

        data,
      }
    }

    return {
      ok: true,

      status: response.status,

      data,
    }
  } catch (err) {
    console.error('Passivo background API request failed:', err)

    return {
      ok: false,

      status: 0,

      error: err?.message || 'Failed to connect to Passivo backend.',
    }
  }
}

async function findExistingPassivoWindow() {
  try {
    const windows = await chrome.windows.getAll({
      populate: true,
    })

    return (
      windows.find((windowInfo) =>
        windowInfo.tabs?.some((tab) => tab.url?.startsWith(PASSIVO_APP_URL)),
      ) || null
    )
  } catch (err) {
    console.error('Passivo window lookup failed:', err)

    return null
  }
}

async function openPassivoLogin() {
  const existingWindow = await findExistingPassivoWindow()

  if (existingWindow?.id) {
    await chrome.windows.update(existingWindow.id, {
      focused: true,
    })

    return
  }

  await chrome.windows.create({
    url: PASSIVO_APP_URL,

    type: 'popup',

    width: 380,

    height: 560,

    focused: true,
  })
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message.type !== 'string') {
    return false
  }

  if (message.type === 'OPEN_PASSIVO_LOGIN') {
    openPassivoLogin().catch((err) => {
      console.error('Passivo login popup failed:', err)
    })

    return false
  }

  if (message.type === 'GET_PASSIVO_PASSWORDS') {
    ;(async () => {
      const result = await apiRequest('/password', {
        method: 'GET',

        token: message.token,
      })

      sendResponse(result)
    })()

    return true
  }

  if (message.type === 'SAVE_PASSIVO_PASSWORD') {
    ;(async () => {
      const payload = message.payload

      if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
        sendResponse({
          ok: false,

          status: 400,

          error: 'Invalid password payload.',
        })

        return
      }

      const result = await apiRequest('/password', {
        method: 'POST',

        token: message.token,

        body: payload,
      })

      sendResponse(result)
    })()

    return true
  }

  return false
})
