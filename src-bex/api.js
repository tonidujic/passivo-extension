import axios from 'axios'

const api = axios.create({
  baseURL: 'https://passivo-backend.onrender.com/api',
})

api.interceptors.request.use(
  async (config) => {
    try {
      const { token } = await chrome.storage.local.get(['token'])

      if (token) {
        config.headers.Authorization = `Bearer ${token}`
      }
    } catch (err) {
      console.error('Failed to read Passivo token:', err)
    }

    return config
  },
  (error) => Promise.reject(error),
)

api.interceptors.response.use(
  (response) => response,

  async (error) => {
    if (error.response?.status === 401) {
      try {
        await chrome.storage.local.clear()

        chrome.runtime.sendMessage({
          type: 'OPEN_PASSIVO_LOGIN',
        })
      } catch (err) {
        console.error('Failed to clear Passivo session:', err)
      }
    }

    return Promise.reject(error)
  },
)

export default api
