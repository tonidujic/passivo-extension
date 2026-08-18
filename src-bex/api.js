import axios from 'axios'

const api = axios.create({
  baseURL: 'http://localhost:3000/api',
  withCredentials: true,
})

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      await chrome.storage.local.clear()

      chrome.runtime.sendMessage({
        type: 'OPEN_PASSIVO_LOGIN',
      })
    }

    return Promise.reject(error)
  },
)

export default api
