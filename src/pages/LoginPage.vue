<template>
  <div class="login-page">
    <q-card flat class="card">
      <img src="~assets/icon-128.png" class="logo" />

      <q-input v-model="email" type="email" placeholder="Email" outlined dense rounded />

      <q-input v-model="password" type="password" placeholder="Password" outlined dense rounded />

      <q-btn
        label="Log in"
        color="positive"
        unelevated
        rounded
        class="login-btn"
        :loading="loading"
        @click="login"
      />
    </q-card>
  </div>
</template>

<script setup>
import { ref } from 'vue'

import { deriveAuthAndEncryptionKeys, exportAuthKey } from 'src/crypto/keys.js'

import {
  base64ToUint8Array,
  base64ToArrayBuffer,
  arrayBufferToBase64,
} from 'src/crypto/encoding.js'

const email = ref('')
const password = ref('')
const loading = ref(false)

async function login() {
  loading.value = true

  try {
    const initRes = await fetch('https://passivo-backend.onrender.com/api/auth/login/init', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: email.value.trim(),
      }),
    })

    const initData = await initRes.json()

    if (!initRes.ok) {
      throw new Error(initData?.message || initData?.data?.message || 'Login init failed')
    }

    const saltBase64 = initData?.data?.salt || initData?.salt

    if (!saltBase64) {
      throw new Error('Salt nije vraćen sa servera')
    }

    const salt = base64ToUint8Array(saltBase64)

    const { authKey, encryptionKey } = await deriveAuthAndEncryptionKeys(password.value, salt)

    const rawAuthKey = await exportAuthKey(authKey)

    const res = await fetch('https://passivo-backend.onrender.com/api/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: email.value.trim(),
        authKey: rawAuthKey,
      }),
    })

    const loginData = await res.json()

    if (!res.ok) {
      throw new Error(loginData?.message || loginData?.data?.message || 'Login failed')
    }

    const user = loginData?.data?.user
    const token = loginData?.data?.token

    if (!user) {
      throw new Error('User nije vraćen sa servera')
    }

    if (!token) {
      throw new Error('Token nije vraćen sa servera')
    }

    if (!user.privateKey) {
      throw new Error('Private key nije vraćen sa servera')
    }

    if (!user.iv) {
      throw new Error('IV nije vraćen sa servera')
    }

    if (!user.publicKey) {
      throw new Error('Public key nije vraćen sa servera')
    }

    const decryptedPrivateKey = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: base64ToUint8Array(user.iv),
      },
      encryptionKey,
      base64ToArrayBuffer(user.privateKey),
    )

    await chrome.storage.local.set({
      token,
      privateKey: arrayBufferToBase64(decryptedPrivateKey),
      publicKey: user.publicKey,
    })

    window.close()
  } catch (err) {
    console.error('PASSIVO LOGIN ERROR:', err)

    alert('ERROR: ' + (err?.message || 'Login failed'))
  } finally {
    loading.value = false
  }
}
</script>
<style scoped>
.login-page {
  width: 360px;
  padding: 22px;
  background: linear-gradient(180deg, #ffffff 0%, #f6fbf8 100%);
  box-sizing: border-box;
  font-family: Inter, Arial, sans-serif;
}

.card {
  display: flex;
  flex-direction: column;
  gap: 14px;
  background: transparent;
  border-radius: 24px;
}

.logo {
  width: 104px;
  height: 104px;
  object-fit: contain;
  margin: 0 auto 12px;
}

:deep(.q-field__control) {
  height: 48px;
  border-radius: 16px;
  background: #ffffff;
  box-shadow: 0 2px 10px rgba(15, 23, 42, 0.04);
}

:deep(.q-field__native),
:deep(.q-field__input) {
  font-size: 14px;
  color: #111827;
}

:deep(.q-field__control:before) {
  border-color: #d9e2dc;
}

:deep(.q-field--focused .q-field__control:after) {
  border-width: 2px;
}

.login-btn {
  height: 50px;
  margin-top: 4px;
  border-radius: 18px;
  font-weight: 800;
  letter-spacing: 0.5px;
  box-shadow: 0 10px 22px rgba(35, 185, 91, 0.28);
}

.login-btn:hover {
  transform: translateY(-1px);
}

.login-btn:active {
  transform: translateY(0);
}
</style>
