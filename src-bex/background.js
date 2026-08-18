import '#q-app/bex/background'
chrome.runtime.onMessage.addListener((message) => {
  if (message.type === 'OPEN_PASSIVO_LOGIN') {
    chrome.action.openPopup().catch(() => {
      chrome.windows.create({
        url: chrome.runtime.getURL('www/index.html#/'),
        type: 'popup',
        width: 390,
        height: 520,
      })
    })

    return
  }
})
