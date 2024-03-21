const createMedusScript = () => {
  const element = document.createElement('script')
  element.src = '/sgroups/js/header.bundle.js'
  element.type = 'text/javascript'
  document.querySelector('body').appendChild(element)
}

const injectOnLandingLoad = () => {
  if (document.location.pathname === '/sgroups/') {
    createMedusScript()
  }
}

const observeUrlChange = () => {
  injectOnLandingLoad()
  let oldHref = document.location.href
  let scriptInjected = false
  const body = document.querySelector('body')
  const observer = new MutationObserver(mutations => {
    if (oldHref !== document.location.href) {
      oldHref = document.location.href
      if (document.location.pathname === '/sgroups/') {
        document.getElementById('medusa-root').style.display = 'block'
        if (!scriptInjected) {
          createMedusScript()
          scriptInjected = true
        }
      } else {
        document.getElementById('medusa-root').style.display = 'none'
      }
    }
  })
  observer.observe(body, { childList: true, subtree: true })
}

window.onload = observeUrlChange
