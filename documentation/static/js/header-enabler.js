const createMedusScript = () => {
  const element = document.createElement('script')
  element.src = '/sgroups/js/header.bundle.js'
  element.type = 'text/javascript'
  document.querySelector('body').appendChild(element)
}

const injectOnLandingLoad = () => {
  if (document.location.pathname === '/sgroups/landing') {
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
      if (document.location.pathname === '/sgroups/landing') {
        document.getElementById('medusa-root').style.display = 'block'
        document.getElementsByTagName('body')[0].style.overflowX = 'hidden'
        if (!scriptInjected) {
          createMedusScript()
          scriptInjected = true
        }
      } else {
        document.getElementById('medusa-root').style.display = 'none'
        document.getElementsByTagName('body')[0].style.overflowX = 'auto'
      }
    }
  })
  observer.observe(body, { childList: true, subtree: true })
}

window.onload = observeUrlChange
