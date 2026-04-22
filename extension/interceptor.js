(function() {
  const originalFetch = window.fetch;

  window.fetch = async function(...args) {
    const response = await originalFetch.apply(this, args);

    try {
      const url = typeof args[0] === 'string' ? args[0] : args[0]?.url || '';

      if (url.includes('api.lovable.dev')) {
        // Capture Authorization header from any Lovable API request
        const headers = args[1]?.headers;
        let authHeader = null;
        if (headers) {
          if (headers instanceof Headers) {
            authHeader = headers.get('Authorization') || headers.get('authorization');
          } else if (typeof headers === 'object') {
            authHeader = headers['Authorization'] || headers['authorization'];
          }
        }
        if (authHeader) {
          window.postMessage({
            type: 'LOVABLE_CT_AUTH_TOKEN',
            token: authHeader,
            url: url,
          }, '*');
        }

        // Intercept ALL Lovable API responses (workspaces, projects, individual workspace updates, etc.)
        const clone = response.clone();
        clone.json().then(body => {
          console.log('[ControlHub] Intercepted:', url);
          window.postMessage({
            type: 'LOVABLE_CT_INTERCEPT',
            url: url,
            method: args[1]?.method || 'GET',
            body: body
          }, '*');
        }).catch(() => {});
      }
    } catch (e) {}

    return response;
  };

  const origOpen = XMLHttpRequest.prototype.open;
  const origSend = XMLHttpRequest.prototype.send;
  const origSetHeader = XMLHttpRequest.prototype.setRequestHeader;

  XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    this._lctUrl = url;
    this._lctMethod = method;
    this._lctHeaders = {};
    return origOpen.call(this, method, url, ...rest);
  };

  XMLHttpRequest.prototype.setRequestHeader = function(name, value) {
    if (this._lctHeaders) {
      this._lctHeaders[name] = value;
    }
    return origSetHeader.call(this, name, value);
  };

  XMLHttpRequest.prototype.send = function(...args) {
    this.addEventListener('load', function() {
      try {
        const url = this._lctUrl || '';
        if (url.includes('api.lovable.dev')) {
          // Capture auth header from XHR
          const authHeader = this._lctHeaders?.['Authorization'] || this._lctHeaders?.['authorization'];
          if (authHeader) {
            window.postMessage({
              type: 'LOVABLE_CT_AUTH_TOKEN',
              token: authHeader,
              url: url,
            }, '*');
          }

          // Relay ALL Lovable API responses
          const body = JSON.parse(this.responseText);
          console.log('[ControlHub] XHR Intercepted:', url);
          window.postMessage({
            type: 'LOVABLE_CT_INTERCEPT',
            url: url,
            method: this._lctMethod || 'GET',
            body: body
          }, '*');
        }
      } catch (e) {}
    });
    return origSend.apply(this, args);
  };

  console.log('[ControlHub] Interceptor loaded');
})();
