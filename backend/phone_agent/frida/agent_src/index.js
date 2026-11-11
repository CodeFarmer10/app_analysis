import Java from 'frida-java-bridge';

const rules = globalThis.__frida_rules__ || [];
const HTTP_DUPLICATE_WINDOW_MS = 100;
const recentHttpFingerprints = new Map();
const STATIC_CONTENT_TYPE_PREFIXES = ['image/', 'video/', 'audio/', 'font/'];
const STATIC_CONTENT_TYPES = new Set([
  'application/javascript',
  'application/pdf',
  'application/wasm',
  'application/zip',
  'text/css',
  'text/javascript',
]);
const STATIC_URL_SUFFIX = /\.(?:7z|avi|css|gif|gz|jpeg|jpg|js|m4a|m4v|mkv|mp3|mp4|png|svg|tar|wasm|webm|webp|woff2?|zip)(?:[?#]|$)/i;

function safeToString(value) {
  try {
    if (value === null || value === undefined) {
      return null;
    }
    return String(value);
  } catch (_error) {
    return '<unprintable>';
  }
}

function isClassNotFoundError(error) {
  const message = safeToString(error) || '';
  return message.includes('ClassNotFoundException') || message.includes("Didn't find class");
}

function sendState(status, extra) {
  const payload = {
    type: 'state',
    status,
  };
  if (extra) {
    Object.keys(extra).forEach((key) => {
      payload[key] = extra[key];
    });
  }
  send(payload);
}

function safeJson(value) {
  try {
    return JSON.stringify(value);
  } catch (_error) {
    return null;
  }
}

function headersToObject(headers) {
  const result = {};
  if (!headers) {
    return result;
  }
  try {
    const size = headers.size();
    for (let index = 0; index < size; index += 1) {
      const name = safeToString(headers.name(index));
      const value = safeToString(headers.value(index));
      if (name) {
        result[name.toLowerCase()] = value;
      }
    }
  } catch (_error) {
    return result;
  }
  return result;
}

function mapToObject(headers) {
  const result = {};
  if (!headers) {
    return result;
  }
  try {
    const iterator = headers.entrySet().iterator();
    while (iterator.hasNext()) {
      const entry = iterator.next();
      const key = safeToString(entry.getKey());
      const value = safeToString(entry.getValue());
      if (key) {
        result[key.toLowerCase()] = value;
      }
    }
  } catch (_error) {
    return result;
  }
  return result;
}

function bodyPreview(body, limit) {
  if (!body) {
    return null;
  }
  try {
    const Buffer = Java.use('okio.Buffer');
    const buffer = Buffer.$new();
    body.writeTo(buffer);
    const text = safeToString(buffer.readUtf8());
    return text ? text.slice(0, limit) : null;
  } catch (_error) {
    return null;
  }
}

function byteArrayPreview(value, limit) {
  if (!value) {
    return null;
  }
  try {
    const JavaString = Java.use('java.lang.String');
    const text = safeToString(JavaString.$new(value, 'UTF-8'));
    return text ? text.slice(0, limit) : null;
  } catch (_error) {
    return null;
  }
}

function isStaticResponse(responseHeaders, url) {
  const contentType = (safeToString(responseHeaders && responseHeaders['content-type']) || '')
    .split(';', 1)[0]
    .trim()
    .toLowerCase();
  if (STATIC_CONTENT_TYPES.has(contentType)) {
    return true;
  }
  if (STATIC_CONTENT_TYPE_PREFIXES.some((prefix) => contentType.startsWith(prefix))) {
    return true;
  }
  const genericBinary = contentType === 'application/octet-stream';
  return Boolean(url && STATIC_URL_SUFFIX.test(url) && (!contentType || genericBinary));
}

function isDuplicateHttpTransaction(payload) {
  const now = Date.now();
  recentHttpFingerprints.forEach((timestamp, fingerprint) => {
    if (now - timestamp > HTTP_DUPLICATE_WINDOW_MS) {
      recentHttpFingerprints.delete(fingerprint);
    }
  });
  const fingerprint = safeJson([
    payload.method,
    payload.url,
    payload.response_status,
    payload.request_headers_json,
    payload.request_body_preview,
    payload.response_headers_json,
    payload.response_body_preview,
    payload.content_type,
  ]);
  const previous = recentHttpFingerprints.get(fingerprint);
  recentHttpFingerprints.set(fingerprint, now);
  return previous !== undefined && now - previous <= HTTP_DUPLICATE_WINDOW_MS;
}

function emitHttpTransaction(response, metadata) {
  try {
    const request = response.request();
    const url = safeToString(request.url());
    const responseHeaders = headersToObject(response.headers());
    const contentType = responseHeaders['content-type'] || null;
    const responseBody = isStaticResponse(responseHeaders, url)
      ? null
      : response.peekBody(65536);
    const payload = {
      timestamp: Date.now() / 1000,
      capture_source: 'network_hook',
      hook_library: metadata && metadata.hook_library ? metadata.hook_library : 'okhttp3/4',
      hook_class: metadata && metadata.hook_class ? metadata.hook_class : 'okhttp3.Response$Builder',
      hook_method: metadata && metadata.hook_method ? metadata.hook_method : 'build',
      parse_status: 'complete',
      is_complete: true,
      method: safeToString(request.method()),
      url,
      request_headers_json: safeJson(headersToObject(request.headers())),
      request_body_preview: bodyPreview(request.body(), 65536),
      response_status: response.code(),
      response_headers_json: safeJson(responseHeaders),
      response_body_preview: responseBody ? bodyPreview(responseBody, 65536) : null,
      content_type: contentType,
    };
    if (isDuplicateHttpTransaction(payload)) {
      sendState('http_transaction_duplicate', {
        method: payload.method,
        url: payload.url,
      });
      return;
    }
    send({
      type: 'http_transaction',
      payload,
    });
  } catch (error) {
    sendState('http_hook_error', { error: safeToString(error) });
  }
}

function emitPartialHttpTransaction(metadata) {
  const payload = metadata || {};
  if (!payload.url) {
    return;
  }
  send({
    type: 'http_transaction',
    payload: {
      timestamp: Date.now() / 1000,
      capture_source: 'network_hook',
      hook_library: payload.hook_library || 'unknown',
      hook_class: payload.hook_class || null,
      hook_method: payload.hook_method || null,
      parse_status: 'partial',
      is_complete: false,
      method: payload.method || 'GET',
      url: payload.url,
      request_headers_json: payload.request_headers
        ? safeJson(payload.request_headers)
        : null,
      request_body_preview: payload.request_body || null,
      response_status: payload.response_status || null,
      response_headers_json: payload.response_headers
        ? safeJson(payload.response_headers)
        : null,
      response_body_preview: payload.response_body || null,
      content_type: payload.content_type || null,
    },
  });
}

function installOkHttpHooks() {
  try {
    const ResponseBuilder = Java.use('okhttp3.Response$Builder');
    const overloads = ResponseBuilder.build.overloads || [];
    overloads.forEach(function (overload) {
      if ((overload.argumentTypes || []).length !== 0) {
        return;
      }
      overload.implementation = function () {
        const response = overload.call(this);
        emitHttpTransaction(response, {
          hook_library: 'okhttp3/4',
          hook_class: 'okhttp3.Response$Builder',
          hook_method: 'build',
        });
        return response;
      };
    });
    sendState('network_hooked', { class_name: 'okhttp3.Response$Builder', method_name: 'build' });
  } catch (error) {
    if (!isClassNotFoundError(error)) {
      sendState('http_hook_error', { error: safeToString(error) });
    }
  }
}

function installHttpURLConnectionHooks() {
  try {
    const HttpURLConnection = Java.use('java.net.HttpURLConnection');
    const overloads = HttpURLConnection.getResponseCode.overloads || [];
    overloads.forEach(function (overload) {
      if ((overload.argumentTypes || []).length !== 0) {
        return;
      }
      overload.implementation = function () {
        const responseCode = overload.call(this);
        try {
          const url = safeToString(this.getURL());
          let method = 'GET';
          try {
            method = safeToString(this.getRequestMethod()) || method;
          } catch (_error) {
            // Some vendor implementations do not expose request method here.
          }
          let requestHeaders = null;
          let responseHeaders = null;
          try {
            requestHeaders = mapToObject(this.getRequestProperties());
          } catch (_error) {
            requestHeaders = null;
          }
          try {
            responseHeaders = mapToObject(this.getHeaderFields());
          } catch (_error) {
            responseHeaders = null;
          }
          emitPartialHttpTransaction({
            hook_library: 'httpurlconnection',
            hook_class: 'java.net.HttpURLConnection',
            hook_method: 'getResponseCode',
            method,
            url,
            request_headers: requestHeaders,
            response_headers: responseHeaders,
            response_status: responseCode,
          });
        } catch (error) {
          sendState('http_hook_error', {
            hook_library: 'httpurlconnection',
            error: safeToString(error),
          });
        }
        return responseCode;
      };
    });
    sendState('network_hooked', {
      class_name: 'java.net.HttpURLConnection',
      method_name: 'getResponseCode',
    });
  } catch (error) {
    if (!isClassNotFoundError(error)) {
      sendState('http_hook_error', { error: safeToString(error) });
    }
  }
}

function installWebViewHooks() {
  try {
    const WebView = Java.use('android.webkit.WebView');
    const overloads = WebView.loadUrl.overloads || [];
    overloads.forEach(function (overload) {
      const argTypes = overload.argumentTypes || [];
      if (argTypes.length === 0 || argTypes[0].className !== 'java.lang.String') {
        return;
      }
      overload.implementation = function () {
        const url = safeToString(arguments[0]);
        let headers = null;
        if (arguments.length > 1) {
          headers = mapToObject(arguments[1]);
        }
        emitPartialHttpTransaction({
          hook_library: 'webview',
          hook_class: 'android.webkit.WebView',
          hook_method: 'loadUrl',
          method: 'GET',
          url,
          request_headers: headers,
        });
        return overload.call.apply(overload, [this].concat(Array.prototype.slice.call(arguments)));
      };
    });

    const postOverloads = WebView.postUrl && WebView.postUrl.overloads
      ? WebView.postUrl.overloads
      : [];
    postOverloads.forEach(function (overload) {
      const argTypes = overload.argumentTypes || [];
      if (argTypes.length < 2 || argTypes[0].className !== 'java.lang.String') {
        return;
      }
      overload.implementation = function () {
        emitPartialHttpTransaction({
          hook_library: 'webview',
          hook_class: 'android.webkit.WebView',
          hook_method: 'postUrl',
          method: 'POST',
          url: safeToString(arguments[0]),
          request_body: byteArrayPreview(arguments[1], 65536),
        });
        return overload.call.apply(overload, [this].concat(Array.prototype.slice.call(arguments)));
      };
    });
    sendState('network_hooked', { class_name: 'android.webkit.WebView', method_name: 'loadUrl' });
    sendState('network_hooked', { class_name: 'android.webkit.WebView', method_name: 'postUrl' });
  } catch (error) {
    if (!isClassNotFoundError(error)) {
      sendState('http_hook_error', { error: safeToString(error) });
    }
  }
}

function installCronetHooks() {
  const builders = new Map();
  try {
    const Builder = Java.use('org.chromium.net.UrlRequest$Builder');
    const builderKey = function (instance) {
      return safeToString(instance);
    };

    if (Builder.$init && Builder.$init.overloads) {
      Builder.$init.overloads.forEach(function (overload) {
        overload.implementation = function () {
          const result = overload.call.apply(
            overload,
            [this].concat(Array.prototype.slice.call(arguments))
          );
          let url = null;
          for (let index = 0; index < arguments.length; index += 1) {
            const candidate = safeToString(arguments[index]);
            if (candidate && candidate.includes('://')) {
              url = candidate;
              break;
            }
          }
          builders.set(builderKey(this), { url, method: 'GET', headers: {} });
          return result;
        };
      });
    }

    const setHttpMethod = Builder.setHttpMethod.overloads || [];
    setHttpMethod.forEach(function (overload) {
      overload.implementation = function (method) {
        const key = builderKey(this);
        const state = builders.get(key) || { url: null, method: 'GET', headers: {} };
        state.method = safeToString(method) || state.method;
        builders.set(key, state);
        return overload.call(this, method);
      };
    });

    const addHeader = Builder.addHeader.overloads || [];
    addHeader.forEach(function (overload) {
      overload.implementation = function (name, value) {
        const key = builderKey(this);
        const state = builders.get(key) || { url: null, method: 'GET', headers: {} };
        const headerName = safeToString(name);
        if (headerName) {
          state.headers[headerName.toLowerCase()] = safeToString(value);
        }
        builders.set(key, state);
        return overload.call(this, name, value);
      };
    });

    const build = Builder.build.overloads || [];
    build.forEach(function (overload) {
      if ((overload.argumentTypes || []).length !== 0) {
        return;
      }
      overload.implementation = function () {
        const result = overload.call(this);
        const state = builders.get(builderKey(this));
        if (state && state.url) {
          emitPartialHttpTransaction({
            hook_library: 'cronet',
            hook_class: 'org.chromium.net.UrlRequest$Builder',
            hook_method: 'build',
            method: state.method,
            url: state.url,
            request_headers: state.headers,
          });
        }
        return result;
      };
    });
    sendState('network_hooked', { class_name: 'org.chromium.net.UrlRequest$Builder', method_name: 'build' });
  } catch (error) {
    if (!isClassNotFoundError(error)) {
      sendState('http_hook_error', { error: safeToString(error) });
    }
  }
}

function installHooks() {
  sendState('script_loaded', { rule_count: rules.length });
  installOkHttpHooks();
  installHttpURLConnectionHooks();
  installWebViewHooks();
  installCronetHooks();

  rules.forEach(function (rule) {
    try {
      let targetClass;
      try {
        targetClass = Java.use(rule.class_name);
      } catch (error) {
        if (isClassNotFoundError(error)) {
          sendState('class_missing', {
            rule_id: rule.id,
            class_name: rule.class_name,
          });
          return;
        }
        throw error;
      }
      if (!targetClass[rule.method_name]) {
        sendState('method_missing', { rule_id: rule.id });
        return;
      }
      const overloads = targetClass[rule.method_name].overloads || [];
      let boundCount = 0;

      overloads.forEach(function (overload) {
        try {
          const argTypes = overload.argumentTypes || [];
          if (rule.arg_count !== null && rule.arg_count !== undefined && argTypes.length !== rule.arg_count) {
            return;
          }
          const signature = argTypes
            .map(function (item) {
              return item.className || item.name || 'unknown';
            })
            .join(',');

          overload.implementation = function () {
            let argIndex = null;
            let args = null;
            if (rule.stringify_args) {
              const rawIndex = rule.hook_args;
              let targetIndex = 0;
              if (rawIndex !== null && rawIndex !== undefined) {
                const parsed = Number(rawIndex);
                if (Number.isFinite(parsed) && parsed >= 0) {
                  targetIndex = Math.floor(parsed);
                }
              }
              if (targetIndex >= 0 && targetIndex < arguments.length) {
                argIndex = targetIndex;
                args = safeToString(arguments[targetIndex]);
              }
            }

            const retval = overload.call.apply(
              overload,
              [this].concat(Array.prototype.slice.call(arguments))
            );
            send({
              type: 'event',
              payload: {
                rule_id: rule.id,
                class_name: rule.class_name,
                method_name: rule.method_name,
                signature,
                timestamp: Date.now() / 1000,
                arg_index: argIndex,
                args,
                retval: rule.include_retval && rule.stringify_retval ? safeToString(retval) : null,
              },
            });
            return retval;
          };
          boundCount += 1;
        } catch (hookError) {
          sendState('hook_error', {
            rule_id: rule.id,
            error: safeToString(hookError),
          });
        }
      });

      sendState('hooked', {
        rule_id: rule.id,
        overloads: boundCount,
      });
    } catch (error) {
      sendState('hook_error', {
        rule_id: rule.id,
        error: safeToString(error),
      });
    }
  });
}

function startJavaHooks() {
  try {
    Java.perform(function () {
      sendState('java_ready');
      installHooks();
    });
  } catch (error) {
    sendState('java_bridge_error', {
      error: safeToString(error),
    });
  }
}

setImmediate(startJavaHooks);
