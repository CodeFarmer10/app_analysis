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

const BODY_LIMIT = 65536;

function byteArrayPreview(value, limit) {
  if (!value || value.length > limit) return null;
  try {
    const JavaString = Java.use('java.lang.String');
    return safeToString(JavaString.$new(value, 'UTF-8'));
  } catch (_error) { return null; }
}

// Observation failures must never replace an app return value or exception.
let observing = false;
function observe(fn) {
  if (observing) return;
  observing = true;
  try { fn(); } catch (error) {
    try { sendState('http_hook_error', { error: safeToString(error) }); } catch (_ignored) {}
  } finally { observing = false; }
}
function read(fn, fallback = null) {
  try { return fn(); } catch (_error) { return fallback; }
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

function passiveRequestBodyPreview(body, url, headers) {
  if (!body || isStaticResponse(headers, url)) return null;
  return read(() => {
    const target = instanceTarget(body);
    // Do not execute arbitrary methods on custom bodies during observation.
    if (!/^okhttp3\.RequestBody\$(?:Companion\$toRequestBody\$)?[0-9]+$/.test(target.name)) return null;
    if (body.isOneShot() !== false || body.isDuplex() !== false) return null;
    const size = Number(body.contentLength());
    if (!Number.isInteger(size) || size < 0 || size > BODY_LIMIT) return null;
    // Only inspect the storage of OkHttp's built-in byte-array bodies. Unknown/custom
    // bodies remain metadata-only, even when they advertise a small contentLength.
    const concrete = Java.cast(body, target.context.factory.use(target.name));
    const kotlin = target.name.includes('$Companion$');
    // frida-java-bridge exposes fields beginning with '$' with an '_' prefix.
    const bytes = concrete[kotlin ? '_$this_toRequestBody' : 'val$content'].value;
    const offset = Number(concrete[kotlin ? '_$offset' : 'val$offset'].value);
    const count = Number(concrete[kotlin ? '_$byteCount' : 'val$byteCount'].value);
    if (!Number.isInteger(offset) || offset < 0 || count !== size || offset + count > bytes.length) return null;
    return safeToString(Java.use('java.lang.String').$new(bytes, offset, count, 'UTF-8'));
  });
}
function requestMetadata(request, metadata) {
  const url = read(() => safeToString(request.url()));
  const headers = read(() => headersToObject(request.headers()));
  return Object.assign({}, metadata, {
    url,
    method: read(() => safeToString(request.method())),
    request_headers: headers,
    request_body: passiveRequestBodyPreview(read(() => request.body()), url, headers),
  });
}

function emitHttpTransaction(response, metadata) {
  const request = read(() => response.request());
  if (!request) return;
  const details = requestMetadata(request, metadata);
  const responseHeaders = read(() => headersToObject(response.headers()));
  const payload = partialPayload(Object.assign(details, {
    response_status: read(() => response.code()),
    response_headers: responseHeaders,
    content_type: responseHeaders && responseHeaders['content-type'],
  }));
  // Send metadata before inspecting the response body. Never ask the upstream
  // source to fill a preview: even a bounded peekBody may wait indefinitely.
  if (!payload.url) return;
  if (!isDuplicateHttpTransaction(payload)) send({ type: 'http_transaction', payload });
  const contentType = (payload.content_type || '').split(';', 1)[0].trim().toLowerCase();
  const streaming = contentType === 'text/event-stream' || contentType.startsWith('application/grpc');
  let declaredLength = null;
  let copiedLength = 0;
  if (!streaming && !isStaticResponse(responseHeaders, details.url)) {
    payload.response_body_preview = read(() => {
      const body = response.body();
      const buffered = body.source().buffer();
      const available = Number(buffered.size());
      if (!Number.isFinite(available) || available <= 0) return null;
      copiedLength = Math.min(available, BODY_LIMIT);
      const context = read(() => instanceTarget(buffered).context, defaultContext);
      const copy = context.factory.use('okio.Buffer').$new();
      buffered.copyTo(copy, 0, copiedLength);
      declaredLength = read(() => Number(body.contentLength()));
      return safeToString(copy.readUtf8());
    });
  }
  // A prefix without a proven complete length remains a partial observation.
  const requestBody = read(() => request.body(), undefined);
  payload.is_complete = payload.response_body_preview !== null && declaredLength !== null
    && declaredLength >= 0 && copiedLength === declaredLength && responseHeaders !== null
    && payload.response_status !== null && (requestBody === null || payload.request_body_preview !== null);
  payload.parse_status = payload.is_complete ? 'complete' : 'partial';
  if (payload.response_body_preview !== null && !isDuplicateHttpTransaction(payload)) send({ type: 'http_transaction', payload });
}

function partialPayload(payload) {
  return {
    timestamp: Date.now() / 1000,
    capture_source: 'network_hook',
    hook_library: payload.hook_library || 'unknown',
    hook_class: payload.hook_class || null,
    hook_method: payload.hook_method || null,
    parse_status: 'partial',
    is_complete: false,
    method: payload.method || null,
    url: payload.url,
    request_headers_json: payload.request_headers ? safeJson(payload.request_headers) : null,
    // RequestBody.writeTo can consume even apparently repeatable bodies. Do not replay it.
    request_body_preview: payload.request_body ?? null,
    response_status: payload.response_status ?? null,
    response_headers_json: payload.response_headers ? safeJson(payload.response_headers) : null,
    response_body_preview: null,
    content_type: payload.content_type || null,
  };
}
function emitPartialHttpTransaction(metadata) {
  if (metadata && metadata.url) send({ type: 'http_transaction', payload: partialPayload(metadata) });
}

const installedMethods = new Set();
// The bridge's .implementation getter exposes a NativeCallback, not the JS
// closure passed to its setter. Keep our closures explicitly for composition.
const methodHandlers = new Map();
function methodKey(context, name, methodName, overload) {
  return overload.handle ? String(overload.handle)
    : [context.id, name, methodName, ...(overload.argumentTypes || []).map(t => t.className)].join(':');
}
const objectIds = new WeakMap();
let nextObjectId = 1;
function identity(value) {
  return read(() => String(Java.use('java.lang.System').identityHashCode(value)), null)
    || read(() => {
      if (!objectIds.has(value)) objectIds.set(value, nextObjectId++);
      return String(objectIds.get(value));
    }, safeToString(value));
}
function boundedSet(map, key, value) {
  if (!map.has(key) && map.size >= 1024) map.delete(map.keys().next().value);
  map.set(key, value);
}
const defaultContext = { factory: Java, id: 'default' };
function instanceTarget(instance, fallback) {
  const cls = instance.getClass();
  const loader = cls.getClassLoader();
  return { name: safeToString(cls.getName()), context: loader
    ? { factory: Java.ClassFactory.get(loader), id: identity(loader) }
    : fallback || defaultContext };
}
function hook(context, name, methodName, before, after, accepts) {
  const cls = read(() => context.factory.use(name));
  if (!cls) return;
  const method = read(() => cls[methodName]);
  if (!method) return;
  (method.overloads || []).forEach(overload => {
    if (accepts && !accepts(overload.argumentTypes || [])) return;
    // Native method identity also deduplicates inherited methods reached through subclasses.
    const key = methodKey(context, name, methodName, overload);
    if (installedMethods.has(key)) return;
    try {
      const previousImplementation = methodHandlers.get(key);
      const handler = function () {
        const args = Array.prototype.slice.call(arguments);
        if (before) observe(() => before(this, args));
        const result = previousImplementation
          ? previousImplementation.apply(this, args)
          : overload.call.apply(overload, [this].concat(args));
        if (after) observe(() => after(this, args, result));
        return result;
      };
      overload.implementation = handler;
      methodHandlers.set(key, handler);
      installedMethods.add(key);
      sendState('network_hooked', { class_name: name, method_name: methodName, loader: context.id });
    } catch (error) {
      sendState('http_hook_error', { class_name: name, method_name: methodName, error: safeToString(error) });
    }
  });
}
const noArgs = types => types.length === 0;
const meta = (library, name, method) => ({ hook_library: library, hook_class: name, hook_method: method });

function installOkHttpCall(context, name) {
  ['execute', 'enqueue'].forEach(method => hook(context, name, method, (self, args) => {
    emitPartialHttpTransaction(requestMetadata(self.request(), meta('okhttp3/4', name, method)));
    if (method === 'enqueue' && args[0]) {
      const target = instanceTarget(args[0], context);
      hook(target.context, target.name, 'onResponse', (_cb, _args) => {
        emitHttpTransaction(_args[1], meta('okhttp3/4', target.name, 'onResponse'));
      });
    }
  }, method === 'execute' ? (_self, _args, result) => emitHttpTransaction(result, meta('okhttp3/4', name, method)) : null));
}
function installOkHttpHooks(context) {
  const name = 'okhttp3.OkHttpClient';
  // Factories identify the concrete public Call implementation, not a transfer.
  hook(context, name, 'newCall', null, (_self, _args, result) => {
    const target = instanceTarget(result, context);
    installOkHttpCall(target.context, target.name);
  });
  ['okhttp3.RealCall', 'okhttp3.internal.connection.RealCall'].forEach(name => installOkHttpCall(context, name));
}

function connectionMetadata(self, name, method) {
  return Object.assign(meta('httpurlconnection', name, method), {
    url: read(() => safeToString(self.getURL())),
    method: read(() => safeToString(self.getRequestMethod())),
    request_headers: read(() => mapToObject(self.getRequestProperties())),
  });
}
function installConnection(context, name) {
  ['connect', 'getResponseCode', 'getInputStream', 'getOutputStream'].forEach(method => {
    hook(context, name, method, self => emitPartialHttpTransaction(connectionMetadata(self, name, method)),
      method === 'getResponseCode' ? (self, _args, result) => {
        // Never call getHeaderFields/getInputStream here: vendor implementations may do I/O.
        emitPartialHttpTransaction(Object.assign(connectionMetadata(self, name, method), { response_status: result }));
      } : null, noArgs);
  });
}
function installHttpURLConnectionHooks(context) {
  ['java.net.HttpURLConnection', 'javax.net.ssl.HttpsURLConnection',
    'com.android.okhttp.internal.huc.HttpURLConnectionImpl',
    'com.android.okhttp.internal.huc.HttpsURLConnectionImpl',
    'com.android.okhttp.internal.http.HttpURLConnectionImpl',
    'com.android.okhttp.internal.http.HttpsURLConnectionImpl',
    'libcore.net.http.HttpURLConnectionImpl', 'libcore.net.http.HttpsURLConnectionImpl']
    .forEach(name => installConnection(context, name));
  hook(context, 'java.net.URL', 'openConnection', null, (_self, _args, connection) => {
    const target = instanceTarget(connection, context);
    installConnection(target.context, target.name);
  });
}

function installWebClient(context, name, serviceWorker = false) {
  ['shouldInterceptRequest', 'onLoadResource'].forEach(method => hook(context, name, method, (_self, args) => {
    const value = args[serviceWorker ? 0 : 1];
    const details = meta(serviceWorker ? 'webview_service_worker' : 'webview', name, method);
    if (typeof value === 'string' || read(() => value.$className) === 'java.lang.String') {
      details.url = safeToString(value);
    } else {
      details.url = read(() => safeToString(value.getUrl()));
      details.method = read(() => safeToString(value.getMethod()));
      details.request_headers = read(() => mapToObject(value.getRequestHeaders()));
    }
    emitPartialHttpTransaction(details);
  }));
}
function installWebViewHooks(context) {
  const name = 'android.webkit.WebView';
  ['loadUrl', 'postUrl'].forEach(method => hook(context, name, method, (_self, args) => {
    const url = safeToString(args[0]);
    emitPartialHttpTransaction(Object.assign(meta('webview', name, method), {
      url, method: method === 'postUrl' ? 'POST' : 'GET',
      request_headers: method === 'loadUrl' && args[1] ? mapToObject(args[1]) : null,
      request_body: method === 'postUrl' && !isStaticResponse(null, url) ? byteArrayPreview(args[1], BODY_LIMIT) : null,
    }));
  }, null, types => types.length > 0 && types[0].className === 'java.lang.String'));
  hook(context, name, 'setWebViewClient', (_self, args) => {
    if (!args[0]) return;
    const target = instanceTarget(args[0], context);
    installWebClient(target.context, target.name);
  });
  // Hook the provider's concrete controller as well as the API base.
  const installController = (ctx, className) => hook(ctx, className, 'setServiceWorkerClient', (_self, args) => {
    if (!args[0]) return;
    const target = instanceTarget(args[0], ctx);
    installWebClient(target.context, target.name, true);
  });
  installController(context, 'android.webkit.ServiceWorkerController');
  hook(context, 'android.webkit.ServiceWorkerController', 'getInstance', null, (_self, _args, controller) => {
    const target = instanceTarget(controller, context);
    installController(target.context, target.name);
  });
}

const cronetBuilders = new Map();
const cronetRequests = new Map();
function installCronetCallback(context, name) {
  ['onResponseStarted', 'onRedirectReceived', 'onSucceeded', 'onFailed', 'onCanceled'].forEach(method => {
    hook(context, name, method, (_self, args) => {
      const requestKey = identity(args[0]);
      const state = cronetRequests.get(requestKey) || {};
      const info = args[1];
      emitPartialHttpTransaction(Object.assign({}, state, meta('cronet', name, method), {
        url: read(() => safeToString(info.getUrl()), state.url),
        response_status: read(() => info.getHttpStatusCode()),
        response_headers: read(() => mapToObject(info.getAllHeaders())),
      }));
      if (['onSucceeded', 'onFailed', 'onCanceled'].includes(method)) cronetRequests.delete(requestKey);
    });
  });
}
function installCronetBuilder(context, name) {
  hook(context, name, 'setHttpMethod', null, (self, args) => {
    const state = cronetBuilders.get(identity(self));
    if (state) state.method = safeToString(args[0]);
  });
  hook(context, name, 'addHeader', null, (self, args) => {
    const state = cronetBuilders.get(identity(self));
    if (state) state.request_headers[safeToString(args[0]).toLowerCase()] = safeToString(args[1]);
  });
  hook(context, name, 'build', null, (self, _args, request) => {
    const key = identity(self);
    const state = cronetBuilders.get(key);
    if (!state) return;
    boundedSet(cronetRequests, identity(request), Object.assign({}, state));
    const target = instanceTarget(request, context);
    hook(target.context, target.name, 'start', self => {
      emitPartialHttpTransaction(Object.assign({}, cronetRequests.get(identity(self)), meta('cronet', target.name, 'start')));
    });
  }, noArgs);
}
function installCronetEngine(context, name) {
  hook(context, name, 'newUrlRequestBuilder', (_self, args) => {
    if (args[1]) {
      const target = instanceTarget(args[1], context);
      installCronetCallback(target.context, target.name);
    }
  }, (_self, args, builder) => {
    boundedSet(cronetBuilders, identity(builder), { url: safeToString(args[0]), method: null, request_headers: {} });
    const target = instanceTarget(builder, context);
    installCronetBuilder(target.context, target.name);
  }, types => types.length === 3 && types[0].className === 'java.lang.String');
}
function installCronetHooks(context) {
  ['org.chromium.net.CronetEngine$Builder', 'org.chromium.net.ExperimentalCronetEngine$Builder',
    'org.chromium.net.impl.NativeCronetEngineBuilderImpl', 'org.chromium.net.impl.JavaCronetEngineBuilderImpl']
    .forEach(name => hook(context, name, 'build', null, (_self, _args, engine) => {
      const target = instanceTarget(engine, context);
      installCronetEngine(target.context, target.name);
    }, noArgs));
  ['org.chromium.net.CronetEngine', 'org.chromium.net.ExperimentalCronetEngine',
    'org.chromium.net.impl.CronetUrlRequestContext', 'org.chromium.net.impl.JavaCronetEngine']
    .forEach(name => installCronetEngine(context, name));
  installCronetBuilder(context, 'org.chromium.net.impl.UrlRequestBuilderImpl');
}

let networkAttempt = 0;
function installNetworkHooks() {
  networkAttempt++;
  const contexts = [defaultContext];
  const seenLoaders = new Set();
  const names = read(() => Java.enumerateLoadedClassesSync(), []);
  const install = context => {
    [installOkHttpHooks, installHttpURLConnectionHooks, installWebViewHooks, installCronetHooks]
      .forEach(fn => observe(() => fn(context)));
    // Resolve concrete vendor classes in their owning factory, without changing the default loader.
    names.filter(name => /(?:HttpURLConnection|HttpsURLConnection|Cronet.*(?:Engine|Context))/.test(name))
      .slice(0, 256).forEach(name => observe(() => {
        if (/URLConnection/.test(name)) installConnection(context, name);
        else installCronetEngine(context, name);
      }));
  };
  install(defaultContext);
  read(() => Java.enumerateClassLoaders({
    onMatch(loader) {
      if (contexts.length >= 33) return;
      const id = identity(loader);
      if (seenLoaders.has(id)) return;
      seenLoaders.add(id);
      read(() => {
        const context = { factory: Java.ClassFactory.get(loader), id };
        contexts.push(context);
        install(context);
      });
    },
    onComplete() {},
  }));
  sendState('network_install_attempt', { attempt: networkAttempt, installed_methods: installedMethods.size, loaders: contexts.length });
  if (networkAttempt < 8) {
    setTimeout(() => {
      try { Java.perform(installNetworkHooks); }
      catch (error) { sendState('http_hook_error', { error: safeToString(error) }); }
    }, Math.min(1000 * Math.pow(2, networkAttempt - 1), 8000));
  } else {
    sendState('network_install_complete', { attempts: networkAttempt, installed_methods: installedMethods.size, coverage: 'bounded; classes loaded after retry window may be missed' });
  }
}

let hooksInstalled = false;
function installHooks() {
  if (hooksInstalled) return;
  hooksInstalled = true;
  sendState('script_loaded', { rule_count: rules.length });
  installNetworkHooks();

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

          const handlerKey = methodKey(defaultContext, rule.class_name, rule.method_name, overload);
          const previousImplementation = methodHandlers.get(handlerKey);
          const handler = function () {
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

            const callArgs = Array.prototype.slice.call(arguments);
            const retval = previousImplementation
              ? previousImplementation.apply(this, callArgs)
              : overload.call.apply(overload, [this].concat(callArgs));
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
          overload.implementation = handler;
          methodHandlers.set(handlerKey, handler);
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

let javaReady = false;
let initChecks = 0;
function watchJavaInitialization() {
  if (javaReady) return;
  initChecks++;
  sendState('java_init_pending', { check: initChecks, java_available: read(() => Boolean(Java.available)) });
  if (initChecks < 8) setTimeout(watchJavaInitialization, 2000);
  else sendState('java_init_timeout', { checks: initChecks, java_available: read(() => Boolean(Java.available)), coverage: 'Java hooks pending; no Java capture confirmed' });
}
function startJavaHooks() {
  // This watchdog runs outside perform: its callback can remain deferred indefinitely.
  setTimeout(watchJavaInitialization, 2000);
  try {
    Java.perform(function () {
      if (javaReady) return;
      javaReady = true;
      sendState('java_ready');
      installHooks();
    });
  } catch (error) {
    sendState('java_bridge_error', { error: safeToString(error) });
  }
}

setImmediate(startJavaHooks);
