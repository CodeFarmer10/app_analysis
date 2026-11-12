const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../phone_agent/frida/agent_src/index.js'), 'utf8').replace(/^import Java from 'frida-java-bridge';\s*/, '');
function method(types, fn = () => undefined) {
  const overload = { argumentTypes: types.map(className => ({ className })), call(self, ...args) { return fn.apply(self, args); } };
  return { overloads: [overload] };
}
const bridgeHandlers = new WeakMap();
function nativeImplementationGetter(cls, name) {
  for (const overload of cls[name].overloads) Object.defineProperty(overload, 'implementation', {
    get() { return bridgeHandlers.has(overload) ? { nativeCallback: true } : null; },
    set(fn) { bridgeHandlers.set(overload, fn); },
  });
}
function invoke(cls, name, self, ...args) {
  if (name === 'execute' && cls.request && !self.request) self = Object.assign({}, self, { request: cls.request });
  const o = cls[name].overloads.find(o => o.argumentTypes.length === args.length);
  return (bridgeHandlers.get(o) || o.implementation || function (...a) { return o.call(this, ...a); }).apply(self, args);
}
function runtime(classes = {}, loaders = [], rules = []) {
  const messages = [], timers = [];
  const use = name => { if (!classes[name]) throw Error('ClassNotFoundException: ' + name); return classes[name]; };
  const Java = { use, cast: value => value, perform: fn => fn(), enumerateLoadedClassesSync: () => Object.keys(classes),
    enumerateClassLoaders: ({ onMatch, onComplete }) => { loaders.forEach(onMatch); onComplete(); },
    ClassFactory: { get: loader => loader.factory } };
  vm.runInNewContext(source, { Java, __frida_rules__: rules, send: msg => messages.push(JSON.parse(JSON.stringify(msg))), setImmediate: fn => fn(), setTimeout: fn => timers.push(fn), console });
  return { messages, timers, classes, http: () => messages.filter(m => m.type === 'http_transaction').map(m => m.payload), tick() { const batch = timers.splice(0); batch.forEach(fn => fn()); } };
}
const headers = entries => ({ size: () => entries.length, name: i => entries[i][0], value: i => entries[i][1] });
function request(body = null, url = 'https://example.test/api') { return { url: () => url, method: () => 'POST', headers: () => headers([['X-Test', 'yes']]), body: () => body }; }
function response(req, peek = () => ({ string: () => 'copied response' })) { return { request: () => req, headers: () => headers([['Content-Type', 'application/json']]), code: () => 201, peekBody: peek }; }
function callRuntime(resp) { const cls = { execute: method([], () => resp), request: () => resp.request() }; return { cls, r: runtime({ 'okhttp3.RealCall': cls }) }; }
function bufferedBody(text, declaredLength = Buffer.byteLength(text)) {
  const bytes = Buffer.from(text);
  const source = { size: () => bytes.length, copyTo(copy, offset, count) { copy.bytes = bytes.subarray(offset, offset + count); return source; } };
  return { contentLength: () => declaredLength, source: () => ({ buffer: () => source, request() { throw Error('upstream read'); } }) };
}
const bufferClass = { $new: () => ({ bytes: Buffer.alloc(0), readUtf8() { return this.bytes.toString('utf8'); } }) };
test('generic over network composes JS handlers when bridge getters return NativeCallback', () => {
  const cls = { getResponseCode: method([], () => 201) }; nativeImplementationGetter(cls, 'getResponseCode');
  const r = runtime({ 'java.net.HttpURLConnection': cls }, [], [{ id: 'code', class_name: 'java.net.HttpURLConnection', method_name: 'getResponseCode', arg_count: 0 }]);
  assert.equal(invoke(cls, 'getResponseCode', { getURL: () => 'https://example.test/bridge', getRequestMethod: () => 'GET' }), 201);
  assert.equal(r.messages.filter(m => m.type === 'event').length, 1); assert.equal(r.http()[0].url, 'https://example.test/bridge');
});
test('late network over generic composes JS handlers with NativeCallback getters', () => {
  const cb = { getClass: () => ({ getName: () => 'app.BridgeCallback', getClassLoader: () => null }) };
  const callbacks = { onResponse: method(['okhttp3.Call', 'okhttp3.Response'], () => 29) }; nativeImplementationGetter(callbacks, 'onResponse');
  const calls = { enqueue: method(['okhttp3.Callback']) };
  const r = runtime({ 'okhttp3.RealCall': calls, 'app.BridgeCallback': callbacks }, [], [{ id: 'cb', class_name: 'app.BridgeCallback', method_name: 'onResponse', arg_count: 2 }]);
  invoke(calls, 'enqueue', { request: () => request() }, cb);
  assert.equal(invoke(callbacks, 'onResponse', cb, {}, response(request())), 29);
  assert.equal(r.messages.filter(m => m.type === 'event').length, 1); assert.ok(r.http().some(x => x.response_status === 201));
});
test('internal response builders are not hooked or recorded', () => {
  const cls = { build: method([], () => response(request())) };
  const r = runtime({ 'okhttp3.Response$Builder': cls });
  assert.equal(cls.build.overloads[0].implementation, undefined);
  invoke(cls, 'build', {}); assert.equal(r.http().length, 0);
});
test('OkHttp factory installs concrete execution hooks without logging construction', () => {
  const req = request();
  const call = { request: () => req, getClass: () => ({ getName: () => 'app.CustomCall', getClassLoader: () => null }) };
  const factory = { newCall: method(['okhttp3.Request'], () => call) };
  const concrete = { execute: method([], () => response(req)) };
  const r = runtime({ 'okhttp3.OkHttpClient': factory, 'app.CustomCall': concrete });
  assert.equal(invoke(factory, 'newCall', {}, req), call); assert.equal(r.http().length, 0);
  invoke(concrete, 'execute', call); assert.equal(r.http()[0].hook_method, 'execute');
});
test('URLConnection factory does not record a configured but unused connection', () => {
  const connection = { getClass: () => ({ getName: () => 'vendor.Connection', getClassLoader: () => null }), getURL: () => 'https://example.test/unused' };
  const factory = { openConnection: method([], () => connection) };
  const r = runtime({ 'java.net.URL': factory, 'vendor.Connection': { connect: method([]) } });
  assert.equal(invoke(factory, 'openConnection', {}), connection); assert.equal(r.http().length, 0);
});
test('Cronet construction stays silent until start and keeps method and headers', () => {
  const nativeClass = name => ({ getName: () => name, getClassLoader: () => null });
  const builder = { getClass: () => nativeClass('app.RequestBuilder') };
  const req = { getClass: () => nativeClass('app.UrlRequest') };
  const engine = { newUrlRequestBuilder: method(['java.lang.String', 'org.chromium.net.UrlRequest$Callback', 'java.util.concurrent.Executor'], () => builder) };
  const build = { setHttpMethod: method(['java.lang.String']), addHeader: method(['java.lang.String', 'java.lang.String']), build: method([], () => req) };
  const concrete = { start: method([]) };
  const r = runtime({ 'org.chromium.net.CronetEngine': engine, 'app.RequestBuilder': build, 'app.UrlRequest': concrete });
  invoke(engine, 'newUrlRequestBuilder', {}, 'https://example.test/cronet', null, {});
  invoke(build, 'setHttpMethod', builder, 'PATCH'); invoke(build, 'addHeader', builder, 'X-Test', 'yes');
  invoke(build, 'build', builder); assert.equal(r.http().length, 0);
  invoke(concrete, 'start', req); assert.equal(r.http().length, 1); assert.equal(r.http()[0].method, 'PATCH');
  assert.equal(JSON.parse(r.http()[0].request_headers_json)['x-test'], 'yes');
});
test('unknown custom request body methods are not executed during observation', () => {
  let probes = 0;
  const body = { getClass: () => ({ getName: () => 'app.CustomBody', getClassLoader: () => null }),
    isOneShot() { probes++; return false; }, isDuplex() { probes++; return false; }, contentLength() { probes++; return 7; } };
  const { cls, r } = callRuntime(response(request(body)));
  invoke(cls, 'execute', {}); assert.equal(probes, 0); assert.equal(r.http()[0].url, 'https://example.test/api');
});
test('unknown stream observes metadata first and reads only buffered bytes', () => {
  let peeks = 0, reads = 0;
  const resp = response(request(), () => { peeks++; return { string: () => 'wrong upstream' }; });
  const cls = { execute: method([], () => resp), request: () => resp.request() };
  const r = runtime({ 'okhttp3.RealCall': cls, 'okio.Buffer': bufferClass });
  resp.headers = () => headers([['Content-Type', 'application/x-ndjson']]);
  resp.body = () => { reads++; assert.equal(r.http()[0].url, 'https://example.test/api'); return bufferedBody('available', -1); };
  assert.equal(invoke(cls, 'execute', {}), resp);
  assert.equal(peeks, 0); assert.ok(reads > 0);
  assert.equal(r.http().at(-1).response_body_preview, 'available'); assert.equal(r.http().at(-1).is_complete, false);
});
test('late callback hook composes generic rules instead of overwriting them', () => {
  const callback = { getClass: () => ({ getName: () => 'app.GenericCallback', getClassLoader: () => null }) };
  const callbacks = { onResponse: method(['okhttp3.Call', 'okhttp3.Response'], () => 19) };
  const calls = { enqueue: method(['okhttp3.Callback']) };
  const r = runtime({ 'okhttp3.RealCall': calls, 'app.GenericCallback': callbacks }, [], [{ id: 'cb', class_name: 'app.GenericCallback', method_name: 'onResponse', arg_count: 2 }]);
  invoke(calls, 'enqueue', { request: () => request() }, callback);
  for (let i = 0; i < 2; i++) assert.equal(invoke(callbacks, 'onResponse', callback, {}, response(request())), 19);
  assert.equal(r.messages.filter(m => m.type === 'event').length, 2);
});
test('generic rule on an existing network hook preserves both observations', () => {
  const cls = { getResponseCode: method([], () => 201) };
  const r = runtime({ 'java.net.HttpURLConnection': cls }, [], [{ id: 'call', class_name: 'java.net.HttpURLConnection', method_name: 'getResponseCode', arg_count: 0 }]);
  assert.equal(invoke(cls, 'getResponseCode', { getURL: () => 'https://example.test/api', getRequestMethod: () => 'POST' }), 201);
  assert.equal(r.messages.filter(m => m.type === 'event').length, 1); assert.equal(r.http()[0]?.url, 'https://example.test/api');
});
test('body failure preserves response metadata and original return', () => {
  const resp = response(request()); resp.body = () => { throw Error('closed'); }; const { cls, r } = callRuntime(resp);
  assert.equal(invoke(cls, 'execute', {}), resp); assert.equal(r.http().at(-1)?.url, 'https://example.test/api'); assert.equal(r.http().at(-1).response_status, 201); assert.equal(r.http().at(-1).response_body_preview, null);
});
test('response preview copies at most 64KiB of already buffered data', () => {
  const resp = response(request(), () => { throw Error('must not peek'); });
  resp.body = () => bufferedBody('a'.repeat(65537));
  const cls = { execute: method([], () => resp), request: () => resp.request() };
  const r = runtime({ 'okhttp3.RealCall': cls, 'okio.Buffer': bufferClass });
  invoke(cls, 'execute', {});
  assert.equal(r.http().at(-1).response_body_preview.length, 65536); assert.equal(r.http().at(-1).is_complete, false);
});
test('fully buffered small response is complete and the original buffer stays intact', () => {
  const body = bufferedBody('copied response'); const resp = response(request()); resp.body = () => body;
  const cls = { execute: method([], () => resp), request: () => resp.request() };
  const r = runtime({ 'okhttp3.RealCall': cls, 'okio.Buffer': bufferClass });
  invoke(cls, 'execute', {});
  assert.equal(r.http().at(-1).response_body_preview, 'copied response'); assert.equal(r.http().at(-1).is_complete, true);
  assert.equal(body.source().buffer().size(), Buffer.byteLength('copied response'));
});
for (const kind of ['one-shot', 'duplex', 'unknown', 'large', 'static']) test('never replays ' + kind + ' request bodies', () => {
  let writes = 0; const body = { isOneShot: () => kind === 'one-shot', isDuplex: () => kind === 'duplex', contentLength: () => kind === 'unknown' ? -1 : kind === 'large' ? 999999 : 4, writeTo() { writes++; } };
  const resp = response(request(body, kind === 'static' ? 'https://example.test/p.png' : undefined));
  if (kind === 'static') resp.headers = () => headers([['Content-Type', 'image/png']]);
  const cls = { execute: method([], () => resp), request: () => resp.request() }; const r = runtime({ 'okhttp3.RealCall': cls, 'okio.Buffer': { $new: () => ({ readUtf8: () => 'body' }) } });
  invoke(cls, 'execute', {}); assert.equal(writes, 0); assert.equal(r.http()[0].request_body_preview, null);
});
test('failed call construction preserves exception identity without inventing a transfer', () => {
  const failure = Error('offline'); const cls = { newCall: method(['okhttp3.Request'], () => { throw failure; }) }; const r = runtime({ 'okhttp3.OkHttpClient': cls });
  assert.throws(() => invoke(cls, 'newCall', {}, request()), e => e === failure);
  assert.equal(r.http().length, 0);
});
test('concrete URLConnection observes connect failure and overridden response code', () => {
  const failure = Error('connect failed'); const cls = { connect: method([], () => { throw failure; }), getResponseCode: method([], () => 204) };
  const r = runtime({ 'com.android.okhttp.internal.huc.HttpURLConnectionImpl': cls });
  const conn = { getURL: () => 'https://example.test/conn', getRequestMethod: () => 'PATCH' };
  assert.throws(() => invoke(cls, 'connect', conn), e => e === failure); assert.equal(r.http()[0]?.method, 'PATCH');
  assert.equal(invoke(cls, 'getResponseCode', conn), 204); assert.equal(r.http().at(-1).response_status, 204);
});
test('WebView actual client override reports subresources with unknown legacy method', () => {
  const clientClass = { onLoadResource: method(['android.webkit.WebView', 'java.lang.String'], () => 17), shouldInterceptRequest: method(['android.webkit.WebView', 'android.webkit.WebResourceRequest'], () => null) };
  const cls = { setWebViewClient: method(['android.webkit.WebViewClient']) }; const r = runtime({ 'android.webkit.WebView': cls, 'app.ActualClient': clientClass });
  const client = { getClass: () => ({ getName: () => 'app.ActualClient', getClassLoader: () => null }) };
  invoke(cls, 'setWebViewClient', {}, client); assert.equal(invoke(clientClass, 'onLoadResource', client, {}, 'https://example.test/resource'), 17);
  const p = r.http().at(-1); assert.equal(p?.url, 'https://example.test/resource'); assert.equal(p.method, null); assert.equal(p.response_body_preview, null);
  invoke(clientClass, 'shouldInterceptRequest', client, {}, { getUrl: () => 'https://example.test/intercept', getMethod: () => 'HEAD', getRequestHeaders: () => null });
  assert.equal(r.http().at(-1).method, 'HEAD');
});
test('Cronet concrete engine tracks builder method and actual callback response without streams', () => {
  const req = { getClass: () => ({ getName: () => 'app.Request', getClassLoader: () => null }) };
  const builder = { getClass: () => ({ getName: () => 'org.chromium.net.impl.UrlRequestBuilderImpl', getClassLoader: () => null }) };
  const builderClass = { setHttpMethod: method(['java.lang.String']), addHeader: method(['java.lang.String', 'java.lang.String']), build: method([], () => req) };
  const callbackClass = { onResponseStarted: method(['org.chromium.net.UrlRequest', 'org.chromium.net.UrlResponseInfo'], () => 19) };
  const engine = { newUrlRequestBuilder: method(['java.lang.String', 'org.chromium.net.UrlRequest$Callback', 'java.util.concurrent.Executor'], () => builder) };
  const requestClass = { start: method([]) };
  const r = runtime({ 'org.chromium.net.impl.CronetUrlRequestContext': engine, 'org.chromium.net.impl.UrlRequestBuilderImpl': builderClass, 'app.Callback': callbackClass, 'app.Request': requestClass });
  const cb = { getClass: () => ({ getName: () => 'app.Callback', getClassLoader: () => null }) };
  invoke(engine, 'newUrlRequestBuilder', {}, 'https://example.test/cronet', cb, {});
  invoke(builderClass, 'setHttpMethod', builder, 'PUT'); invoke(builderClass, 'build', builder);
  assert.equal(r.http().length, 0); invoke(requestClass, 'start', req);
  assert.equal(r.http().at(-1)?.method, 'PUT');
  const info = { getUrl: () => 'https://example.test/redirected', getHttpStatusCode: () => 202, getAllHeaders: () => null };
  assert.equal(invoke(callbackClass, 'onResponseStarted', cb, req, info), 19);
  assert.equal(r.http().at(-1).url, 'https://example.test/redirected'); assert.equal(r.http().at(-1).response_status, 202); assert.equal(r.http().at(-1).response_body_preview, null);
});
test('late class installation is idempotent and retry ends with diagnostics', () => {
  const r = runtime(); const cls = { execute: method([], () => response(request())) }; r.classes['okhttp3.RealCall'] = cls;
  r.tick(); invoke(cls, 'execute', { request: () => request() }); assert.ok(r.http().length > 0);
  const impl = cls.execute.overloads[0].implementation; for (let i = 0; i < 30; i++) r.tick();
  assert.equal(cls.execute.overloads[0].implementation, impl); assert.equal(r.timers.length, 0);
  assert.ok(r.messages.some(m => m.status === 'network_install_complete'));
});
test('nondefault loader receives hooks when default loader cannot resolve class', () => {
  const cls = { execute: method([], () => response(request())) };
  const loader = { toString: () => 'isolated', factory: { use(name) { if (name === 'okhttp3.RealCall') return cls; throw Error('ClassNotFoundException'); } } };
  const r = runtime({}, [loader]); invoke(cls, 'execute', { request: () => request() }); assert.equal(r.http()[0]?.hook_library, 'okhttp3/4');
});
test('OkHttp callback metadata survives application callback failure', () => {
  const failure = Error('app callback');
  const cbClass = { onResponse: method(['okhttp3.Call', 'okhttp3.Response'], () => { throw failure; }) };
  const callClass = { enqueue: method(['okhttp3.Callback']) };
  const r = runtime({ 'okhttp3.RealCall': callClass, 'app.OkCallback': cbClass });
  const cb = { getClass: () => ({ getName: () => 'app.OkCallback', getClassLoader: () => null }) };
  invoke(callClass, 'enqueue', { request: () => request() }, cb);
  assert.throws(() => invoke(cbClass, 'onResponse', cb, {}, response(request())), e => e === failure);
  assert.equal(r.http().at(-1).response_status, 201);
});
test('Cronet engine builder installs a custom concrete engine', () => {
  const engine = { getClass: () => ({ getName: () => 'app.CustomEngine', getClassLoader: () => null }) };
  const cls = { build: method([], () => engine) };
  const engineClass = { newUrlRequestBuilder: method(['java.lang.String', 'org.chromium.net.UrlRequest$Callback', 'java.util.concurrent.Executor'], () => null) };
  const r = runtime({ 'org.chromium.net.CronetEngine$Builder': cls, 'app.CustomEngine': engineClass });
  assert.equal(invoke(cls, 'build', {}), engine);
  invoke(engineClass, 'newUrlRequestBuilder', engine, 'https://example.test/custom', null, {});
  assert.equal(typeof engineClass.newUrlRequestBuilder.overloads[0].implementation, 'function');
  assert.equal(r.http().length, 0);
});
test('service worker concrete controller installs actual callback override', () => {
  const controller = { getClass: () => ({ getName: () => 'app.Controller', getClassLoader: () => null }) };
  const ctrlClass = { setServiceWorkerClient: method(['android.webkit.ServiceWorkerClient']) };
  const clientClass = { shouldInterceptRequest: method(['android.webkit.WebResourceRequest'], () => 5) };
  const api = { getInstance: method([], () => controller) };
  const r = runtime({ 'android.webkit.ServiceWorkerController': api, 'app.Controller': ctrlClass, 'app.SWClient': clientClass });
  invoke(api, 'getInstance', {});
  const client = { getClass: () => ({ getName: () => 'app.SWClient', getClassLoader: () => null }) };
  invoke(ctrlClass, 'setServiceWorkerClient', controller, client);
  assert.equal(invoke(clientClass, 'shouldInterceptRequest', client, { getUrl: () => 'https://example.test/sw', getMethod: () => 'OPTIONS' }), 5);
  assert.equal(r.http().at(-1)?.method, 'OPTIONS'); assert.equal(r.http().at(-1).response_body_preview, null);
});
test('copy string/close and header exceptions preserve URL and original return', () => {
  const resp = response(request(), () => ({ string() { throw Error('encoding'); }, close() { throw Error('close'); } }));
  resp.headers = () => { throw Error('headers'); };
  const { cls, r } = callRuntime(resp); assert.equal(invoke(cls, 'execute', {}), resp);
  assert.equal(r.http()[0]?.url, 'https://example.test/api'); assert.equal(r.http()[0].response_body_preview, null);
});
test('static response never peeks and original response stream is never read', () => {
  const resp = response(request(null, 'https://example.test/a.png'), () => { throw Error('must not peek'); });
  let peeks = 0; resp.headers = () => headers([['Content-Type', 'image/png']]); resp.peekBody = () => { peeks++; };
  resp.body = () => { throw Error('must not read original'); };
  const { cls, r } = callRuntime(resp); invoke(cls, 'execute', {});
  assert.equal(peeks, 0); assert.equal(r.http()[0].response_body_preview, null);
});
test('URLConnection concrete instance from URL factory is hooked even with arbitrary class name', () => {
  const connection = { getClass: () => ({ getName: () => 'vendor.Connection', getClassLoader: () => null }), getURL: () => 'https://example.test/vendor', getRequestMethod: () => 'DELETE' };
  const urlClass = { openConnection: method([], () => connection) };
  const concrete = { getInputStream: method([], () => 7) };
  const r = runtime({ 'java.net.URL': urlClass, 'vendor.Connection': concrete });
  assert.equal(invoke(urlClass, 'openConnection', {}), connection); assert.equal(invoke(concrete, 'getInputStream', connection), 7);
  assert.equal(r.http().at(-1)?.method, 'DELETE'); assert.equal(r.http().at(-1).hook_class, 'vendor.Connection');
});
test('WebView POST only decodes bounded nonstatic byte arrays', () => {
  const cls = { postUrl: method(['java.lang.String', '[B'], () => 3) };
  let decodes = 0;
  const r = runtime({ 'android.webkit.WebView': cls, 'java.lang.String': { $new: () => { decodes++; return 'data'; } } });
  for (const [url, size] of [['https://example.test/a', 65537], ['https://example.test/a.png', 4]]) invoke(cls, 'postUrl', {}, url, { length: size });
  assert.equal(decodes, 0); assert.equal(r.http()[0].request_body_preview, null);
  assert.equal(invoke(cls, 'postUrl', {}, 'https://example.test/api', { length: 4 }), 3);
  assert.equal(r.http().at(-1).request_body_preview, 'data');
});

test('passively captures small built-in JSON RequestBody without replay', () => {
  const body = {
    getClass: () => ({ getName: () => 'okhttp3.RequestBody$Companion$toRequestBody$2', getClassLoader: () => null }),
    isOneShot: () => false, isDuplex: () => false, contentLength: () => 7,
    '_$this_toRequestBody': { value: [123, 34, 120, 34, 58, 49, 125] }, '_$offset': { value: 0 }, '_$byteCount': { value: 7 },
    writeTo() { throw Error('must never replay'); },
  };
  const resp = response(request(body)); const cls = { execute: method([], () => resp), request: () => resp.request() };
  const r = runtime({ 'okhttp3.RealCall': cls, 'okhttp3.RequestBody$Companion$toRequestBody$2': {}, 'java.lang.String': { $new: (bytes, offset, count) => Buffer.from(bytes).subarray(offset, offset + count).toString('utf8') } });
  invoke(cls, 'execute', {}); assert.equal(r.http()[0].request_body_preview, '{"x":1}');
});
for (const contentType of ['text/event-stream', 'application/grpc', 'application/grpc+proto']) test('skips streaming response ' + contentType, () => {
  let peeks = 0; const resp = response(request(), () => { peeks++; throw Error('stream blocks'); });
  resp.headers = () => headers([['Content-Type', contentType]]);
  const { cls, r } = callRuntime(resp); invoke(cls, 'execute', {});
  assert.equal(peeks, 0); assert.equal(r.http()[0].url, 'https://example.test/api'); assert.equal(r.http()[0].is_complete, false);
});
test('failed and possibly truncated previews are marked partial', () => {
  for (const body of [() => { throw Error('closed'); }, () => bufferedBody('a'.repeat(65537))]) {
    const resp = response(request()); resp.body = body; const cls = { execute: method([], () => resp), request: () => resp.request() };
    const r = runtime({ 'okhttp3.RealCall': cls, 'okio.Buffer': bufferClass }); invoke(cls, 'execute', {});
    assert.equal(r.http().at(-1).parse_status, 'partial'); assert.equal(r.http().at(-1).is_complete, false);
  }
});
test('network retries preserve generic rule implementation and one event per call', () => {
  const cls = { record: method(['java.lang.String'], value => value + '!') };
  const r = runtime({ 'app.Generic': cls }, [], [{ id: 9, class_name: 'app.Generic', method_name: 'record', arg_count: 1, stringify_args: true, include_retval: true, stringify_retval: true }]);
  const impl = cls.record.overloads[0].implementation;
  for (let i = 0; i < 10; i++) r.tick();
  assert.equal(cls.record.overloads[0].implementation, impl); assert.equal(invoke(cls, 'record', {}, 'keep'), 'keep!');
  const events = r.messages.filter(m => m.type === 'event'); assert.equal(events.length, 1); assert.equal(events[0].payload.args, 'keep'); assert.equal(events[0].payload.retval, 'keep!');
});
test('deferred Java initialization reports pending without claiming installed', () => {
  const messages = [], timers = [];
  vm.runInNewContext(source, { Java: { available: false, perform() {} }, send: m => messages.push(m), setImmediate: fn => fn(), setTimeout: fn => timers.push(fn) });
  for (let i = 0; i < 20 && timers.length; i++) timers.shift()();
  assert.ok(messages.some(m => m.status === 'java_init_pending' && m.java_available === false));
  assert.ok(messages.some(m => m.status === 'java_init_timeout'));
  assert.ok(!messages.some(m => ['java_ready', 'network_hooked'].includes(m.status)));
  assert.equal(timers.length, 0);
});
