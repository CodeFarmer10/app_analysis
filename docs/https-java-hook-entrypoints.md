# Java HTTP Hook 公开入口与边界

当前代码覆盖主流 Java 请求路径，不承诺所有库、版本、混淆、自定义实现及进程。

| 网络栈 | 直接观测的常用入口 | 仅定位/传递配置，不直接产生日志 |
| --- | --- | --- |
| OkHttp 3/4 | Call.execute、Call.enqueue、Callback.onResponse | OkHttpClient.newCall 获取实际 Call 类 |
| HttpURLConnection / HTTPS | connect、getInputStream、getOutputStream、getResponseCode | URL.openConnection 获取实际连接类 |
| WebView | loadUrl、postUrl、WebViewClient.shouldInterceptRequest/onLoadResource、ServiceWorkerClient.shouldInterceptRequest | setWebViewClient、ServiceWorkerController.getInstance/setServiceWorkerClient 定位实际回调类 |
| Cronet | UrlRequest.start、onResponseStarted/onRedirectReceived/onSucceeded/onFailed/onCanceled | Engine/Request Builder 工厂、setHttpMethod/addHeader、build 获取真实对象并传递配置 |

已删除 OkHttp Response.Builder.build Hook：这是响应对象内部构造细节，可能一请求触发多次，常用程序通常通过 execute 返回值或 onResponse 接收响应。

`com.android.okhttp.internal...`、`okhttp3.internal.connection.RealCall` 等具体类名仍保留：Hook 的是这些类上实现的公开 API。仅拦截抽象接口不保证能截获实现类重写的方法，不能因包名含 internal 就删除。

openConnection/newCall/Builder.build 不再作为请求发生的直接日志证据；实际执行失败时，请求入口观测仍可保留为 partial。enqueue/start 代表执行尝试或调度，并不保证已经发送网络包。一个请求仍可能有请求和响应等多阶段观测，未实现严格同源事务归并。

覆盖边界：不读取所有 Java 流的完整内容；不是全部重定向中间跳转的逐包审计；Cronet BidirectionalStream、自定义 Call.Factory/混淆入口、WebView 非标准引擎及其他进程可能需要额外适配。URLConnection 只走头部等特殊入口的覆盖依赖实际实现是否经过上述公共方法。此次精简没有增加内部协议/Socket Hook。

不额外 Hook Retrofit：通常复用 OkHttp 执行路径。静态资源继续仅记录元数据。

代码和 bundle 同步更新；生产部署与真机覆盖验证仍待执行。

回归验证：4 个精简用例先失败，精简后通过；独立审查又复现 Frida implementation getter 返回 NativeCallback 的兼容问题，现通过按方法身份保存 JS handler 组合通用规则与网络 Hook。2 个桥接语义用例先失败再通过。最终 Java 行为测试 38 项、后端 unittest 320 项通过，bundle 已重建并通过语法检查。
