# 外部对接：分析任务提交与结果查询

本文档依据当前后端实现编写。示例域名 `https://api.example.com` 请替换为实际部署地址。三个接口均无需 Bearer Token；如提交时携带有效 Bearer Token，任务会归属该用户。匿名提交的任务可凭 `task_id` 使用本文的结果接口查询。

## 对接流程

1. 上传 APK 或提交 APK 下载 URL，从成功条目中保存 `task_id`。
2. 按 `task_id` 调用结果接口，建议每约 5 秒轮询一次。
3. `status=completed` 时读取 `result`；出现 `download_failed`、`static_failed` 或 `dynamic_failed` 时停止轮询。

所有成功的 HTTP 请求均返回 `200`，响应外层格式为 `{"code":0,"message":"ok","data":...}`。批量提交时，HTTP 200 不代表每个条目都成功，须检查 `data.items[].success`。

## 1. 上传 APK

`POST /api/tasks/upload`，请求类型为 `multipart/form-data`。每个文件独立创建任务，同一批次中 MD5 相同的文件只处理第一份。

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `files` | 文件，可重复 | 是 | 一个或多个 APK；多个文件重复使用字段名 `files`。单文件上限 `500 × 1024 × 1024` 字节。 |
| `task_description` | 字符串 | 否 | 任务描述，默认空；服务端最多保留 255 个字符。 |
| `priority` | 整数 | 否 | 1～1000000，默认 1；数值越小优先级越高。 |

```bash
curl -X POST 'https://api.example.com/api/tasks/upload' \
  -F 'files=@/path/to/first.apk' \
  -F 'files=@/path/to/second.apk' \
  -F 'task_description=外部送检' \
  -F 'priority=1'
```

响应示例：

```json
{
  "code": 0,
  "message": "ok",
  "data": {
    "batch_id": "11111111-1111-4111-8111-111111111111",
    "items": [
      {
        "filename": "first.apk",
        "success": true,
        "task_id": "22222222-2222-4222-8222-222222222222",
        "md5": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "file_size": 12345,
        "status": "static_analyzing"
      },
      {
        "filename": "second.apk",
        "success": false,
        "reason": "文件不是APK，检测到MIME类型: text/plain"
      }
    ],
    "total": 2
  }
}
```

`batch_id` 标识提交批次；`total` 是条目数，不是成功数。请从 `success: true` 的 `items[].task_id` 提取任务 ID。失败条目不保证有 `task_id`。

## 2. 通过下载 URL 提交 APK

`POST /api/tasks/url`，请求类型为 `application/json`。每个 URL 独立创建任务；URL 必须是包含主机名的 HTTP/HTTPS 地址，同一批次中的重复 URL 会被忽略。

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `urls` | 字符串数组 | 是 | 1～100 条 APK 下载 URL。 |
| `task_description` | 字符串 | 否 | 任务描述，最多 255 个字符，默认空。 |
| `priority` | 整数 | 否 | 1～1000000，默认 1；数值越小优先级越高。 |

```bash
curl -X POST 'https://api.example.com/api/tasks/url' \
  -H 'Content-Type: application/json' \
  -d '{"urls":["https://files.example.com/first.apk"],"task_description":"外部送检","priority":1}'
```

响应示例：

```json
{
  "code": 0,
  "message": "ok",
  "data": {
    "batch_id": "11111111-1111-4111-8111-111111111111",
    "items": [
      {
        "url": "https://files.example.com/first.apk",
        "success": true,
        "task_id": "22222222-2222-4222-8222-222222222222",
        "status": "downloading"
      }
    ],
    "total": 1
  }
}
```

URL 与任务 ID 的对应关系以 `items[]` 为准；从 `success: true` 的 `items[].task_id` 提取任务 ID。下载投递失败的条目可能含 `task_id` 和 `status: "download_failed"`，但 `success` 为 `false`。

## 3. 查询分析结果

`GET /api/tasks/{task_id}/result`。路径中的 `task_id` 取自提交响应；无需请求体和 Bearer Token。

```bash
curl 'https://api.example.com/api/tasks/22222222-2222-4222-8222-222222222222/result'
```

分析未完成时：

```json
{"code":0,"message":"ok","data":{"status":"static_analyzing","result":null}}
```

分析完成时：

```json
{
  "code": 0,
  "message": "ok",
  "data": {
    "status": "completed",
    "result": {
      "appName": "示例APP",
      "downloadUrl": "https://files.example.com/app.apk",
      "size": 12345,
      "md5": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "packageName": "com.example.app",
      "version": "1.2",
      "controlList": [{"controlDomain": "c2.example.com", "controlIp": "8.8.8.8", "controlPort": 443}],
      "fraudType": "虚假投资",
      "analyseDate": "2026-11-11T12:30:00",
      "icon": "https://files.example.com/icon.png",
      "report": "https://files.example.com/report.pdf",
      "framework": "Flutter"
    }
  }
}
```

### 状态

| `status` | 含义 | `result` |
| --- | --- | --- |
| `downloading` | 正在下载 APK | `null` |
| `download_failed` | 下载失败 | `null` |
| `static_analyzing` | 正在静态分析 | `null` |
| `static_failed` | 静态分析失败 | `null` |
| `waiting_device` | 等待动态分析设备 | `null` |
| `dynamic_tracing` | 正在动态分析 | `null` |
| `dynamic_failed` | 动态分析失败 | `null` |
| `completed` | 动态分析完成 | 结果对象 |

### 完成时的结果字段

下表字段在 `result` 中全部**必返**。必返指键名存在；分析未识别出数据时值可能为 `null`。`controlList` 无记录时为 `[]`。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `appName` | 字符串或 `null` | APP 名称。 |
| `downloadUrl` | 字符串或 `null` | 原始 APK 链接。 |
| `size` | 整数或 `null` | APK 大小，单位字节。 |
| `md5` | 字符串或 `null` | APK 文件 MD5。 |
| `packageName` | 字符串或 `null` | Android 包名。 |
| `version` | 字符串或 `null` | APP 版本名。 |
| `controlList` | 对象数组 | 主控目标列表；每项包含 `controlDomain`、`controlIp`、`controlPort`。 |
| `fraudType` | 字符串或 `null` | 已匹配的涉诈模型类型；未匹配时为 `null`。 |
| `analyseDate` | 字符串或 `null` | 任务最近更新时间，ISO 8601 格式；并非独立记录的完成时间。 |
| `icon` | 字符串或 `null` | APP 图标链接。 |
| `report` | 字符串或 `null` | PDF 报告链接。 |
| `framework` | 字符串或 `null` | 检测到的开发框架。 |

`controlList` 汇总普通流量和 eCapture 日志中标记为真实主控的记录，按域名、IP、端口去重。没有主控记录时返回 `[]`；直接 IP 目标的 `controlDomain` 可能为 `null`。报告异步生成，任务刚进入 `completed` 时 `report` 可能仍为 `null`，可稍后重查。

`downloadUrl`、`icon`、`report` 使用存储服务配置的对象地址，调用方需要能访问该地址；这三个字段并非临时签名 URL。

## 错误与边界情况

| HTTP 状态 | 场景 | 响应 |
| --- | --- | --- |
| `200` | 请求已处理 | `code: 0`；批量提交仍需逐条检查 `success`。 |
| `401` | 提交接口携带无效 Bearer Token | `code: 401`，`data: null`。不传 Token 即可匿名提交。 |
| `404` | 查询的任务 ID 不存在 | `{"code":404,"message":"任务不存在","data":null}`。 |
| `422` | 请求结构校验失败，如缺少 `files`、`urls` 为空、优先级越界 | `code: 422`，`data` 为校验错误列表。 |

上传文件不是 APK、超过单文件大小限制或同批重复，通常体现为相应 `items[]` 条目的 `success: false` 和 `reason`，整个批次仍可能返回 HTTP 200。提交成功只表示任务已创建并投递，最终结果以查询接口的 `status` 为准。
