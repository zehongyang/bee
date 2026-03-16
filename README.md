# Bee Framework

Bee 是一个基于 Go 语言的高性能、多协议支持的服务端框架。它旨在简化后端开发，提供统一的上下文接口 (`IContext`) 来处理 HTTP、TCP 和 WebSocket 请求，并集成了常用的数据库、缓存和配置管理组件。

## 🚀 特性

- **多协议支持**：
  - **HTTP**: 基于 [Gin](https://github.com/gin-gonic/gin) 框架，提供强大的路由和中间件支持。
  - **WebSocket**: 基于 [Gorilla WebSocket](https://github.com/gorilla/websocket)，支持 JSON 和 Protobuf 数据格式。
  - **TCP**: 内置自定义二进制协议的高性能 TCP 服务端。
- **统一上下文 (`IContext`)**：无论使用哪种协议，都能通过统一的接口进行请求绑定、响应处理和上下文管理。
- **组件集成**：
  - **数据库**: 集成 [XORM](https://xorm.io/)，支持 MySQL, PostgreSQL, SQLite 等，并内置分表 (`SplitTable`) 支持。
  - **缓存/Redis**: 集成 [go-redis](https://github.com/redis/go-redis)，提供便捷的 Redis 操作接口。
  - **配置管理**: 使用 [Viper](https://github.com/spf13/viper) 加载 YAML 配置。
  - **日志**: 集成 [Zerolog](https://github.com/rs/zerolog) 高性能日志库。
- **工具库**: 提供单例模式、栈、去重等常用工具函数。

## 🛠️ 安装

```bash
go get github.com/zehongyang/bee
```

## 📖 使用指南

### 1. HTTP 服务

```go
package main

import (
    "github.com/zehongyang/bee"
)

func main() {
    server := bee.NewHttpServer()

    // 注册路由
    server.Get("/ping", func(ctx bee.IContext) {
        ctx.ResponseOk(map[string]string{
            "message": "pong",
        })
    })

    // 启动服务
    server.Run(":8080")
}
```

### 2. WebSocket 服务

```go
package main

import (
    "github.com/zehongyang/bee"
)

func main() {
    server := bee.NewWebSocketServer()

    // 启动服务
    server.Run(":8081", "/ws")
}
```

### 3. TCP 服务

TCP 服务使用自定义的二进制协议包 (`Package`) 进行通信，包含版本、内容类型、FID、QID、Code 和数据体。

```go
package main

import (
    "github.com/zehongyang/bee"
)

func main() {
    server := bee.NewTcpServer() // 假设存在此构造函数，基于代码推断
    server.Run(":8082")
}
```

### 4. 统一上下文 (IContext)

`IContext` 接口定义了跨协议的通用操作：

```go
type IContext interface {
    Bind(obj any) error                   // 绑定请求数据
    GetAccount() AccountInfo              // 获取用户信息
    ResponseOk(obj any)                   // 响应成功
    ResponseError(code int, msg ...string)// 响应错误
    Next()                                // 执行下一个中间件
    AbortWithStatus(code int)             // 中止并返回状态码
    SetAccount(account AccountInfo)       // 设置用户信息
    GetHeader(key string) string          // 获取头部信息
    SetHeader(key, value string)          // 设置头部信息
    BindHeader(obj any) error             // 绑定头部数据
    BindUri(obj any) error                // 绑定 URI 数据
}
```

## ⚙️ 配置

项目默认加载 `application.yml` 配置文件。

**示例配置 (`application.yml`):**

```yaml
logger:
  level: "debug"
  writer: "console"

dbs:
  - name: "default"
    driver: "mysql"
    dataSource: "root:password@tcp(127.0.0.1:3306)/bee?charset=utf8mb4"
    maxIdle: 10
    maxConn: 100

rds:
  - name: "cache"
    addr: "127.0.0.1:6379"
    password: ""
    db: 0
```

## 📂 项目结构

```
bee/
├── caches/       # 缓存抽象与实现
├── config/       # 配置加载逻辑
├── dbs/          # 数据库管理 (XORM 封装)
├── logger/       # 日志封装
├── rds/          # Redis 管理
├── utils/        # 通用工具函数
├── context.go    # IContext 接口定义
├── handler.go    # 处理器定义
├── http_server.go # HTTP 服务实现
├── tcp_server.go  # TCP 服务实现
├── websocket_server.go # WebSocket 服务实现
├── application.yml # 配置文件示例
└── go.mod        # 依赖管理
```

## 📝 协议格式

### TCP 包结构

| 字段        | 类型   | 描述                            |
| ----------- | ------ | ------------------------------- |
| Version     | int8   | 协议版本                        |
| ContentType | int8   | 内容类型 (0: JSON, 1: Protobuf) |
| Fid         | int32  | 功能 ID                         |
| Qid         | int32  | 请求 ID (用于匹配响应)          |
| Code        | int32  | 状态码                          |
| Length      | int32  | 数据长度                        |
| Data        | []byte | 数据体                          |

### WebSocket 数据结构

WebSocket 消息使用 JSON 封装（除非直接传输二进制流），结构如下：

```json
{
  "content_type": 0,
  "fid": 1001,
  "qid": 1,
  "code": 200,
  "data": "base64_encoded_data_if_needed_or_raw_object"
}
```
