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
- **优雅关闭**: `bee.Run` 统一监听退出信号，先等在途请求收尾，再倒序执行清理钩子（见「5. 优雅关闭」）。
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
    "github.com/zehongyang/bee/logger"
)

func main() {
    server := bee.NewHttpServer()

    // 注册路由
    server.Get("/ping", func(ctx bee.IContext) {
        ctx.ResponseOk(map[string]string{
            "message": "pong",
        })
    })

    // 启动服务：bee.Run 会阻塞到收到 SIGINT/SIGTERM，并负责优雅关闭
    if err := bee.Run(server, ":8080"); err != nil {
        logger.Fatal().Err(err).Msg("http server exited")
    }
}
```

### 2. WebSocket 服务

```go
package main

import (
    "github.com/zehongyang/bee"
)

func main() {
    // 握手路径由 WithWsPath 指定，默认 /ws
    server := bee.NewWebSocketServer(bee.WithWsPath("/ws"))

    // 启动服务
    bee.Run(server, ":8081")
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
    server := bee.NewTcpServer()
    bee.Run(server, ":8082")
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

### 5. 优雅关闭

三种 server 都实现了 `bee.Server`（`Run(addr) error` + `Shutdown(ctx) error`），交给 `bee.Run` 托管即可：

```go
func main() {
    server := bee.NewHttpServer()

    // 登记退出前要做的清理，按登记的相反顺序执行
    bee.OnShutdown("worker", func(ctx context.Context) error {
        return worker.Stop(ctx)
    })

    bee.Run(server, ":8080")
}
```

收到 `SIGINT` / `SIGTERM` 后的固定顺序：

1. 停止接受新请求，等待在途请求处理完；
2. 倒序执行 `bee.OnShutdown` 登记的清理动作（`dbs.GetDB` / `rds.Get` 建立的连接会自动登记，不用自己写）；
3. 超时则放弃剩余清理强制退出，返回 `bee.ErrShutdownTimeout`。

第 1 步的预算是 `shutdown.timeoutSeconds`，第 2 步另有一份 5 秒的独立预算。清理钩子不跟在途请求抢预算是有意的：一次几十秒的外部调用就能把总预算耗光，共用的话钩子拿到手就是过期的 ctx——最需要清理的那次退出反而什么都清不掉。

关闭卡住时再按一次 `Ctrl+C` 会立刻结束进程——`bee.Run` 在开始关闭时就把信号处理还原成了默认行为。

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

shutdown:
  # 等在途请求处理完的预算（秒），不配置时默认 15；清理钩子另有一份 5 秒的独立预算
  timeoutSeconds: 15
```

## 📂 项目结构

```
bee/
├── caches/       # 缓存抽象与实现
├── config/       # 配置加载逻辑
├── dbs/          # 数据库管理 (XORM 封装)
├── lifecycle/    # 退出清理钩子登记表
├── logger/       # 日志封装
├── rds/          # Redis 管理
├── utils/        # 通用工具函数
├── app.go        # bee.Run：信号监听与优雅关闭
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
