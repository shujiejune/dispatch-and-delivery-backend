# Logistics 模块开发说明


## 一、仓库现状概览
以下根据仓库根目录 `dispatch-and-delivery` 的结构，列出主要文件夹及其作用：

- 根目录
  - `cmd/api/main.go`：应用启动入口，在此完成配置加载、数据库连接和各模块的依赖注入。
  - `go.mod` / `go.sum`：Go 模块信息和依赖列表。
  - `database schema.md`、`ERD.drawio.png`：数据库结构文档与 ER 图。
- `cmd/api`：仅含 `main.go`，启动 HTTP 服务器。
- `pkg`
  - `utils.go`：预留的工具函数，目前为空实现。
- `internal`
  - `api`
    - `middleware/auth.go`：JWT 认证与管理员权限校验中间件。
    - `router.go`：集中注册所有 HTTP 路由。
  - `config`
    - `config.go`：读取 `.env` 文件并提供配置结构体。
  - `migrations`：建表脚本，已包含 `users`、`addresses`、`machines`、`orders` 等表的创建 SQL。
  - `models`：通用结构体定义，例如 JWT Claims、错误响应、订单模型等。
  - `modules`
    - `users`：用户模块
    - `orders`：订单模块

## 二、与要求的功能对比

手册要求 Logistics 模块提供以下能力：
1. `Machine status`:位置、可用性等。
2. `ComputeRoute`：调用 Google Maps Directions API 计算路线并保存结果。
3. `AssignOrder`：根据可用设备和路线为订单分配任务。
4. `ReportTracking` / `GetTracking`：设备上报位置并允许客户端查询轨迹。

当前仓库仅存在 `machines` 表及路由占位，缺少具体的模型定义、仓储层、服务层、HTTP 处理器，以及保存路线和追踪信息的数据库表。

## 从现有代码可借鉴的部分

* **分层结构示例**：`internal/modules/users` 与 `internal/modules/orders` 已完整实现 Repository、Service、Handler 三层，物流模块可按照相同模式编写。
* **模型定义**：`internal/models` 中包含订单及通用响应结构，新增的机器或路线模型也应放在此处，保持风格一致。
* **路由注册方式**：查看 `internal/api/router.go` 学习如何使用 Echo 的路由分组并加入中间件。
* **数据库迁移**：`internal/migrations` 展示了创建表的 SQL 和如何以 `up.sql`/`down.sql` 成对管理迁移文件，可参照新增物流相关表。
* **配置读取与工具函数**：`internal/config` 提供加载 `.env` 的示例，`pkg/utils.go` 可放置通用辅助方法。

## 三、待完成的具体任务

下面按功能点列出开发任务。相关代码将放在 `internal/modules/logistics` 目录下，并按功能拆分为以下四个文件：
- `logistic_MachineStatus.go`: 机器状态管理
- `logistic_ComputeRoutes.go`: 路线计算和保存
- `logistic_Assign.go`: 订单与设备分配
- `logistic_Tracking.go`: 位置上报与轨迹查询

### 1. 设备状态管理 (`logistic_MachineStatus.go`)

1. **数据模型与仓库层**
   ```text
   Repository
     ├─ FindMachineByID(id)
     ├─ UpdateMachine(machine)
     └─ ListMachines()

   实现示例
     - 在数据库中执行 INSERT/UPDATE/SELECT
   ```
   `models.Machine` 结构体放在 `internal/models`，字段与 `machines` 表对应。

2. **服务层**
   ```text
   Service.SetStatus(machineID, status, location)
       查找机器记录 -> repo.FindMachineByID(machineID)
       若不存在则返回错误
       更新机器状态与位置
       调用 repo.UpdateMachine
   Service.ListMachines()
       调用 repo.ListMachines 获取全部记录
   ```

3. **处理器与路由**
   ```text
   Handler.GetFleet
       调用 service.ListMachines
       返回机器列表的 JSON

   Handler.SetMachineStatus
       读取 machineId、位置、状态
       调用 service.SetStatus

   路由注册 (Admin 组)
       GET  /fleet                 -> GetFleet
       PUT  /fleet/:machineId/status -> SetMachineStatus
   ```

### 2. 计算路线（ComputeRoute） (`logistic_ComputeRoutes.go`)
 
1. **数据库迁移**
   `internal/migrations/002_create_routes_table.up.sql`
   ```sql
   CREATE TABLE routes (
       id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
       order_id UUID NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
       polyline TEXT NOT NULL,
       distance_meters INTEGER,
       duration_seconds INTEGER,
       created_at TIMESTAMPTZ NOT NULL DEFAULT now()
   );
   ```
   对应的 `.down.sql` 用于回滚。

2. **服务层实现**
   ```text
   Service.ComputeRoute(orderID)
       获取订单的取货和送达地址
       调用 Google Maps Directions API 计算路线
       若成功, 将距离、耗时和折线保存到数据库
       返回路线信息
   ```

3. **处理器与路由**
   ```text
   Handler.ComputeRoute
       解析 orderId
       调用 service.ComputeRoute
       返回计算后的路线 JSON

   路由注册
       POST /orders/:orderId/route -> ComputeRoute
   ```


### 3. 分配订单（AssignOrder） (`logistic_Assign.go`)

1. **服务逻辑**
   ```text
   Service.AssignOrder(orderID)
       获取订单的配送地址
       查询所有空闲机器并计算其到达时间
       选择距离最近的机器
       更新订单状态和机器状态
   ```

2. **接口触发**
   ```text
   Handler.ReassignOrder
       读取 orderId
       调用 service.AssignOrder
       返回 200 OK

   可在支付完成后调用，或提供管理员端口 POST /admin/orders/:orderId/reassign
   ```


 

### 4. 位置上报与轨迹查询 (`logistic_Tracking.go`)

1. **数据库迁移**
   `internal/migrations/002_create_tracking_events_table.up.sql`
   ```sql
   CREATE TABLE tracking_events (
       id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
       order_id UUID NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
       machine_id UUID NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
       location GEOGRAPHY(Point,4326) NOT NULL,
       created_at TIMESTAMPTZ NOT NULL DEFAULT now()
   );
   ```

2. **仓库与服务层**
   ```text
   Repository
     ├─ CreateTrackingEvent(event)
     └─ ListTrackingEvents(orderID)

   Service.ReportTracking(orderID, location)
       新建追踪记录并写入数据库

   Service.GetTracking(orderID)
       查询指定订单的追踪记录并返回
   ```

3. **HTTP 与 WebSocket**
   ```text
   Handler.ReportTracking
       读取位置信息
       调用 service.ReportTracking

   Handler.GetTracking
       调用 service.GetTracking
       返回轨迹列表

   Handler.HandleTrackingWS
       建立 WebSocket 并持续推送最新位置

   路由注册
       POST /orders/:orderId/track -> ReportTracking
       GET  /orders/:orderId/track -> GetTracking
       GET  /ws/orders/:orderId/track -> HandleTrackingWS (需认证)
   ```



