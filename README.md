# 科研样品全生命周期管理服务

这是一个面向科研机构样品库、实验室和课题组的模块化后端，集中管理样品接收、分装、借用、归还、消耗、销毁、库存盘点、谱系事件、保管位置、异常记录、登录权限、审计以及可恢复后台任务。项目使用 FastAPI 与 SQLite，所有运行数据保存在单个本地数据库文件中，不依赖另行部署的数据库、缓存或消息队列。

## 已有能力

- 身份与权限：支持引导管理员、登录、会话、用户、角色和细粒度权限。
- 批次与二维码：接收批次保存项目、数量和稳定二维码载荷。
- 可轮换交接凭证：为接收批次发放绑定批次、交出方、接收方、有效期与单调版本的一次性二维码，明文仅发放/轮换时返回一次，库内只存摘要；支持轮换、撤销（仅限未使用）。
- 扫码交接回执：单事务幂等扫码接收，原子落库本次交接数量、拒收原因与保管位置；旧版本、过期、已撤销、已关闭批次、交接方不符、内容冲突均返回各自可区分错误码；被拒扫码同样留痕。
- 交接使用轨迹：管理员可查看凭证/批次完整生命周期（发放、轮换、撤销、接收、回放、拒绝），普通查询不泄露任何可重放二维码内容。
- 样品档案：登记样品、数量、单位、保管位置和生命周期状态。
- 分装谱系：一次事务内扣减母样、创建子样、记录损耗与事件链。
- 借用归还：保存借用数量、到期时间、部分归还和最终归还状态。
- 实验消耗：使用幂等键登记消耗，防止重复请求二次扣减。
- 位置脱敏：普通权限只能看到受限位置的替代码，授权人员可查看精确位置。
- 双人审批：高风险操作要求申请人与审批人分离，并累计不同审批人的决定。
- 异常追踪：异常可以关联样品或接收批次，保存严重度和处理状态。
- 审计与任务：关键身份及业务操作留痕，后台任务支持去重、领取与完成。

## 运行环境

- Python 3.11
- SQLite 3，由 Python 标准库提供
- Linux、macOS 或 Windows

## 安装

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

默认数据库位于 `./data/samples.db`，可用 `SAMPLE_DATABASE_PATH` 指定其他路径。

## 初始化与完整性检查

```bash
python -m app.cli init-db
python -m app.cli check-db
```

## 启动 API

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## 测试

```bash
python -m pytest
```

## 编译检查

```bash
python -m compileall -q app tests
```

## API 冒烟

```bash
python -m app.cli smoke
```

## 交接凭证与扫码接收

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| POST | `/api/handovers/batches/{id}/close` | `handovers.issue` | 关闭接收批次 |
| POST | `/api/handovers/credentials` | `handovers.issue` | 发放首枚凭证，响应中的 `qr_content` 仅此一次返回 |
| POST | `/api/handovers/credentials/{id}/rotate` | `handovers.issue` | 轮换为下一单调版本，旧码立即作废 |
| POST | `/api/handovers/credentials/{id}/revoke` | `handovers.issue` | 撤销尚未使用的凭证 |
| GET | `/api/handovers/credentials/{id}` | `handovers.issue` | 凭证详情（不含明文/摘要） |
| GET | `/api/handovers/batches/{id}` | `samples.read` | 批次凭证与回执清单（脱敏） |
| GET | `/api/handovers/credentials/{id}/trail`、`/api/handovers/batches/{id}/trail` | `handovers.trail`（仅管理员角色持有） | 完整使用轨迹 |
| POST | `/api/handovers/receive` | `handovers.receive` | 扫码接收入库（幂等） |

扫码接收在单个 `BEGIN IMMEDIATE` 事务内原子写入回执（本次交接数量、拒收原因、保管位置），并以凭证与回执的唯一约束兜底并发。可区分错误码：

- `credential_not_found`（404）：二维码无法识别或不存在
- `credential_expired`：超过有效期
- `credential_superseded`：版本已被轮换取代
- `credential_revoked`：凭证已撤销
- `batch_closed`：接收批次已关闭
- `handover_party_mismatch`：扫码接收人与凭证绑定接收方不一致
- `handover_payload_conflict`：同一凭证重复扫码但内容与原回执不一致

重复扫码（内容一致）返回 200 并带 `replayed: true`，回放原回执且不重复计数。

