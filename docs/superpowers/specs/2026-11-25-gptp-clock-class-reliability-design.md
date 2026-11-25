# gPTP clockClass 时间可靠性显示设计

## 目标

M22 作为 gPTP Master 时，在 Announce 中通过 Grandmaster clockClass 表示
GNSS 时间是否已经同步到 gPTP。Slave 程序需要显示原始 clockClass，并依据
客户定义值给出直观的时间可靠性状态。

客户验收规则：

- `clockClass=6`：GNSS 已同步，PTP 时间可靠。
- `clockClass=248`：上电默认或尚未同步。
- `clockClass=13`：断开天线后的降级状态。
- `clockClass=52`：PB 复位后的过渡状态。

## 可靠性状态

| clockClass | 状态 | 说明 |
| --- | --- | --- |
| `6` | `GNSS_LOCKED` | GNSS 时间已同步到 gPTP |
| `248` | `WAITING_GNSS` | 等待 GNSS 同步 |
| `13` | `DEGRADED` | 降级/保持状态，不可判定为 GNSS 同步 |
| `52` | `TRANSITIONING` | 复位后的过渡状态 |
| 其他 | `UNKNOWN` | 未定义的值 |
| 最近 Announce 超过 3 秒 | `STALE` | 没有新鲜的 Grandmaster 状态 |

`STALE` 优先于 clockClass 映射。即使最后收到的 clockClass 为 6，只要
超过 3 秒没有新的有效 Announce，也不能显示为可靠。

## Announce 数据

Slave 快照新增：

- Announce sequence ID。
- clockClass。
- clockAccuracy。
- clockVariance。
- priority1。
- priority2。
- stepsRemoved。
- timeSource。
- 最近 Announce 时间及 Age。
- 派生可靠性状态。

clockClass 必须来自当前锁定 Grandmaster 的 Announce。Ack 或 Sync 报文
不能替代 clockClass 状态。

## GUI 展示

Slave 模式状态区增加：

- 明显的时间可靠性徽标：
  - `GNSS_LOCKED`
  - `WAITING_GNSS`
  - `DEGRADED`
  - `TRANSITIONING`
  - `UNKNOWN`
  - `STALE`
- `GM class=<value>`。
- Announce sequence 和 Age。
- clockAccuracy。
- timeSource。
- stepsRemoved。

Grandmaster 信息文本使用紧凑格式，完整字段放入 Tooltip 或详情。

颜色：

- `GNSS_LOCKED`：绿色。
- `WAITING_GNSS`、`TRANSITIONING`：黄色。
- `DEGRADED`、`STALE`：红色。
- `UNKNOWN`：灰色。

## 状态变化日志

只有状态真正变化时记录：

```text
clockClass 248 -> 6, WAITING_GNSS -> GNSS_LOCKED
clockClass 6 -> 13, GNSS_LOCKED -> DEGRADED
Announce stale, DEGRADED -> STALE
```

相同状态的高频刷新不得重复写日志。

## 兼容性

- Master 模式继续显示自己的 clockClass，不受本功能影响。
- 在没有 Announce、只收到 Sync/FollowUp 时，可靠性状态显示 `UNKNOWN`
  或 `STALE`，不能把原始偏移分析误标为 GNSS 已同步。
- 角色切换、停止和重启时清空旧 clockClass、Announce sequence 和可靠性状态。

## 验证

自动化测试覆盖：

- clockClass 248 -> 6 状态切换。
- 6 -> 13 降级。
- 13 -> 6 恢复。
- clockClass 52 过渡状态。
- 未定义 clockClass。
- Announce 超过 3 秒进入 STALE。
- 相同状态不重复记录日志。
- Master/Slave 切换和停止清理。
- 响应式界面上字段不撑宽窗口。

实机测试：

- M22 Master 上电未同步时显示 `WAITING_GNSS` 和 class 248。
- 收星同步后显示 `GNSS_LOCKED` 和 class 6。
- 断开天线后显示 `DEGRADED` 和 class 13。
- 接回天线并同步后恢复 `GNSS_LOCKED`。

## 非目标

- 不根据 clockClass 修改 Windows 系统时间。
- 不替代完整的 BMCA。
- 不把 clockClass 单独等同于 offset 精度。
