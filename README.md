# inbox-guard · 附件目录监控与解析准入

监听一个附件落地目录，把每一个文件送过「稳定性 → 体积/哈希 → 压缩包结构 → 病毒扫描」四道闸门，
只有全部通过的文件才进入解析队列。被拦下的文件**移动**到隔离区，数据库里保留完整哈希、原因码与事件轨迹，
可以从页面上重试、释放或删除。

- 零第三方依赖：Node.js ≥ 22.5（用到 `node:sqlite`、`node:zlib`、`fs.watch`）
- 状态都在 SQLite（WAL）+ 磁盘目录里，进程随时可以停止再拉起
- 页面是纯静态 HTML/CSS/JS，由同一个 HTTP 服务托管

```bash
npm start          # http://127.0.0.1:4173，数据目录 ./data
npm run demo       # 生成演示样例 + 启动面板（数据目录 ./data-demo）
npm run demo -- --reset     # 先清空 data-demo 再演示
npm run demo -- --seed-only # 只创建目录并投放样例，不启动监控
npm test           # node:test 全量用例
```

演示脚本会依次投放：正常 txt/csv/json、`*.part` 临时文件、2 MB 超大文件、两层嵌套压缩包、
五层嵌套压缩包、含 `../` 的压缩包、重复内容、同名替换、由 mock 判定为感染的样例；
最后暂停接收并留一批待处理文件，让页面上的「目录水位」显示为警告级别，点「暂停接收」即可继续排空。

## 目录结构

```
src/
  index.js       进程入口：加载配置、启动服务与 HTTP
  service.js     装配数据库 / 扫描器 / 流水线 / 监控 / 解析队列 + 定时维护
  config.js      配置与环境变量（全部可覆盖）
  watcher.js     fs.watch（低延迟提示）+ 周期巡检（正确性来源），按路径合并事件
  pipeline.js    准入流水线：接收、稳定性、哈希、压缩包、扫描、入队、隔离、重试、释放、删除
  stability.js   静默窗口、写入句柄探测、哈希、无覆盖移动
  archive.js     ZIP/ZIP64、tar、gzip 结构检查（嵌套、穿越、符号链接、加密、炸弹）
  scanner.js     扫描引擎（mock / 外部命令）+ 熔断器与可用性状态
  parsequeue.js  解析队列：抢占式领取、解析前复算哈希、报告落盘、失败重试
  parser.js      txt/csv/json/xml/markdown/OOXML/压缩包清单解析
  db.js          SQLite 模式与仓储层
  reasons.js     原因码目录（中文标签、严重度、是否可重试）
  http.js        JSON API + 静态页面
public/          仪表盘（原生 HTML/CSS/JS）
scripts/
  demo.js        一键演示：投放代表性样例并启动面板
  mock-scanner.js 外部扫描器适配示例（JSON 输出，exit 75 = 不可用）
test/            node:test 用例（监控重启、重复事件、扫描不可用等）
```

数据目录（默认 `./data`）：

```
inbox/       落地目录（被监控）
staging/     接收后的暂存副本；检查只读这里
quarantine/  隔离副本（文件被移动，不是复制）
queue/       已准入，等待/正在解析
out/         解析报告 <product-id>.report.json
trash/       删除操作移入的回收区（记录仍保留）
inbox-guard.sqlite3
```

## 准入流水线

1. **接收**：`fs.watch` 只是提示，真正的来源是每 15 秒（可配）的巡检；同一路径的连续事件会合并。
   临时名（`.xxx`、`*.part`、`*.crdownload`、`~$*` 等）且刚写入的文件只记一条 `ignored` 事件，不建产品记录；
   名字像临时文件但已静置超过 `TEMP_GRACE_MS` 的，按普通文件处理。
2. **稳定性**：等待 `STABILITY_QUIET_MS` 内 size/mtime/inode 不变，并检查 Linux `/proc/*/fdinfo`
   是否有进程仍以写方式持有它。超时未稳定 → `unstable_write`（可重试）；等待期间被替换 → 重新开始。
3. **同名替换**：同名路径再次出现且 size/mtime 不同，旧记录保留原状态并记 `replaced` 事件；
   新文件生成新的产品记录。仍在检查中的旧任务会被中止。
4. **体积与哈希**：先算完整 SHA-256 + 头尾采样哈希，再判断是否超过 `MAX_FILE_BYTES`。
   超大文件 → `too_large`，哈希照样留下。
5. **重复内容**：相同 SHA-256 的第二次投递 → `duplicate_content`，指明首个产品 id。
6. **压缩包**：识别 ZIP/ZIP64、tar、gzip 并按层展开（受 `MAX_ARCHIVE_DEPTH` 限制）。
   路径穿越、绝对路径、符号链接、加密成员、重名成员、成员过多、解压总量/压缩比超限 → 相应原因码；
   嵌套超限 → `archive_too_deep`。检查有独立时间预算（`archive_inspection_timeout`）。
7. **病毒扫描**：mock 引擎按内容哈希给出确定性判定（可配感染率/可疑率），或通过 `SCAN_CMD` 接真实扫描器。
   扫描器不可用/超时 → `scanner_unavailable` / `scanner_timeout`（可重试，文件留在隔离区，不会当作干净放行）。
8. **入队**：移动到 `queue/`，解析结果写入 `out/`。解析前会复算哈希，不一致 → `hash_mismatch`。

## 页面

- **目录水位**：收件目录当前占用 / 预算，70% 警告、90% 危险；附最近采样趋势。
- **统计块**：隔离中、解析队列、检查中、健康状态、扫描引擎。
- **隔离原因分布**：按原因码计数（单色系条形），点击可筛选列表。
- **文件表格**：状态筛选、搜索、排序、分页；行内「重试 / 释放 / 删除」。
- **详情**：哈希、采样哈希、来源路径、存储路径、扫描结论、压缩包结论、解析摘要、完整事件轨迹。
- **扫描器开关**：模拟不可用 / 模拟失败 / 恢复；健康检查随之降级。
- **事件流**：发现、忽略、替换、隔离、重试、入队、解析、释放、删除等全部留痕。

「释放」会先复算哈希，一致才移动（默认 `data/released/`，可指定绝对目录；数据目录之外需显式确认）；
「删除」把副本移入 `trash/`，记录、哈希、原因保留，可勾选彻底删除（同时清除去重记录）。

## 重试语义

| 原因码 | 自动重试 | 人工重试 |
|---|---|---|
| `scanner_unavailable` `scanner_timeout` `scanner_error` | 是（指数退避 + 抖动，上限 `SCAN_MAX_ATTEMPTS`） | 是 |
| `unstable_write` `archive_inspection_timeout` | 是 | 是 |
| `virus_detected` `scan_suspicious` `too_large` `hash_mismatch` 及压缩包结构问题 | 否 | 否（只能显式释放或删除） |
| `duplicate_content` `temp_file` `file_missing` | 否 | 否 |

重试是从隔离区把副本移回暂存区重新走一遍检查，不会复用旧的判定；重试表落库，重启后继续。

## 监控重启与幂等

- 启动时先巡检一遍收件目录，停机期间落地的文件不会漏。
- `checking` 状态且副本在 `staging/` 的记录会继续检查；`running` 的解析会重置为待处理。
- `queue/` / `quarantine/` 中的无主文件（例如数据库重建）按文件名中的产品 id 接管。
- 记录在、副本不在 → `lost`，哈希与原因仍保留。
- 同一路径的重复事件、同一内容的重复投递、并发请求都不会产生重复产品（内容寻址 + 唯一约束 + 在途任务表）。

## 配置

所有配置都有环境变量，完整清单见 `src/config.js`。常用的：

| 变量 | 默认 | 说明 |
|---|---|---|
| `PORT` / `HOST` | `4173` / `127.0.0.1` | HTTP 监听 |
| `INBOX_DATA_DIR` | `./data` | 数据根目录（其余目录默认在其下） |
| `WATCH_DIR` `STAGING_DIR` `QUARANTINE_DIR` `QUEUE_DIR` `OUT_DIR` `TRASH_DIR` `DB_PATH` | 见上文 | 单独覆盖各目录 |
| `MAX_FILE_BYTES` | 64 MiB | 单文件上限 |
| `MAX_ARCHIVE_DEPTH` | 3 | 压缩包嵌套层数 |
| `MAX_ARCHIVE_MEMBERS` | 2000 | 成员数上限 |
| `MAX_ARCHIVE_UNCOMPRESSED_BYTES` | 512 MiB | 解压总量上限 |
| `MAX_ARCHIVE_RATIO` | 120 | 单成员压缩比告警阈值 |
| `STABILITY_QUIET_MS` | 1500 | 静默窗口 |
| `STABILITY_MAX_WAIT_MS` | 600000 | 等待稳定的总预算 |
| `TEMP_GRACE_MS` | 30000 | 临时名文件给予的静置宽限 |
| `SWEEP_INTERVAL_MS` | 15000 | 巡检周期 |
| `SCAN_MODE` | `auto` | `auto` / `mock` / `external` |
| `SCAN_CMD` `SCAN_ARGS` | 空 | 外部扫描命令，`{path}` `{sha256}` `{name}` 占位 |
| `SCAN_MOCK_INFECTED_RATE` / `SCAN_MOCK_SUSPICIOUS_RATE` | `0.08` / `0.04` | mock 判定比例 |
| `SCAN_MAX_ATTEMPTS` `SCAN_RETRY_BASE_MS` `SCAN_RETRY_MAX_MS` | `3` `1000` `30000` | 重试退避 |
| `SCAN_CIRCUIT_FAILS` `SCAN_CIRCUIT_OPEN_MS` | `2` `30000` | 熔断阈值与冷却（冷却后放一次半开探测） |
| `WATERLINE_BUDGET_BYTES` | 2 GiB | 水位预算（演示脚本用 8 MiB） |
| `WATERLINE_WARNING_PCT` / `WATERLINE_CRITICAL_PCT` | `70` / `90` | 水位阈值 |
| `EVENT_RETENTION_MS` | 30 天 | 事件与回收区保留期 |

### 接真实扫描器

```bash
SCAN_MODE=external \
SCAN_CMD=/usr/local/bin/av-scan \
SCAN_ARGS="--json {path}" \
npm start
```

扫描器需在 stdout 输出一个 JSON 对象：`{"verdict":"clean|suspicious|infected","severity":"none|low|medium|high|critical","engine":"...","signature":null}`。
退出码 75、非零退出、输出无法解析、超时，都视为**服务不可用**（可重试），而不是「有病毒」。
`npm run mock-scanner -- <file>` 是一个可用的示例实现。

## 验证

```bash
npm test
```

覆盖：临时文件、稳定入队与报告、超大文件、病毒判定、嵌套/穿越/炸弹压缩包、同名替换、扫描不可用与自动重试、
熔断与恢复、显式重试、释放/删除、重复事件合并、监控重启（暂存中/检查中/无主文件/缺失副本）、内容去重、
维护模式、水位采样、HTTP 分页/过滤/错误路径/静态资源安全、扫描器模拟开关与健康检查。

手工验证扫描服务不可用：页面上点「模拟不可用」→ 新投放文件被隔离为 `scanner_unavailable`（哈希保留）；
点「恢复」后自动重试把文件送入解析队列。

## 边界与取舍

- 这是准入网关，不是杀毒软件：内置 mock 仅用于演示与测试，生产请接真实引擎。
- 稳定性判断依赖静默窗口；网络盘上的 `fs.watch` 可能不触发，兜底是周期巡检。
- 解析器只做轻量内容提取（文本/CSV/JSON/OOXML/压缩包清单），不执行任何内容。
- 压缩包只检查结构，不解压到磁盘；所有读取都有长度与时间上限。
