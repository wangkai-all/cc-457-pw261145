// Dashboard client. Plain ES module: fetch dashboard, render, act.

const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];

const REASON_META = {
  temp_file: { label: "临时文件", group: "stability" },
  unstable_write: { label: "写入未稳定", group: "stability" },
  too_large: { label: "超大文件", group: "size" },
  archive_too_deep: { label: "压缩包嵌套过深", group: "archive" },
  archive_path_traversal: { label: "压缩包路径穿越", group: "archive" },
  archive_absolute_path: { label: "压缩包绝对路径", group: "archive" },
  archive_symlink: { label: "压缩包含符号链接", group: "archive" },
  archive_encrypted: { label: "压缩包已加密", group: "archive" },
  archive_too_many_members: { label: "压缩包成员过多", group: "archive" },
  archive_expansion_limit: { label: "压缩包解压超限", group: "archive" },
  archive_duplicate_member: { label: "压缩包重名成员", group: "archive" },
  archive_unreadable: { label: "压缩包损坏", group: "archive" },
  archive_inspection_timeout: { label: "压缩包检查超时", group: "archive" },
  virus_detected: { label: "检出病毒", group: "security" },
  scan_suspicious: { label: "可疑文件", group: "security" },
  scanner_unavailable: { label: "扫描服务不可用", group: "security" },
  scanner_timeout: { label: "扫描超时", group: "security" },
  scanner_error: { label: "扫描异常", group: "security" },
  duplicate_content: { label: "重复内容", group: "dedupe" },
  hash_mismatch: { label: "内容校验失败", group: "integrity" },
  file_missing: { label: "文件缺失", group: "integrity" },
  parse_failed: { label: "解析失败", group: "parse" },
  parse_unsupported: { label: "格式不支持", group: "parse" },
};

const STATE_LABEL = {
  checking: "检查中",
  quarantined: "隔离中",
  queued: "队列中",
  released: "已释放",
  deleted: "已删除",
  lost: "已丢失",
  duplicate: "重复",
};

const SCAN_LABEL = { clean: "通过", infected: "恶意", suspicious: "可疑", error: "未知" };

const SEVERITY_LABEL = {
  info: "提示",
  low: "低危",
  medium: "中危",
  high: "高危",
  critical: "严重",
};

const EVENT_SEVERITY = {
  quarantined: "high",
  scan_infected: "critical",
  scan_suspicious: "high",
  scan_clean: "good",
  queued: "good",
  parse_ready: "good",
  deleted: "low",
  released: "low",
  lost: "medium",
  error: "critical",
  parse_failed: "high",
  hash_mismatch: "critical",
  retry_exhausted: "medium",
  scanner_simulated: "medium",
  scanner_recovered: "good",
  maintenance: "medium",
  recovered: "medium",
};

const state = {
  dashboard: null,
  filter: "quarantined",
  search: "",
  sort: "newest",
  page: 0,
  pageSize: 50,
  items: [],
  total: 0,
  selectedId: null,
  detail: null,
  busy: false,
  events: [],
  lastEventId: null,
  pollTimer: null,
  paused: localStorage.getItem("inbox.theme.paused") === "1",
};

const fmt = {
  bytes(n) {
    if (!Number.isFinite(n)) return "—";
    if (n < 1024) return `${n} B`;
    const u = ["KB", "MB", "GB", "TB"];
    let v = n / 1024;
    let i = 0;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i += 1; }
    return `${v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2)} ${u[i]}`;
  },
  time(iso) {
    if (!iso) return "—";
    const d = new Date(iso);
    const diff = Date.now() - d.getTime();
    if (diff < 45_000) return "刚刚";
    if (diff < 3_600_000) return `${Math.round(diff / 60_000)} 分钟前`;
    if (diff < 86_400_000) return `${Math.round(diff / 3_600_000)} 小时前`;
    return d.toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
  },
  abs(iso) {
    return iso ? new Date(iso).toLocaleString("zh-CN", { hour12: false }) : "—";
  },
  dur(ms) {
    if (!Number.isFinite(ms) || ms < 0) return "—";
    const s = Math.floor(ms / 1000);
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    if (d) return `${d} 天 ${h} 小时`;
    if (h) return `${h} 小时 ${m} 分`;
    if (m) return `${m} 分`;
    return `${s} 秒`;
  },
  shortHash(h) {
    if (!h) return null;
    return `${h.slice(0, 10)}…${h.slice(-6)}`;
  },
};

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

function reasonMeta(code) {
  return REASON_META[code] ?? { label: code || "未知", group: "integrity" };
}

// ---- API ----------------------------------------------------------------
async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "content-type": "application/json" },
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  let body = null;
  try { body = await res.json(); } catch { /* empty */ }
  if (!res.ok) {
    throw new Error(body?.error || `请求失败（HTTP ${res.status}）`);
  }
  return body;
}

function toast(message, kind = "ok") {
  const el = document.createElement("div");
  el.className = "toast";
  el.dataset.kind = kind;
  el.innerHTML = `<span aria-hidden="true">${kind === "error" ? "⚠" : "✓"}</span><span>${esc(message)}</span>`;
  $("#toasts").append(el);
  setTimeout(() => el.remove(), kind === "error" ? 6000 : 3500);
}

// ---- rendering: header / hero / tiles -----------------------------------
function renderHeader(d) {
  const health = d.health;
  const pill = $("#overall");
  pill.dataset.status = health.status;
  $("#overall-text").textContent =
    health.status === "ok" ? "运行正常" : health.status === "degraded" ? "降级运行" : "服务异常";
  const scan = d.scanner;
  const bits = [
    `运行 ${fmt.dur(d.uptimeMs)}`,
    scan.available ? `扫描：${scan.engine}` : "扫描不可用",
    d.maintenance ? "维护模式" : null,
    d.watcher.running ? "监控已连接" : "监控仅巡检",
  ].filter(Boolean);
  $("#subtitle").textContent = bits.join(" · ");
  $("#btn-pause").setAttribute("aria-pressed", String(d.maintenance));
  $("#btn-pause").textContent = d.maintenance ? "恢复接收" : "暂停接收";
  $("#foot-meta").textContent = `服务时间 ${fmt.abs(d.serverTime)}`;
}

function renderWaterline(d) {
  const w = d.waterline;
  const sub = $("#waterline-sub");
  const levelText = w.level === "critical" ? "接近容量上限" : w.level === "warning" ? "水位偏高" : "余量充足";
  sub.textContent = `${levelText} · 预算 ${fmt.bytes(w.budgetBytes)}`;
  $("#waterline-value").textContent = `${w.percent.toFixed(1)}%`;
  const fill = $("#waterline-fill");
  fill.style.width = `${Math.max(0.5, w.percent)}%`;
  fill.dataset.level = w.level;
  $("#waterline-meter").setAttribute(
    "aria-label",
    `收件目录占用 ${w.percent.toFixed(1)}%，${fmt.bytes(w.bytes)} / ${fmt.bytes(w.budgetBytes)}，${w.files} 个文件`,
  );
  $("#waterline-files").textContent = `${w.files} 个文件 · ${fmt.bytes(w.bytes)}`;
  $("#waterline-budget").textContent = `采样 ${fmt.time(w.sampledAt)}`;
  $("#waterline-warn").style.left = `${d.waterline.warningPct}%`;
  $("#waterline-crit").style.left = `${d.waterline.criticalPct}%`;
}

function renderTiles(d) {
  const q = d.parse;
  const queueTotal = d.counts.queued;
  $("#tile-queue").textContent = String(queueTotal);
  $("#tile-queue-foot").innerHTML =
    q.running > 0
      ? `<span class="up">${q.running} 个解析中</span>`
      : q.failed > 0
        ? `<span class="up">${q.failed} 个待重试</span>`
        : `${q.pending} 个待解析 · ${q.ready} 个完成`;

  $("#tile-quarantine").textContent = String(d.quarantine.total);
  const retry = d.quarantine.retryable;
  $("#tile-quarantine-foot").innerHTML = d.quarantine.total
    ? `${retry ? `<span class="up">${retry} 个可重试</span>` : "等待人工处理"}`
    : `<span class="ok">无待处理</span>`;

  $("#tile-checking").textContent = String(d.counts.checking);
  $("#tile-checking-foot").textContent = d.counts.checking ? "稳定性 / 扫描进行中" : "空闲";

  const h = d.health;
  $("#tile-health").textContent = h.status === "ok" ? "正常" : h.status === "degraded" ? "降级" : "异常";
  $("#tile-health-foot").textContent = d.scanner.available ? "扫描可用" : "扫描熔断中";
}

function renderHealth(d) {
  const list = $("#health-list");
  const icon = (s) =>
    s === "ok"
      ? '<svg viewBox="0 0 12 12" aria-hidden="true"><path d="M2 6.2 4.6 9 10 3.2" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>'
      : s === "degraded"
        ? '<svg viewBox="0 0 12 12" aria-hidden="true"><path d="M6 1.8 11 10.5H1z" fill="none" stroke="currentColor" stroke-width="1.4"/><path d="M6 5v2.6M6 9v.1" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>'
        : '<svg viewBox="0 0 12 12" aria-hidden="true"><path d="M3 3l6 6M9 3l-6 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>';
  const word = { ok: "正常", degraded: "降级", down: "异常" };
  list.innerHTML = d.health.checks
    .map(
      (c) => `<li>
        <span class="check-icon" data-status="${esc(c.status)}">${icon(c.status)}</span>
        <span class="check-label">${esc(c.label)}<span class="sr-only">：${word[c.status]}</span></span>
        <span class="check-detail">${esc(c.detail ?? "")}</span>
      </li>`,
    )
    .join("");
  $("#health-age").textContent = `更新于 ${fmt.abs(d.serverTime)}`;

  const s = d.scanner;
  $("#scanner-name").textContent = s.engine;
  const parts = [];
  parts.push(s.available ? "状态：可用" : `状态：熔断${s.openUntil ? `，冷却至 ${fmt.abs(s.openUntil)}` : ""}`);
  parts.push(`连续失败 ${s.consecutiveFailures}`);
  if (s.lastOkAt) parts.push(`上次成功 ${fmt.time(s.lastOkAt)}`);
  if (s.lastError) parts.push(`错误：${s.lastError}`);
  $("#scanner-meta").textContent = parts.join(" · ");
  const mock = s.mode !== "external";
  $$("#scanner-buttons .btn").forEach((b) => { b.disabled = !mock; });
}

function renderReasons(d) {
  const chart = $("#reason-chart");
  const empty = $("#reasons-empty");
  const reasons = d.quarantine.reasons ?? [];
  $("#reasons-total").textContent = d.quarantine.total ? `${d.quarantine.total} 个文件` : "—";
  if (!reasons.length) {
    chart.innerHTML = "";
    empty.hidden = false;
    return;
  }
  empty.hidden = true;
  const max = Math.max(...reasons.map((r) => r.count));
  // A single-series magnitude chart: one hue. Severity is carried by the badge
  // text in the label column, not by colouring the bars per-row.
  chart.innerHTML = reasons
    .map((r) => {
      const meta = reasonMeta(r.code);
      const pct = Math.max(3, (r.count / max) * 100);
      return `<div class="reason-row" title="${esc(meta.label)}：${r.count} 个，共 ${fmt.bytes(r.bytes)}${r.retryable ? "（可自动重试）" : ""}">
        <span class="reason-name"><span class="swatch" style="background:var(--series-1)" aria-hidden="true"></span>${esc(r.label)}</span>
        <span class="reason-track"><span class="reason-bar" style="width:${pct}%;background:var(--series-1)"></span></span>
        <span class="reason-count">${r.count}<small> · ${fmt.bytes(r.bytes)}</small></span>
      </div>`;
    })
    .join("");
}

// ---- products table -----------------------------------------------------
function stateBadge(p) {
  const label = STATE_LABEL[p.state] ?? p.state;
  return `<span class="badge" data-kind="${esc(p.state)}"><span class="bdot" aria-hidden="true"></span>${esc(label)}</span>`;
}

function parseBadge(p) {
  if (p.state !== "queued") return "";
  const map = { pending: ["待解析", "checking"], running: ["解析中", "checking"], ready: ["已完成", "queued"], failed: ["解析失败", "quarantined"] };
  const [label, kind] = map[p.parse_status] ?? ["—", "checking"];
  return ` <span class="badge" data-kind="${kind}"><span class="bdot" aria-hidden="true"></span>${esc(label)}</span>`;
}

function renderProducts() {
  const body = $("#products-body");
  if (!state.items.length) {
    body.innerHTML = `<tr class="empty-row"><td colspan="7">没有符合条件的文件。</td></tr>`;
  } else {
    body.innerHTML = state.items
      .map((p) => {
        const meta = p.reason_code ? reasonMeta(p.reason_code) : null;
        const retryable = p.reason_detail?.retryable;
        const canRetry = p.state === "quarantined" && retryable && p.storage_path;
        const canRelease = ["quarantined", "queued"].includes(p.state) && p.storage_path;
        const canDelete = !["deleted"].includes(p.state) && p.state !== "checking";
        const reason = meta
          ? `<div class="reason-cell">
               <span class="reason-label">${esc(meta.label)}</span>
               <span class="reason-hint">${esc(
                 p.reason_detail?.retryable
                   ? "可安全重试"
                   : SEVERITY_LABEL[p.reason_detail?.severity] ?? "",
               )}</span>
             </div>`
          : `<span class="muted">—</span>`;
        return `<tr data-id="${esc(p.id)}" class="${p.id === state.selectedId ? "selected" : ""}" tabindex="0">
          <td><div class="file-cell"><span class="file-name" title="${esc(p.original_name)}">${esc(p.original_name)}</span><span class="file-id">${esc(p.id)}</span></div></td>
          <td>${stateBadge(p)}${parseBadge(p)}</td>
          <td>${reason}</td>
          <td class="num">${esc(p.sizeLabel ?? fmt.bytes(p.size_bytes))}</td>
          <td>${p.sha256 ? `<span class="hash" title="${esc(p.sha256)}">${esc(fmt.shortHash(p.sha256))}</span>` : `<span class="hash missing">计算中</span>`}</td>
          <td class="time">${fmt.time(p.first_seen_at)}</td>
          <td class="actions-col"><div class="row-actions">
            ${canRetry ? `<button class="btn tiny" type="button" data-act="retry" data-id="${esc(p.id)}">重试</button>` : ""}
            ${canRelease ? `<button class="btn tiny" type="button" data-act="release" data-id="${esc(p.id)}">释放</button>` : ""}
            ${canDelete ? `<button class="btn tiny" type="button" data-act="delete" data-id="${esc(p.id)}">删除</button>` : ""}
          </div></td>
        </tr>`;
      })
      .join("");
  }
  const shownFrom = state.total ? state.page * state.pageSize + 1 : 0;
  const shownTo = Math.min(state.total, (state.page + 1) * state.pageSize);
  $("#products-count").textContent = `显示 ${shownFrom}–${shownTo} / 共 ${state.total} 个`;
  $("#page-label").textContent = `${state.page + 1} / ${Math.max(1, Math.ceil(state.total / state.pageSize))}`;
  $("#prev").disabled = state.page === 0;
  $("#next").disabled = (state.page + 1) * state.pageSize >= state.total;
}

async function loadProducts() {
  const params = new URLSearchParams();
  if (state.filter) params.set("state", state.filter);
  if (state.search) params.set("q", state.search);
  params.set("sort", state.sort);
  params.set("limit", String(state.pageSize));
  params.set("offset", String(state.page * state.pageSize));
  const res = await api(`/api/products?${params}`);
  state.items = res.items;
  state.total = res.total;
  renderProducts();
}

// ---- events -------------------------------------------------------------
function renderEvents(events) {
  const el = $("#events");
  if (!events.length) {
    el.innerHTML = '<li><span class="ev-dot"></span><span class="ev-text muted">暂无活动</span><span></span></li>';
    return;
  }
  el.innerHTML = events
    .map((e) => {
      const sev = EVENT_SEVERITY[e.kind] ?? (e.kind === "quarantined" ? "high" : "low");
      return `<li>
        <span class="ev-dot" data-sev="${sev}" aria-hidden="true"></span>
        <div>
          <div class="ev-text">${esc(e.summary)}</div>
          <div class="ev-meta">${esc(e.kind)}${e.reason_code ? ` · ${esc(reasonMeta(e.reason_code).label)}` : ""}</div>
        </div>
        <span class="ev-time" title="${esc(fmt.abs(e.at))}">${esc(fmt.time(e.at))}</span>
      </li>`;
    })
    .join("");
}

// ---- detail -------------------------------------------------------------
async function loadDetail(id) {
  state.selectedId = id;
  renderProducts();
  const el = $("#detail");
  $("#detail-id").textContent = id;
  try {
    const d = await api(`/api/products/${encodeURIComponent(id)}`);
    state.detail = d;
    renderDetail(d);
  } catch (err) {
    el.innerHTML = `<p class="muted">${esc(err.message)}</p>`;
  }
}

function renderDetail({ product: p, events, parseResult }) {
  const el = $("#detail");
  const meta = p.reason_code ? reasonMeta(p.reason_code) : null;
  const detail = p.reason_detail ?? {};
  const items = [
    ["状态", STATE_LABEL[p.state] ?? p.state],
    ["体积", `${p.sizeLabel ?? fmt.bytes(p.size_bytes)}`],
    ["SHA-256", p.sha256 || "尚未计算"],
    ["原因", meta ? meta.label : "—"],
    ["扫描", p.scan_verdict ? `${SCAN_LABEL[p.scan_verdict] ?? p.scan_verdict}${p.scan_signature ? `（${p.scan_signature}）` : ""}` : "—"],
    ["扫描引擎", p.scan_engine || "—"],
    ["压缩包", p.archive_kind ? `${p.archive_kind} · ${p.archive_members ?? 0} 成员 · 深度 ${p.archive_depth ?? 0}` : "—"],
    ["解析", p.parse_status ? `${p.parse_status}（尝试 ${p.parse_attempts} 次）` : "—"],
    ["发现时间", fmt.abs(p.first_seen_at)],
    ["更新时间", fmt.abs(p.updated_at)],
    ["存储位置", p.storage_path || "—"],
    ["去重来源", p.dedupe_of || "—"],
  ];
  if (p.next_retry_at) items.push(["下次重试", fmt.abs(p.next_retry_at)]);
  if (detail.releasedBy) items.push(["释放操作人", detail.releasedBy]);
  if (p.release_target) items.push(["释放至", p.release_target]);
  if (p.last_error) items.push(["最近错误", p.last_error]);

  const detailKeys = Object.keys(detail).filter(
    (k) => !["retryable", "severity", "extraReasons", "quarantinedAt"].includes(k),
  );
  const detailKv = detailKeys.map((k) => [k, typeof detail[k] === "object" ? JSON.stringify(detail[k]) : String(detail[k])]);
  if (Array.isArray(detail.extraReasons) && detail.extraReasons.length) {
    detailKv.push(["附加风险", detail.extraReasons.map((c) => reasonMeta(c).label).join("、")]);
  }

  const canRetry = p.state === "quarantined" && p.reason_detail?.retryable && p.storage_path;
  const canRelease = ["quarantined", "queued"].includes(p.state) && p.storage_path;
  const canDelete = p.state !== "deleted" && p.state !== "checking";

  el.className = "detail";
  el.innerHTML = `
    <div class="detail-head">
      <div>
        <div class="detail-name">${esc(p.original_name)}</div>
        <div class="file-id">${esc(p.id)}</div>
      </div>
      <div class="pill-row">${stateBadge(p)}${parseBadge(p)}${p.reason_detail?.retryable ? '<span class="badge" data-kind="retry">可重试</span>' : ""}</div>
    </div>
    <div class="detail-actions">
      ${canRetry ? '<button class="btn tiny" type="button" data-act="retry" data-id="' + esc(p.id) + '">重新检查</button>' : ""}
      ${canRelease ? '<button class="btn tiny" type="button" data-act="release" data-id="' + esc(p.id) + '">释放</button>' : ""}
      ${canDelete ? '<button class="btn tiny" type="button" data-act="delete" data-id="' + esc(p.id) + '">删除</button>' : ""}
    </div>
    <div class="detail-grid">
      ${items.map(([k, v]) => `<div class="detail-item"><span class="k">${esc(k)}</span><span class="v ${k === "SHA-256" || k === "存储位置" ? "mono" : ""}">${esc(v)}</span></div>`).join("")}
    </div>
    ${detailKv.length ? `<div class="detail-section-title">原因详情</div><ul class="kv-list">${detailKv.map(([k, v]) => `<li><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></li>`).join("")}</ul>` : ""}
    ${parseResult ? `<div class="detail-section-title">解析摘要</div><div class="detail-item"><span class="v">${esc(parseResult.summary)}</span></div>` : ""}
    <div class="detail-section-title">事件轨迹</div>
    <ul class="kv-list">${events.map((e) => `<li><span class="k">${esc(fmt.time(e.at))}</span><span class="v">${esc(e.summary)}</span></li>`).join("")}</ul>
  `;
}

// ---- refresh loop -------------------------------------------------------
async function refreshDashboard() {
  const d = await api("/api/dashboard");
  state.dashboard = d;
  renderHeader(d);
  renderWaterline(d);
  renderTiles(d);
  renderHealth(d);
  renderReasons(d);
  renderEvents(d.events);
  if (state.detail) {
    // Keep the detail pane fresh without re-fetching on every poll if nothing changed.
    const row = state.items.find((p) => p.id === state.selectedId);
    if (row && row.updated_at !== state.detail?.product?.updated_at) loadDetail(state.selectedId);
  }
}

async function refreshAll() {
  if (state.busy) return;
  try {
    await Promise.all([refreshDashboard(), loadProducts()]);
    if (state.selectedId && !state.detail) loadDetail(state.selectedId);
  } catch (err) {
    toast(`刷新失败：${err.message}`, "error");
    $("#overall").dataset.status = "down";
    $("#overall-text").textContent = "连接中断";
  }
}

function schedulePoll() {
  clearInterval(state.pollTimer);
  if (state.paused) return;
  state.pollTimer = setInterval(refreshAll, 5000);
}

// ---- actions ------------------------------------------------------------
async function act(kind, id) {
  if (kind === "retry") {
    try {
      const res = await api(`/api/products/${encodeURIComponent(id)}/retry`, { method: "POST", body: {} });
      toast(`已重新检查：${res.product.original_name}`);
      await refreshAll();
      if (state.selectedId === id) loadDetail(id);
    } catch (err) {
      toast(`重试失败：${err.message}`, "error");
    }
  }
}

const releaseDialog = $("#release-dialog");
const deleteDialog = $("#delete-dialog");
let dialogTarget = null;

function openRelease(id) {
  const p = state.items.find((x) => x.id === id) ?? state.detail?.product;
  if (!p) return;
  dialogTarget = id;
  $("#release-target-name").textContent = `${p.original_name} · ${p.sizeLabel ?? fmt.bytes(p.size_bytes)}`;
  $("#release-dir").value = "";
  $("#release-note").value = "";
  const risky = p.reason_code && ["virus_detected", "scan_suspicious", "hash_mismatch", "archive_path_traversal"].includes(p.reason_code);
  $("#release-warn").hidden = !risky;
  releaseDialog.showModal();
}

function openDelete(id) {
  const p = state.items.find((x) => x.id === id) ?? state.detail?.product;
  if (!p) return;
  dialogTarget = id;
  $("#delete-target-name").textContent = `${p.original_name} · ${p.sizeLabel ?? fmt.bytes(p.size_bytes)}`;
  $("#delete-hard").checked = false;
  deleteDialog.showModal();
}

$("#release-dialog").addEventListener("close", async () => {
  if ($("#release-dialog").returnValue !== "ok" || !dialogTarget) return;
  const targetDir = $("#release-dir").value.trim();
  const note = $("#release-note").value.trim();
  try {
    await api(`/api/products/${encodeURIComponent(dialogTarget)}/release`, {
      method: "POST",
      body: {
        targetDir: targetDir || undefined,
        note,
        confirmOutsideDataDir: Boolean(targetDir),
      },
    });
    toast("已释放");
    await refreshAll();
    if (state.selectedId) loadDetail(state.selectedId);
  } catch (err) {
    toast(`释放失败：${err.message}`, "error");
  }
});

$("#delete-dialog").addEventListener("close", async () => {
  if ($("#delete-dialog").returnValue !== "ok" || !dialogTarget) return;
  try {
    await api(`/api/products/${encodeURIComponent(dialogTarget)}/delete`, {
      method: "POST",
      body: { confirm: true, hard: $("#delete-hard").checked },
    });
    toast("已删除");
    if (state.selectedId === dialogTarget) {
      state.selectedId = null;
      state.detail = null;
      $("#detail").className = "detail empty";
      $("#detail").innerHTML = '<p class="muted">在文件清单中选择一行，查看哈希、检查结果与完整事件轨迹。</p>';
      $("#detail-id").textContent = "选择一行查看";
    }
    await refreshAll();
  } catch (err) {
    toast(`删除失败：${err.message}`, "error");
  }
});

// ---- wiring -------------------------------------------------------------
$("#products-body").addEventListener("click", (ev) => {
  const btn = ev.target.closest("button[data-act]");
  if (btn) {
    ev.stopPropagation();
    const { act: action, id } = btn.dataset;
    if (action === "release") openRelease(id);
    else if (action === "delete") openDelete(id);
    else act(action, id);
    return;
  }
  const row = ev.target.closest("tr[data-id]");
  if (row) loadDetail(row.dataset.id);
});

$("#products-body").addEventListener("keydown", (ev) => {
  const row = ev.target.closest("tr[data-id]");
  if (row && (ev.key === "Enter" || ev.key === " ")) {
    ev.preventDefault();
    loadDetail(row.dataset.id);
  }
});

$("#detail").addEventListener("click", (ev) => {
  const btn = ev.target.closest("button[data-act]");
  if (!btn) return;
  const { act: action, id } = btn.dataset;
  if (action === "release") openRelease(id);
  else if (action === "delete") openDelete(id);
  else act(action, id);
});

$("#state-filter").addEventListener("click", async (ev) => {
  const btn = ev.target.closest(".seg-btn");
  if (!btn) return;
  $$("#state-filter .seg-btn").forEach((b) => {
    b.classList.toggle("active", b === btn);
    b.setAttribute("aria-selected", String(b === btn));
  });
  state.filter = btn.dataset.state;
  state.page = 0;
  await loadProducts();
});

let searchTimer;
$("#search").addEventListener("input", (ev) => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(async () => {
    state.search = ev.target.value.trim();
    state.page = 0;
    await loadProducts();
  }, 220);
});

$("#sort").addEventListener("change", async (ev) => {
  state.sort = ev.target.value;
  await loadProducts();
});

$("#prev").addEventListener("click", async () => {
  if (state.page === 0) return;
  state.page -= 1;
  await loadProducts();
});
$("#next").addEventListener("click", async () => {
  if ((state.page + 1) * state.pageSize >= state.total) return;
  state.page += 1;
  await loadProducts();
});

$("#btn-refresh").addEventListener("click", refreshAll);

$("#btn-pause").addEventListener("click", async () => {
  const want = !(state.dashboard?.maintenance ?? false);
  try {
    const res = await api("/api/maintenance", { method: "POST", body: { enabled: want } });
    toast(res.maintenance ? "已暂停接收与解析" : "已恢复接收与解析");
    await refreshAll();
  } catch (err) {
    toast(`切换失败：${err.message}`, "error");
  }
});

$("#scanner-buttons").addEventListener("click", async (ev) => {
  const btn = ev.target.closest("button[data-scanner]");
  if (!btn) return;
  try {
    await api(`/api/scanner/${btn.dataset.scanner}`, { method: "POST", body: { count: 2 } });
    toast("已更新扫描模拟状态");
    await refreshAll();
  } catch (err) {
    toast(`操作失败：${err.message}`, "error");
  }
});

$("#btn-theme").addEventListener("click", () => {
  const cur = document.documentElement.dataset.theme;
  const next = cur === "dark" ? "light" : cur === "light" ? "" : "dark";
  if (next) document.documentElement.dataset.theme = next;
  else delete document.documentElement.dataset.theme;
  localStorage.setItem("inbox.theme", next);
});

// Restore theme.
{
  const t = localStorage.getItem("inbox.theme");
  if (t) document.documentElement.dataset.theme = t;
}

// Pause polling when the tab is hidden; catch up immediately on return.
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    clearInterval(state.pollTimer);
  } else {
    refreshAll();
    schedulePoll();
  }
});

refreshAll();
schedulePoll();
