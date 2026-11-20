// Reason catalog. Every quarantine / failure has exactly one code, and the UI
// reads human labels from here so wording stays consistent between the API,
// the event journal and the dashboard.

export const REASON_GROUPS = {
  stability: "稳定性",
  size: "体积",
  archive: "压缩包",
  security: "安全扫描",
  dedupe: "重复",
  integrity: "完整性",
  parse: "解析",
};

/**
 * severity: info | low | medium | high | critical
 * retryable: whether re-running the checks can plausibly change the outcome
 * automatic: emitted by the monitor rather than an operator action
 */
export const REASONS = {
  temp_file: {
    label: "临时文件",
    group: "stability",
    severity: "low",
    retryable: false,
    hint: "文件名或形态表明它是写入过程中的中间产物，不是可处理附件。",
  },
  unstable_write: {
    label: "写入未稳定",
    group: "stability",
    severity: "medium",
    retryable: true,
    hint: "在等待窗口内文件仍被修改或一直有写入句柄，无法确认内容完整。",
  },
  too_large: {
    label: "超大文件",
    group: "size",
    severity: "medium",
    retryable: false,
    hint: "超过单文件体积上限，已停止读取并保留采样哈希。",
  },
  archive_too_deep: {
    label: "压缩包嵌套过深",
    group: "archive",
    severity: "high",
    retryable: false,
    hint: "嵌套层数超过上限，继续展开可能消耗大量资源。",
  },
  archive_path_traversal: {
    label: "压缩包路径穿越",
    group: "archive",
    severity: "high",
    retryable: false,
    hint: "成员路径包含 ..，解压时可能写到目标目录之外。",
  },
  archive_absolute_path: {
    label: "压缩包绝对路径",
    group: "archive",
    severity: "high",
    retryable: false,
    hint: "成员使用绝对路径，解压行为不可控。",
  },
  archive_symlink: {
    label: "压缩包含符号链接",
    group: "archive",
    severity: "medium",
    retryable: false,
    hint: "符号链接可能在解压后指向包外文件。",
  },
  archive_encrypted: {
    label: "压缩包已加密",
    group: "archive",
    severity: "high",
    retryable: false,
    hint: "加密内容无法检查，也无法保证下游解析安全。",
  },
  archive_too_many_members: {
    label: "压缩包成员过多",
    group: "archive",
    severity: "medium",
    retryable: false,
    hint: "成员数超过上限，可能是压缩炸弹。",
  },
  archive_expansion_limit: {
    label: "压缩包解压超限",
    group: "archive",
    severity: "high",
    retryable: false,
    hint: "声明的解压总量超过上限，按压缩炸弹处理。",
  },
  archive_duplicate_member: {
    label: "压缩包重名成员",
    group: "archive",
    severity: "high",
    retryable: false,
    hint: "包内存在同名成员，解压结果取决于实现，可能被用来覆盖文件。",
  },
  archive_unreadable: {
    label: "压缩包损坏",
    group: "archive",
    severity: "medium",
    retryable: false,
    hint: "压缩包结构损坏或被截断，无法完成检查。",
  },
  archive_inspection_timeout: {
    label: "压缩包检查超时",
    group: "archive",
    severity: "medium",
    retryable: true,
    hint: "在时间预算内未能完成展开检查。",
  },
  virus_detected: {
    label: "检出病毒",
    group: "security",
    severity: "critical",
    retryable: false,
    hint: "扫描引擎返回恶意判定。只有显式放行才会进入解析。",
  },
  scan_suspicious: {
    label: "可疑文件",
    group: "security",
    severity: "high",
    retryable: false,
    hint: "扫描引擎返回可疑判定，需人工判断。",
  },
  scanner_unavailable: {
    label: "扫描服务不可用",
    group: "security",
    severity: "medium",
    retryable: true,
    hint: "扫描服务连续失败或熔断，文件被保留而不是放行。服务恢复后可安全重试。",
  },
  scanner_timeout: {
    label: "扫描超时",
    group: "security",
    severity: "medium",
    retryable: true,
    hint: "扫描超过时间预算，结果未知。",
  },
  scanner_error: {
    label: "扫描异常",
    group: "security",
    severity: "medium",
    retryable: true,
    hint: "扫描过程返回了无法识别的结果。",
  },
  duplicate_content: {
    label: "重复内容",
    group: "dedupe",
    severity: "info",
    retryable: false,
    hint: "相同内容此前已经处理过，本次投递不再重复入队。",
  },
  hash_mismatch: {
    label: "内容校验失败",
    group: "integrity",
    severity: "high",
    retryable: false,
    hint: "存储副本的哈希与记录不一致，可能被改动，拒绝继续处理。",
  },
  file_missing: {
    label: "文件缺失",
    group: "integrity",
    severity: "medium",
    retryable: false,
    hint: "记录仍在，但磁盘上的副本已不存在。",
  },
  parse_failed: {
    label: "解析失败",
    group: "parse",
    severity: "medium",
    retryable: true,
    hint: "准入通过，但解析阶段失败；文件仍在解析队列中。",
  },
  parse_unsupported: {
    label: "格式不支持",
    group: "parse",
    severity: "low",
    retryable: false,
    hint: "解析器不识别该格式，文件内容仍完整保留。",
  },
};

export function reasonInfo(code) {
  return (
    REASONS[code] ?? {
      label: code ?? "未知",
      group: "integrity",
      severity: "medium",
      retryable: false,
      hint: null,
    }
  );
}

export const REASON_CODES = Object.keys(REASONS);
