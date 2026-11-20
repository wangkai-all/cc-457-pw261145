// Entry point: starts the service and the HTTP server, handles shutdown.

import { loadConfig } from "./config.js";
import { createLogger } from "./log.js";
import { Service } from "./service.js";
import { createServer } from "./http.js";

const log = createLogger();

const cfg = loadConfig();
const service = new Service(cfg, { log });
await service.init();

const server = createServer(service);

server.listen(cfg.port, cfg.host, () => {
  log.info(
    { url: `http://${cfg.host}:${cfg.port}`, dataDir: cfg.dataDir },
    `附件监控面板已就绪：http://${cfg.host}:${cfg.port}`,
  );
});

await service.start();

let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  log.info({ signal }, "正在停止服务");
  const force = setTimeout(() => {
    log.error({}, "优雅停止超时，强制退出");
    process.exit(1);
  }, 10_000);
  force.unref();
  try {
    server.close();
    await service.stop();
  } finally {
    clearTimeout(force);
    process.exit(0);
  }
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("unhandledRejection", (err) => {
  log.error({ err: err?.message, stack: err?.stack }, "未处理的 Promise 拒绝");
});
process.on("uncaughtException", (err) => {
  log.error({ err: err?.message, stack: err?.stack }, "未捕获异常，准备退出");
  shutdown("uncaughtException");
});
