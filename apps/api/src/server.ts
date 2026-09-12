import { app } from "./app.js";
import { config } from "./config.js";
import { pool } from "./db.js";
const server = app.listen(config.PORT, "127.0.0.1", () =>
  console.log(`SecureWallet API: http://127.0.0.1:${config.PORT}`),
);
for (const signal of ["SIGINT", "SIGTERM"] as const)
  process.on(signal, () => {
    server.close(() => {
      void pool.end();
    });
  });
