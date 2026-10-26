// server.js - minimal SMS receiver for testing MacroDroid
const express = require("express");
const app = express();

// 1. Log EVERY request, even failed ones or unknown routes
app.use((req, res, next) => {
  console.log(`[${new Date().toLocaleTimeString()}] ${req.method} ${req.url} from ${req.ip}`);
  next();
});

// 2. Read the body as raw bytes, whatever Content-Type MacroDroid sends
app.use(express.raw({ type: () => true, limit: "1mb" }));

// Health check: open this in a browser to test the connection
app.get("/health", (req, res) => {
  res.json({ ok: true, time: Date.now() });
});

// MacroDroid posts here
app.post("/api/sms", (req, res) => {
  const rawBody = Buffer.isBuffer(req.body) ? req.body.toString("utf8") : "";
  let text = rawBody;
  let sender = req.query.sender || req.get("x-sender") || "unknown";

  // If the body is JSON, pull the fields out of it
  try {
    const json = JSON.parse(rawBody);
    if (json && typeof json === "object") {
      text = json.text || json.message || rawBody;
      sender = json.sender || sender;
    }
  } catch (e) {
    // Not JSON: the body is the plain SMS text
  }

  console.log("SMS received");
  console.log("  Sender:", sender);
  console.log("  Content-Type:", req.get("content-type"));
  console.log("  Text:", text);

  res.json({
    ok: true,
    sender,
    length: text.length,
    notificationText: "TrustVault got your SMS",
  });
});

// Catch-all so wrong URLs show up clearly
app.use((req, res) => {
  res.status(404).json({ error: "Route not found", path: req.url });
});

// "0.0.0.0" means: accept connections from other devices, not only this laptop
app.listen(3000, "0.0.0.0", () => {
  console.log("SMS test server running on port 3000");
});