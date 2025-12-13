const express = require("express");
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json({ limit: "100kb" }));

const PORT = process.env.PORT || 3000;
const API_KEY = process.env.LODGIC_AUTH_API_KEY;
const BCRYPT_ROUNDS = Number(process.env.BCRYPT_ROUNDS || 10);

app.get("/health", (req, res) => {
  res.json({ ok: true, service: "lodgic-auth" });
});

app.post("/hash", async (req, res) => {
  try {
    const key = req.header("x-lodgic-key");
    if (!API_KEY || !key || key !== API_KEY) {
      return res.status(401).json({ ok: false, error: "UNAUTHORIZED" });
    }

    const { password } = req.body || {};
    if (!password || typeof password !== "string" || password.length < 8) {
      return res.status(400).json({ ok: false, error: "INVALID_PASSWORD" });
    }

    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    return res.json({ ok: true, password_hash: hash, algo: "bcrypt", rounds: BCRYPT_ROUNDS });
  } catch (e) {
    return res.status(500).json({ ok: false, error: "HASH_FAILED" });
  }
});

app.listen(PORT, () => {
  console.log(`[lodgic-auth] listening on port ${PORT}`);
});
