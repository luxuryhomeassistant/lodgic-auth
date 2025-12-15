const express = require("express");
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json({ limit: "100kb" }));

const PORT = process.env.PORT || 3000;
const API_KEY = process.env.LODGIC_AUTH_API_KEY;
const BCRYPT_ROUNDS = Number(process.env.BCRYPT_ROUNDS || 10);

// ---------- HEALTH ----------
app.get("/health", (req, res) => {
  res.json({ ok: true, service: "lodgic-auth" });
});

// ---------- HASH PASSWORD ----------
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
    return res.json({
      ok: true,
      password_hash: hash,
      algo: "bcrypt",
      rounds: BCRYPT_ROUNDS
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: "HASH_FAILED" });
  }
});

// ---------- VERIFY PASSWORD ----------
app.post("/verify", async (req, res) => {
  try {
    const key = req.header("x-lodgic-key");
    if (!API_KEY || !key || key !== API_KEY) {
      return res.status(401).json({ ok: false, error: "UNAUTHORIZED" });
    }

    const { password, hash } = req.body || {};

    if (
      !password ||
      !hash ||
      typeof password !== "string" ||
      typeof hash !== "string"
    ) {
      return res.status(400).json({ ok: false, error: "INVALID_INPUT" });
    }

    const valid = await bcrypt.compare(password, hash);
    return res.json({ ok: valid });
  } catch (e) {
    return res.status(500).json({ ok: false, error: "VERIFY_FAILED" });
  }
});

// =====================================================
// =============== NUEVO: SESIONES =====================
// =====================================================

// ---------- VALIDAR SESIÓN ----------
app.post("/session/validate", async (req, res) => {
  try {
    const key = req.header("x-lodgic-key");
    if (!API_KEY || !key || key !== API_KEY) {
      return res.status(401).json({ ok: false, error: "UNAUTHORIZED" });
    }

    const { token } = req.body || {};
    if (!token || typeof token !== "string") {
      return res.status(400).json({ ok: false, error: "TOKEN_REQUIRED" });
    }

    const response = await fetch(process.env.N8N_VALIDATE_SESSION_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-lodgic-key": API_KEY
      },
      body: JSON.stringify({ token })
    });

    const data = await response.json();
    return res.json(data);

  } catch (e) {
    return res.status(500).json({
      ok: false,
      error: "SESSION_VALIDATE_FAILED"
    });
  }
});

// ---------- REVOCAR SESIÓN ----------
app.post("/session/revoke", async (req, res) => {
  try {
    const key = req.header("x-lodgic-key");
    if (!API_KEY || !key || key !== API_KEY) {
      return res.status(401).json({ ok: false, error: "UNAUTHORIZED" });
    }

    const { token } = req.body || {};
    if (!token || typeof token !== "string") {
      return res.status(400).json({ ok: false, error: "TOKEN_REQUIRED" });
    }

    await fetch(process.env.N8N_REVOKE_SESSION_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-lodgic-key": API_KEY
      },
      body: JSON.stringify({ token })
    });

    return res.json({ ok: true });

  } catch (e) {
    return res.status(500).json({
      ok: false,
      error: "SESSION_REVOKE_FAILED"
    });
  }
});

// ---------- START SERVER ----------
app.listen(PORT, () => {
  console.log(`[lodgic-auth] listening on port ${PORT}`);
});
