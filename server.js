/**
 * Waitless — Backend Server (Node.js + Express)
 * ─────────────────────────────────────────────
 * This server handles:
 *   • Firebase Admin SDK for server-side auth verification
 *   • REST API routes (optional layer on top of direct Firestore)
 *   • Webhook / notification endpoints
 *
 * NOTE: The app largely uses Firebase Firestore's real-time listeners
 * directly from the frontend. This backend adds an extra security layer
 * and can be used for server-side operations / future extensions.
 *
 * Setup:
 *   1. npm install
 *   2. Add your Firebase service account JSON (see below)
 *   3. node server.js
 */

const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const rateLimit = require("express-rate-limit");

// ── Firebase Admin Init ───────────────────────────────────────────────────────
// Download your service account key from:
// Firebase Console → Project Settings → Service Accounts → Generate new private key
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT); // ADD YOUR FILE HERE

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

// ── Express Setup ─────────────────────────────────────────────────────────────
const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors({
  origin: [
    "https://joggy0577-lgtm.github.io",
    "http://localhost:3000"
  ],
  methods: ["GET","POST","PATCH","DELETE"],
  allowedHeaders: ["Content-Type","Authorization"]
}));
app.use(express.json());

// Rate limiting — prevent abuse
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use(limiter);

// ── Middleware: Verify Firebase ID Token ──────────────────────────────────────
async function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Unauthorized: No token" });
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.user = decoded;
    next();
  } catch (e) {
    res.status(401).json({ error: "Unauthorized: Invalid token" });
  }
}

// ── Routes ────────────────────────────────────────────────────────────────────

// Health check
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ── PUBLIC: Get all active appointments ──────────────────────────────────────
app.get("/api/appointments", async (req, res) => {
  try {
    const snap = await db
      .collection("appointments")
      .where("active", "==", true)
      .get();

    const appointments = snap.docs.map((d) => ({ id: d.id, ...d.data() }));
    res.json({ appointments });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to fetch appointments" });
  }
});

// ── PUBLIC: Get single appointment ───────────────────────────────────────────
app.get("/api/appointments/:id", async (req, res) => {
  try {
    const docRef = db.collection("appointments").doc(req.params.id);
    const snap = await docRef.get();
    if (!snap.exists) return res.status(404).json({ error: "Not found" });
    res.json({ id: snap.id, ...snap.data() });
  } catch (e) {
    res.status(500).json({ error: "Failed to fetch appointment" });
  }
});

// ── DOCTOR: Create appointment ────────────────────────────────────────────────
// One active appointment per doctor enforced server-side
app.post("/api/appointments", verifyToken, async (req, res) => {
  const { title, startTime, totalTokens, notes } = req.body;

  if (!title || !startTime) {
    return res.status(400).json({ error: "title and startTime are required" });
  }
  if (totalTokens < 1 || totalTokens > 500) {
    return res.status(400).json({ error: "totalTokens must be between 1–500" });
  }

  try {
    // Enforce: one active appointment per doctor
    const existing = await db
      .collection("appointments")
      .where("doctorId", "==", req.user.uid)
      .where("active", "==", true)
      .get();

    if (!existing.empty) {
      return res.status(409).json({
        error: "You already have an active appointment session. End it before creating a new one.",
      });
    }

    const docRef = db.collection("appointments").doc();
    const appointment = {
      doctorId: req.user.uid,
      doctorName: req.user.name || "Doctor",
      doctorPhoto: req.user.picture || "",
      title,
      startTime,
      totalTokens: Number(totalTokens),
      currentToken: 1,
      status: "normal",        // normal | emergency | nopatient | break
      instruction: "",
      active: true,
      notes: notes || "",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    await docRef.set(appointment);
    res.status(201).json({ id: docRef.id, ...appointment });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to create appointment" });
  }
});

// ── DOCTOR: Update appointment (token control, status, instruction) ──────────
app.patch("/api/appointments/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  const { status, currentToken, instruction } = req.body;

  try {
    const docRef = db.collection("appointments").doc(id);
    const snap = await docRef.get();

    if (!snap.exists) return res.status(404).json({ error: "Not found" });

    const data = snap.data();

    // Only the owner doctor can update
    if (data.doctorId !== req.user.uid) {
      return res.status(403).json({ error: "Forbidden: Not your appointment" });
    }

    const updates = {};

    // Status update
    const validStatuses = ["normal", "emergency", "nopatient", "break"];
    if (status !== undefined) {
      if (!validStatuses.includes(status)) {
        return res.status(400).json({ error: "Invalid status" });
      }
      updates.status = status;
    }

    // Token update
    if (currentToken !== undefined) {
      const token = Number(currentToken);
      if (token < 1 || token > data.totalTokens) {
        return res.status(400).json({ error: "currentToken out of range" });
      }
      updates.currentToken = token;
    }

    // Instruction broadcast
    if (instruction !== undefined) {
      updates.instruction = String(instruction).slice(0, 300); // max 300 chars
    }

    updates.updatedAt = admin.firestore.FieldValue.serverTimestamp();
    await docRef.update(updates);

    res.json({ success: true, updates });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to update appointment" });
  }
});

// ── DOCTOR: End appointment session ──────────────────────────────────────────
app.delete("/api/appointments/:id", verifyToken, async (req, res) => {
  const { id } = req.params;

  try {
    const docRef = db.collection("appointments").doc(id);
    const snap = await docRef.get();

    if (!snap.exists) return res.status(404).json({ error: "Not found" });
    if (snap.data().doctorId !== req.user.uid) {
      return res.status(403).json({ error: "Forbidden" });
    }

    await docRef.update({
      active: false,
      endedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.json({ success: true, message: "Session ended." });
  } catch (e) {
    res.status(500).json({ error: "Failed to end session" });
  }
});

// ── DOCTOR: Get my active appointment ────────────────────────────────────────
app.get("/api/my-appointment", verifyToken, async (req, res) => {
  try {
    const snap = await db
      .collection("appointments")
      .where("doctorId", "==", req.user.uid)
      .where("active", "==", true)
      .get();

    if (snap.empty) return res.json({ appointment: null });
    const d = snap.docs[0];
    res.json({ appointment: { id: d.id, ...d.data() } });
  } catch (e) {
    res.status(500).json({ error: "Failed to fetch" });
  }
});

// ── Start Server ──────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🚀 Waitless backend running on http://localhost:${PORT}\n`);
});

module.exports = app;
