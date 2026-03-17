/**
 * Waitless — Backend Server (Node.js + Express)
 * ─────────────────────────────────────────────
 * Fixes in this version:
 *   • startTime is now optional (was incorrectly required)
 *   • totalTokens validation handles undefined/NaN safely
 *   • "notstarted" added to valid statuses
 *   • doctorName reads from correct Firebase token field
 *   • CORS now allows ALL origins (open API for any device/domain)
 *   • Appointment created with status "notstarted" by default
 */

const express  = require("express");
const cors     = require("cors");
const admin    = require("firebase-admin");
const rateLimit = require("express-rate-limit");

// ── Firebase Admin Init ───────────────────────────────────────────────────────
// ── Firebase Admin Init ───────────────────────────────────────────────────────
// Reads credentials from environment variable (safe for deployment)
// Set FIREBASE_SERVICE_ACCOUNT env var on Render with the full JSON content
let serviceAccount;
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  try {
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  } catch(e) {
    console.error("Failed to parse FIREBASE_SERVICE_ACCOUNT env var:", e.message);
    process.exit(1);
  }
} else {
  // Fallback for local development
  try {
    serviceAccount = require("./serviceAccountKey.json");
  } catch(e) {
    console.error("No FIREBASE_SERVICE_ACCOUNT env var and no serviceAccountKey.json found.");
    process.exit(1);
  }
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

// ── Express Setup ─────────────────────────────────────────────────────────────
const app  = express();
const PORT = process.env.PORT || 4000;

// Allow ALL origins so any device / domain can reach the API
app.use(cors({ origin: "*" }));
app.use(express.json());

// Rate limiting
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });
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

// ── Valid statuses ────────────────────────────────────────────────────────────
// "notstarted" = session created but doctor hasn't begun serving yet
const VALID_STATUSES = ["notstarted", "normal", "emergency", "nopatient", "break"];

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
    const snap = await db.collection("appointments").doc(req.params.id).get();
    if (!snap.exists) return res.status(404).json({ error: "Not found" });
    res.json({ id: snap.id, ...snap.data() });
  } catch (e) {
    res.status(500).json({ error: "Failed to fetch appointment" });
  }
});

// ── DOCTOR: Create appointment ────────────────────────────────────────────────
app.post("/api/appointments", verifyToken, async (req, res) => {
  const { title, startTime, totalTokens, notes } = req.body;

  // Only title is required — startTime is optional display info
  if (!title || !title.trim()) {
    return res.status(400).json({ error: "title is required" });
  }

  // Safe token count parsing — default 20 if missing/invalid
  const tokenCount = Number(totalTokens);
  const safeTokens = (!tokenCount || isNaN(tokenCount))
    ? 20
    : Math.min(Math.max(Math.floor(tokenCount), 1), 500);

  try {
    // Enforce: one active appointment per doctor
    const existing = await db
      .collection("appointments")
      .where("doctorId", "==", req.user.uid)
      .where("active", "==", true)
      .get();

    if (!existing.empty) {
      return res.status(409).json({
        error: "You already have an active session. End it before creating a new one.",
      });
    }

    // Firebase token fields: display_name (Admin SDK) or name (standard JWT)
    const doctorName  = req.user.display_name || req.user.name || "Doctor";
    const doctorPhoto = req.user.picture || "";

    const docRef = db.collection("appointments").doc();
    const appointment = {
      doctorId:          req.user.uid,
      doctorName:        doctorName,
      doctorPhoto:       doctorPhoto,
      doctorWaitlessId:  req.body.doctorWaitlessId ? String(req.body.doctorWaitlessId).slice(0,20) : "",
      title:             title.trim(),
      startTime:         startTime || "",
      totalTokens:       safeTokens,
      currentToken:      1,
      status:            "notstarted",
      instruction:       "",
      active:            true,
      notes:             notes ? String(notes).trim() : "",
      location:          req.body.location ? String(req.body.location).slice(0,100) : "",
      createdAt:         admin.firestore.FieldValue.serverTimestamp(),
    };

    await docRef.set(appointment);

    // Return the id so frontend can use it immediately
    res.status(201).json({ id: docRef.id, ...appointment });
  } catch (e) {
    console.error("Create appointment error:", e);
    res.status(500).json({ error: "Failed to create appointment" });
  }
});

// ── DOCTOR: Update appointment (token, status, instruction) ──────────────────
app.patch("/api/appointments/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  const { status, currentToken, instruction } = req.body;

  try {
    const docRef = db.collection("appointments").doc(id);
    const snap   = await docRef.get();

    if (!snap.exists) return res.status(404).json({ error: "Not found" });

    const data = snap.data();

    if (data.doctorId !== req.user.uid) {
      return res.status(403).json({ error: "Forbidden: Not your appointment" });
    }

    const updates = {};

    // Status — now includes "notstarted" in the valid list
    if (status !== undefined) {
      if (!VALID_STATUSES.includes(status)) {
        return res.status(400).json({ error: `Invalid status. Must be one of: ${VALID_STATUSES.join(", ")}` });
      }
      updates.status = status;
    }

    // Token navigation
    if (currentToken !== undefined) {
      const token = Number(currentToken);
      if (isNaN(token) || token < 1 || token > data.totalTokens) {
        return res.status(400).json({ error: "currentToken out of range" });
      }
      updates.currentToken = token;
    }

    // Broadcast instruction
    if (instruction !== undefined) {
      updates.instruction = String(instruction).slice(0, 300);
    }

    updates.updatedAt = admin.firestore.FieldValue.serverTimestamp();
    await docRef.update(updates);

    res.json({ success: true, updates });
  } catch (e) {
    console.error("Update appointment error:", e);
    res.status(500).json({ error: "Failed to update appointment" });
  }
});

// ── DOCTOR: End appointment session ──────────────────────────────────────────
app.delete("/api/appointments/:id", verifyToken, async (req, res) => {
  const { id } = req.params;

  try {
    const docRef = db.collection("appointments").doc(id);
    const snap   = await docRef.get();

    if (!snap.exists) return res.status(404).json({ error: "Not found" });
    if (snap.data().doctorId !== req.user.uid) {
      return res.status(403).json({ error: "Forbidden" });
    }

    await docRef.update({
      active:  false,
      endedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.json({ success: true, message: "Session ended." });
  } catch (e) {
    console.error("End session error:", e);
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
  console.log(`   CORS: open (all origins allowed)`);
  console.log(`   Valid statuses: ${VALID_STATUSES.join(", ")}\n`);
});

module.exports = app;
