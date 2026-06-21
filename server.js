const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();
app.use(express.json());

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function setupDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS conversations (
      id SERIAL PRIMARY KEY,
      name TEXT,
      message TEXT,
      platform TEXT,
      date TEXT,
      user_id INTEGER
    )
  `);
  await db.query(`
    CREATE TABLE IF NOT EXISTS agents (
      id SERIAL PRIMARY KEY,
      name TEXT,
      role TEXT
    )
  `);
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE,
      password TEXT,
      name TEXT
    )
  `);
}

setupDB().catch(console.error);

const JWT_SECRET = process.env.JWT_SECRET || "secret-key";

const requireAuth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "محتاج تسجل دخول" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: "الـ token غلط" });
  }
};

app.get("/", (req, res) => {
  res.json({ message: "السيرفر شغال بنجاح" });
});

app.get("/api/conversations", requireAuth, async (req, res) => {
  const result = await db.query(
    "SELECT * FROM conversations WHERE user_id = $1 ORDER BY id DESC",
    [req.user.id]
  );
  res.json(result.rows);
});

app.post("/api/conversations", requireAuth, async (req, res) => {
  const { name, message, platform, date } = req.body;
  const result = await db.query(
    "INSERT INTO conversations (name, message, platform, date, user_id) VALUES ($1, $2, $3, $4, $5) RETURNING *",
    [name, message, platform, date, req.user.id]
  );
  res.json(result.rows[0]);
});

app.get("/api/agents", requireAuth, async (req, res) => {
  const result = await db.query("SELECT * FROM agents");
  res.json(result.rows);
});

app.post("/api/agents", requireAuth, async (req, res) => {
  const { name, role } = req.body;
  const result = await db.query(
    "INSERT INTO agents (name, role) VALUES ($1, $2) RETURNING *",
    [name, role]
  );
  res.json(result.rows[0]);
});

app.post("/api/register", async (req, res) => {
  const { email, password, name } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  try {
    const result = await db.query(
      "INSERT INTO users (email, password, name) VALUES ($1, $2, $3) RETURNING *",
      [email, hashed, name]
    );
    res.json({ message: "تم التسجيل", id: result.rows[0].id });
  } catch {
    res.status(400).json({ message: "الإيميل موجود بالفعل" });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
  const user = result.rows[0];
  if (!user) return res.status(401).json({ message: "بيانات غلط" });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ message: "بيانات غلط" });
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, name: user.name });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("السيرفر شغال على البورت " + PORT);
});