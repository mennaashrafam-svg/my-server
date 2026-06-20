const express = require("express");
const Database = require("better-sqlite3");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
const db = new Database("mydata.db");

// جداول قاعدة البيانات
db.exec(`
  CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    message TEXT,
    platform TEXT,
    date TEXT
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    role TEXT
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    name TEXT
  )
`);

app.use(express.json());

// التحقق من الـ token
const requireAuth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "محتاج تسجل دخول" });
  try {
    req.user = jwt.verify(token, "secret-key");
    next();
  } catch {
    res.status(401).json({ message: "الـ token غلط" });
  }
};

// المحادثات
app.get("/api/conversations", requireAuth, (req, res) => {
  const conversations = db.prepare("SELECT * FROM conversations").all();
  res.json(conversations);
});

app.post("/api/conversations", requireAuth, (req, res) => {
  const { name, message, platform, date } = req.body;
  const result = db.prepare(
    "INSERT INTO conversations (name, message, platform, date) VALUES (?, ?, ?, ?)"
  ).run(name, message, platform, date);
  res.json({ id: result.lastInsertRowid, name, message, platform, date });
});

// الموظفين
app.get("/api/agents", requireAuth, (req, res) => {
  const agents = db.prepare("SELECT * FROM agents").all();
  res.json(agents);
});

app.post("/api/agents", requireAuth, (req, res) => {
  const { name, role } = req.body;
  const result = db.prepare(
    "INSERT INTO agents (name, role) VALUES (?, ?)"
  ).run(name, role);
  res.json({ id: result.lastInsertRowid, name, role });
});

// تسجيل مستخدم جديد
app.post("/api/register", async (req, res) => {
  const { email, password, name } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  try {
    const result = db.prepare(
      "INSERT INTO users (email, password, name) VALUES (?, ?, ?)"
    ).run(email, hashed, name);
    res.json({ message: "تم التسجيل", id: result.lastInsertRowid });
  } catch {
    res.status(400).json({ message: "الإيميل موجود بالفعل" });
  }
});

// تسجيل الدخول
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
  if (!user) return res.status(401).json({ message: "بيانات غلط" });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ message: "بيانات غلط" });
  const token = jwt.sign({ id: user.id, email: user.email }, "secret-key", { expiresIn: "7d" });
  res.json({ token, name: user.name });
});

app.listen(3000, () => {
  console.log("السيرفر شغال على http://localhost:3000");
});