// server.js – Nano Host Backend
// npm init -y && npm install express sqlite3 bcryptjs jsonwebtoken cors
// node server.js

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'nano-host-secret-2026-change-in-production';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname))); // Serviert index.html

// SQLite DB
const db = new sqlite3.Database('./nanohost.db', (err) => {
  if (err) console.error('❌ DB Error:', err);
  else console.log('✅ SQLite verbunden: nanohost.db');
});

// Tabelle erstellen
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  plan TEXT DEFAULT 'Free',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// ===== AUTH ROUTES =====

// REGISTRIERUNG
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: 'Alle Felder benötigt' });
    if (username.length < 3) return res.status(400).json({ error: 'Username mind. 3 Zeichen' });
    if (password.length < 6) return res.status(400).json({ error: 'Passwort mind. 6 Zeichen' });

    const hashed = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
      [username.toLowerCase(), email.toLowerCase(), hashed],
      function (err) {
        if (err) {
          if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'Username oder E-Mail bereits vergeben' });
          return res.status(500).json({ error: 'Serverfehler' });
        }
        res.status(201).json({ message: 'Registrierung erfolgreich', userId: this.lastID });
      }
    );
  } catch (e) { res.status(500).json({ error: 'Fehler bei Registrierung' }); }
});

// LOGIN
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username=? OR email=?', [username.toLowerCase(), username.toLowerCase()], async (err, user) => {
      if (err) return res.status(500).json({ error: 'Serverfehler' });
      if (!user) return res.status(401).json({ error: 'Benutzer nicht gefunden' });
      
      const match = await bcrypt.compare(password, user.password);
      if (!match) return res.status(401).json({ error: 'Falsches Passwort' });

      const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
      res.json({ message: 'Login erfolgreich', token, user: { id: user.id, username: user.username, plan: user.plan } });
    });
  } catch (e) { res.status(500).json({ error: 'Login fehlgeschlagen' }); }
});

// USER PROFIL (geschützt)
app.get('/api/user', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Token benötigt' });
  
  const token = auth.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Ungültiger Token' });
    db.get('SELECT id, username, email, plan, created_at FROM users WHERE id=?', [decoded.id], (e, user) => {
      if (!user) return res.status(404).json({ error: 'User nicht gefunden' });
      res.json({ user });
    });
  });
});

// TARIF WECHSELN (geschützt)
app.put('/api/user/plan', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Token benötigt' });
  const token = auth.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Ungültiger Token' });
    const { plan } = req.body;
    if (!['Free', 'Ultra', 'Nano', 'GOD'].includes(plan)) return res.status(400).json({ error: 'Ungültiger Tarif' });
    db.run('UPDATE users SET plan=? WHERE id=?', [plan, decoded.id], function(e) {
      if (e) return res.status(500).json({ error: 'Fehler' });
      res.json({ message: `Tarif zu ${plan} gewechselt` });
    });
  });
});

// HEALTH
app.get('/api/health', (req, res) => res.json({ status: 'ok', uptime: process.uptime() }));

// START
app.listen(PORT, () => {
  console.log(`\n🚀 Nano Host Backend läuft auf http://localhost:${PORT}`);
  console.log(`📊 Health: http://localhost:${PORT}/api/health`);
  console.log(`🌐 Frontend: http://localhost:${PORT}/index.html\n`);
});
