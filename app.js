const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const db = new sqlite3.Database('./gym-attendance.db');

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'gym_secret_key',
  resave: false,
  saveUninitialized: true,
}));

app.set('view engine', 'ejs');

// Create tables
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT,
  role TEXT
)`);

db.run(`CREATE TABLE IF NOT EXISTS attendance (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  date TEXT,
  time TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id)
)`);

// 🔐 Hardcoded admin user creation
const defaultAdmin = {
  username: 'admin',
  password: 'admin',
  role: 'admin',
};

db.get('SELECT * FROM users WHERE username = ?', [defaultAdmin.username], async (err, row) => {
  if (!row) {
    const hashedPassword = await bcrypt.hash(defaultAdmin.password, 10);
    db.run(
      'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
      [defaultAdmin.username, hashedPassword, defaultAdmin.role],
      (err) => {
        if (err) console.error('Error creating default admin:', err.message);
        else console.log('✅ Default admin created (username: admin, password: admin)');
      }
    );
  }
});

// Routes
app.get('/', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.redirect(req.session.user.role === 'admin' ? '/admin' : '/dashboard');
});

app.get('/login', (req, res) => {
  res.render('login', { message: null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (user && await bcrypt.compare(password, user.password)) {
      req.session.user = user;
      return res.redirect(user.role === 'admin' ? '/admin' : '/dashboard');
    } else {
      return res.render('login', { message: 'Invalid credentials' });
    }
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});



app.get('/dashboard', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'user') {
      return res.redirect('/login');
    }
  
    const userId = req.session.user.id;
    const username = req.session.user.username;
  
    db.all('SELECT date, time FROM attendance WHERE user_id = ?', [userId], (err, rows) => {
      if (err) {
        console.error('Error loading attendance records:', err.message);
        return res.send('Error loading attendance records');
      }
  
      res.render('dashboard', {
        username,
        logs: rows
      });
    });
  });
  
  
app.get('/profile', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'user') return res.redirect('/login');
  res.render('profile', { user: req.session.user });
});

app.post('/punch', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const { id } = req.session.user;
  const now = new Date();
  const date = now.toISOString().split('T')[0];
  const time = now.toTimeString().split(' ')[0];

  db.run('INSERT INTO attendance (user_id, date, time) VALUES (?, ?, ?)', [id, date, time], (err) => {
    res.redirect('/dashboard');
  });
});

app.get('/admin', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') return res.redirect('/login');
  db.all('SELECT * FROM users', (err, users) => {
    db.all(`SELECT attendance.id, users.username, attendance.date, attendance.time
            FROM attendance JOIN users ON attendance.user_id = users.id`, (err, records) => {
      res.render('admin', { users, records });
    });
  });
});

app.post('/create-user', async (req, res) => {
  const { username, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  db.run('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hashedPassword, role], (err) => {
    res.redirect('/admin');
  });
});
app.get('/admin-dashboard', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') return res.redirect('/login');
    const search = req.query.search || '';
    const sql = `
      SELECT u.id, u.username,
      (
        SELECT date || ' ' || time 
        FROM attendance a 
        WHERE a.user_id = u.id 
        ORDER BY a.id DESC LIMIT 1
      ) as lastPunch
      FROM users u
      WHERE u.username LIKE ?
    `;
    db.all(sql, [`%${search}%`], (err, users) => {
      res.render('admin-dashboard', { users });
    });
  });
  
  
  // Per-user attendance history
  app.get('/admin/user/:id', (req, res) => {
    const userId = req.params.id;
    db.get("SELECT username FROM users WHERE id = ?", [userId], (err, user) => {
      if (err || !user) return res.send("User not found");
  
      db.all("SELECT date, time FROM attendance WHERE user_id = ?", [userId], (err, logs) => {
        if (err) return res.send("Error fetching logs");
  
        res.render('user-history', { username: user.username, logs, userId }); // ← Pass userId here
      });
    });
  });
  
  app.get('/admin/export/pdf/:id', (req, res) => {
    const userId = req.params.id;
    db.get("SELECT username FROM users WHERE id = ?", [userId], (err, user) => {
      if (err || !user) return res.send("User not found");
  
      db.all("SELECT date, time FROM attendance WHERE user_id = ?", [userId], (err, rows) => {
        const doc = new PDFDocument();
        res.setHeader('Content-disposition', `attachment; filename=${user.username}-attendance.pdf`);
        res.setHeader('Content-type', 'application/pdf');
        doc.pipe(res);
  
        doc.fontSize(20).text(`${user.username}'s Attendance Report`, { align: 'center' });
        doc.moveDown();
        rows.forEach(log => {
          doc.fontSize(14).text(`Date: ${log.date}  |  Time: ${log.time}`);
        });
        doc.end();
      });
    });
  });
  const { Parser } = require('json2csv');
  const fs = require('fs');
  const PDFDocument = require('pdfkit');
  
  // Export CSV
  app.get('/admin/export/csv/:id', (req, res) => {
    const userId = req.params.id;
    db.all("SELECT date, time FROM attendance WHERE user_id = ?", [userId], (err, rows) => {
      if (err) return res.send("Error generating CSV");
      const csv = new Parser({ fields: ['date', 'time'] }).parse(rows);
      res.setHeader('Content-disposition', 'attachment; filename=attendance.csv');
      res.set('Content-Type', 'text/csv');
      res.status(200).send(csv);
    });
  });
    

// Start server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`🏋️ Gym Attendance App running at http://localhost:${PORT}`);
});
