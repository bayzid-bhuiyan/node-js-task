require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());
app.use(cors());

// Database Connection
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

// ---------------------------------------------------------
//  FIXED EMAIL TRANSPORTER (Localhost Method)
// ---------------------------------------------------------
const transporter = nodemailer.createTransport({
    host: 'localhost',      // CHANGED: Connect internally to bypass firewall
    port: 587,              // Standard port for submission
    secure: false,          // False for TLS
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    tls: {
        rejectUnauthorized: false // Ignore certificate mismatch on localhost
    },
    debug: true, 
    logger: true 
});

// MIDDLEWARE
const authenticateUser = async (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).send("Access Denied");

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        const [rows] = await pool.execute('SELECT status FROM users WHERE id = ?', [verified.id]);
        
        if (rows.length === 0 || rows[0].status === 'blocked') {
            return res.status(403).json({ message: 'User blocked or deleted' });
        }
        
        req.user = verified;
        next();
    } catch (err) {
        res.status(401).send("Invalid Token");
    }
};

// 1. REGISTER (With Logs & Rollback)
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        console.log(`[1/4] Registration request received for: ${email}`); 

        const hash = await bcrypt.hash(password, 10);
        
        // 1. Insert User (Status: unverified)
        const [result] = await pool.execute(
            'INSERT INTO users (name, email, password_hash, last_login, status) VALUES (?, ?, ?, NOW(), "unverified")',
            [name, email, hash]
        );
        console.log(`[2/4] Database Insert Success! User ID: ${result.insertId}`); 

        // 2. Try to Send Email
        const verifyLink = `${req.protocol}://${req.get('host')}/api/verify/${result.insertId}`;
        
        console.log(`[3/4] Attempting to send email to ${email} via Localhost...`); 
        
        try {
            await transporter.sendMail({
                from: `"Task 4 App" <${process.env.EMAIL_USER}>`, 
                to: email,
                subject: 'Verify your account',
                html: `<p>Hello ${name},</p><p>Click <a href="${verifyLink}">here</a> to activate your account.</p>`
            });
            
            console.log(`[4/4] SUCCESS: Email sent to ${email}`); 
            res.status(201).json({ message: "Registration successful! Please check your email." });

        } catch (emailErr) {
            console.error(`[ERROR] Email Sending Failed: ${emailErr.message}`); 
            
            // Delete user if email fails (Rollback)
            await pool.execute('DELETE FROM users WHERE id = ?', [result.insertId]);
            console.log(`[ROLLBACK] User ${result.insertId} deleted from DB because email failed.`);
            
            return res.status(500).json({ message: "Error: Email could not be sent. User not saved." });
        }

    } catch (err) {
        console.error("[ERROR] Database Error:", err.message);
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: "Email already exists" });
        }
        res.status(500).json({ message: err.message });
    }
});

// 2. VERIFY ROUTE
app.get('/api/verify/:id', async (req, res) => {
    try {
        await pool.execute(
            'UPDATE users SET status = "active" WHERE id = ? AND status = "unverified"',
            [req.params.id]
        );
        res.send("<h1>Account Verified!</h1><p>You can now login.</p>");
    } catch (err) {
        res.status(500).send("Verification failed");
    }
});

// 3. LOGIN
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const [users] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    
    if (users.length === 0) return res.status(404).send("User not found");
    const user = users[0];

    if (user.status === 'blocked') return res.status(403).send("User is blocked");

    const validPass = await bcrypt.compare(password, user.password_hash);
    if (!validPass) return res.status(400).send("Invalid password");

    await pool.execute('UPDATE users SET last_login = NOW() WHERE id = ?', [user.id]);

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET);
    res.json({ token, name: user.name });
});

// 4. GET USERS
app.get('/api/users', authenticateUser, async (req, res) => {
    const [users] = await pool.execute('SELECT id, name, email, last_login, status FROM users ORDER BY last_login DESC');
    res.json(users);
});

// 5. ADMIN ACTIONS
app.post('/api/admin/action', authenticateUser, async (req, res) => {
    const { userIds, action } = req.body;

    if (action === 'deleteUnverified') {
        await pool.execute('DELETE FROM users WHERE status = "unverified"');
        return res.send("Unverified users deleted");
    }

    if (!userIds || userIds.length === 0) return res.status(400).send("No users selected");

    let query = '';
    if (action === 'block') query = 'UPDATE users SET status = "blocked" WHERE id IN (?)';
    if (action === 'unblock') query = 'UPDATE users SET status = "active" WHERE id IN (?)';
    if (action === 'delete') query = 'DELETE FROM users WHERE id IN (?)';

    if (query) {
        await pool.query(query, [userIds]);
        res.send("Action completed");
    } else {
        res.status(400).send("Invalid action");
    }
});

app.use(express.static('public')); 

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running`));