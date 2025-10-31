const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

// Database connection
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
}).promise();

// Validation middleware
const validateLogin = [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 })
];

const validateSignup = [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 })
        .matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9]).{6,}$/)
        .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character')
];

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Authentication required' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Login endpoint
router.post('/login', validateLogin, async (req, res) => {
    try {
        // Check validation results
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, password } = req.body;
        
        const [rows] = await pool.query('SELECT * FROM rutuja_sup WHERE email_sup = ?', [email]);
        
        if (rows.length === 0) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const user = rows[0];
        const isValidPassword = await bcrypt.compare(password, user.pass_sup);

        if (!isValidPassword) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { id: user.id, email: user.email_sup },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Set HTTP-only cookie with token
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });

        res.json({ 
            message: 'Login successful',
            user: {
                id: user.id,
                email: user.email_sup
            },
            token
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Signup endpoint
router.post('/signup', validateSignup, async (req, res) => {
    try {
        // Check validation results
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, password } = req.body;
        
        // Check if user already exists
        const [existingUsers] = await pool.query('SELECT * FROM rutuja_sup WHERE email_sup = ?', [email]);
        
        if (existingUsers.length > 0) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);
        
        // Insert new user
        const [result] = await pool.query(
            'INSERT INTO rutuja_sup (email_sup, pass_sup, created_at) VALUES (?, ?, NOW())',
            [email, hashedPassword]
        );

        // Generate JWT token for automatic login
        const token = jwt.sign(
            { id: result.insertId, email },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({ 
            message: 'User created successfully',
            user: {
                id: result.insertId,
                email
            },
            token
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Logout endpoint
router.post('/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: 'Logged out successfully' });
});

// Get current user endpoint
router.get('/me', authenticateToken, async (req, res) => {
    try {
        const [user] = await pool.query(
            'SELECT id, email_sup, created_at FROM rutuja_sup WHERE id = ?',
            [req.user.id]
        );

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json({ user });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Password reset request
router.post('/forgot-password', [
    body('email').isEmail().normalizeEmail()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email } = req.body;
        
        // Generate reset token
        const resetToken = jwt.sign(
            { email },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        // Store reset token in database
        await pool.query(
            'UPDATE rutuja_sup SET reset_token = ?, reset_token_expires = DATE_ADD(NOW(), INTERVAL 1 HOUR) WHERE email_sup = ?',
            [resetToken, email]
        );

        // TODO: Send password reset email
        // This would typically involve setting up an email service

        res.json({ message: 'Password reset instructions sent to email' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

module.exports = router; 