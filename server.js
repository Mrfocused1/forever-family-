const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.VERCEL
    ? path.join('/tmp', 'forever-family-data')
    : path.join(__dirname, 'data');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
    try {
        fs.mkdirSync(DATA_DIR, { recursive: true });
    } catch (err) {
        console.error('Failed to create data directory:', err.message);
    }
}

app.use(express.json());
app.use(express.static(__dirname));

// ─── Helpers ───────────────────────────────────────────────────────────────
function readJSON(file) {
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (_) { return []; }
}
function writeJSON(file, data) {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// ─── POST /api/join ─────────────────────────────────────────────────────────
app.post('/api/join', (req, res) => {
    const { name, email, phone, city, interest, message } = req.body;
    if (!name || !email || !city || !interest) {
        return res.status(400).json({ error: 'Required fields missing.' });
    }

    const file = path.join(DATA_DIR, 'submissions.json');
    const submissions = readJSON(file);
    submissions.push({
        id: Date.now(),
        timestamp: new Date().toISOString(),
        name, email, phone: phone || '', city, interest, message: message || ''
    });
    writeJSON(file, submissions);

    console.log(`[JOIN] ${name} <${email}> — ${interest}`);
    res.json({ success: true });
});

// ─── POST /api/referral ──────────────────────────────────────────────────────
app.post('/api/referral', (req, res) => {
    const { name, referralName, relationship, urgency, situation } = req.body;
    if (!name || !referralName || !situation) {
        return res.status(400).json({ error: 'Required fields missing.' });
    }

    const file = path.join(DATA_DIR, 'referrals.json');
    const referrals = readJSON(file);
    referrals.push({
        id: Date.now(),
        timestamp: new Date().toISOString(),
        name, referralName, relationship: relationship || '', urgency: urgency || 'unspecified', situation
    });
    writeJSON(file, referrals);

    console.log(`[G-LINE] ${name} → re: ${referralName} (${urgency})`);
    res.json({ success: true });
});

// ─── POST /api/portal-login ──────────────────────────────────────────────────
// In production: generate per-member codes stored in a database.
// These are demo codes for initial setup — replace with real codes per member.
const TIER_CODES = {
    'FF-BRONZE-2025': 'bronze',
    'FF-SILVER-2025': 'silver',
    'FF-GOLD-2025': 'gold',
    'FF-PLATINUM-2025': 'platinum',
};

app.post('/api/portal-login', (req, res) => {
    const { email, code } = req.body;
    if (!email || !code) {
        return res.status(400).json({ error: 'Email and access code required.' });
    }

    const tier = TIER_CODES[code.toUpperCase().trim()];
    if (!tier) {
        return res.status(401).json({ error: 'Invalid access code. Check your welcome email.' });
    }

    // Simple base64 token — replace with JWT in production
    const payload = JSON.stringify({ email, tier, issued: Date.now(), exp: Date.now() + 86400000 });
    const token = Buffer.from(payload).toString('base64');

    console.log(`[PORTAL] ${email} logged in as ${tier}`);
    res.json({ success: true, tier, token });
});

// ─── GET /api/steps ──────────────────────────────────────────────────────────
app.get('/api/steps', (req, res) => {
    const steps = readJSON(path.join(DATA_DIR, 'steps.json'));
    res.json({ steps });
});

// ─── POST /api/steps (admin only) ────────────────────────────────────────────
app.post('/api/steps', (req, res) => {
    const auth = req.headers['x-admin-key'];
    if (auth !== process.env.ADMIN_KEY && process.env.NODE_ENV !== 'development') {
        return res.status(403).json({ error: 'Forbidden.' });
    }
    const { location, city, area, steppers, status, startTime, endTime, purpose, outcome, coordinatedBy } = req.body;
    const file = path.join(DATA_DIR, 'steps.json');
    const steps = readJSON(file);
    const newStep = {
        id: Date.now(),
        location, city, area,
        steppers: parseInt(steppers) || 0,
        status: status || 'upcoming',
        startTime, endTime: endTime || null,
        purpose, outcome: outcome || null,
        coordinatedBy: coordinatedBy || 'SOS Team'
    };
    steps.push(newStep);
    writeJSON(file, steps);
    console.log(`[STEP] New step added: ${location} (${status})`);
    res.json({ success: true, step: newStep });
});

// ─── PUT /api/steps/:id (admin only) ─────────────────────────────────────────
app.put('/api/steps/:id', (req, res) => {
    const auth = req.headers['x-admin-key'];
    if (auth !== process.env.ADMIN_KEY && process.env.NODE_ENV !== 'development') {
        return res.status(403).json({ error: 'Forbidden.' });
    }
    const file = path.join(DATA_DIR, 'steps.json');
    const steps = readJSON(file);
    const idx = steps.findIndex(s => String(s.id) === String(req.params.id));
    if (idx === -1) return res.status(404).json({ error: 'Step not found.' });
    steps[idx] = { ...steps[idx], ...req.body };
    writeJSON(file, steps);
    res.json({ success: true, step: steps[idx] });
});

// ─── GET /api/submissions (admin view) ───────────────────────────────────────
app.get('/api/submissions', (req, res) => {
    const auth = req.headers['x-admin-key'];
    if (auth !== process.env.ADMIN_KEY && process.env.NODE_ENV !== 'development') {
        return res.status(403).json({ error: 'Forbidden.' });
    }
    res.json({
        submissions: readJSON(path.join(DATA_DIR, 'submissions.json')),
        referrals: readJSON(path.join(DATA_DIR, 'referrals.json'))
    });
});

// ─── Catch-all: serve HTML pages or fallback to index.html ─────────────────
app.get('*', (req, res) => {
    // Check if the path corresponds to an existing HTML file
    const requestedPath = req.path;
    const cleanPath = requestedPath.replace(/^\//, ''); // Remove leading slash
    
    // If requesting a specific .html file that exists, serve it
    if (cleanPath.endsWith('.html')) {
        const filePath = path.join(__dirname, cleanPath);
        if (fs.existsSync(filePath)) {
            return res.sendFile(filePath);
        }
    }
    
    // If requesting a page without extension (e.g., /about), check for .html version
    if (!cleanPath.includes('.') && cleanPath.length > 0) {
        const htmlPath = path.join(__dirname, cleanPath + '.html');
        if (fs.existsSync(htmlPath)) {
            return res.sendFile(htmlPath);
        }
    }
    
    // Otherwise serve index.html (for SPA routing or root path)
    res.sendFile(path.join(__dirname, 'index.html'));
});

if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`\n  Forever Family — Server running`);
        console.log(`  Local: http://localhost:${PORT}\n`);
    });
}

module.exports = app;
