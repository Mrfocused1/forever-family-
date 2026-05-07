require('dotenv').config();
const express = require('express');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY
);

const _rl = new Map();
function rateLimit(ip, max = 10, windowMs = 60000) {
    const now = Date.now();
    const e = _rl.get(ip) || { n: 0, t: now + windowMs };
    if (now > e.t) { e.n = 0; e.t = now + windowMs; }
    e.n++;
    _rl.set(ip, e);
    return e.n > max;
}

app.use(express.json());
app.use('/images', express.static(path.join(__dirname, 'images')));
app.use(express.static(__dirname));

// ─── POST /api/join ─────────────────────────────────────────────────────────
app.post('/api/join', async (req, res) => {
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    if (rateLimit(ip, 10)) return res.status(429).json({ error: 'Too many requests. Please try again later.' });

    const { name, email, phone, city, interest, message } = req.body;
    if (!name || !email || !city || !interest) {
        return res.status(400).json({ error: 'Required fields missing.' });
    }

    const { error } = await supabase.from('submissions').insert({
        name, email, phone: phone || '', city, interest, message: message || ''
    });

    if (error) {
        console.error('[JOIN] Supabase error:', error.message);
        return res.status(500).json({ error: 'Failed to save submission.' });
    }

    console.log(`[JOIN] ${name} <${email}> — ${interest}`);
    res.json({ success: true });
});

// ─── POST /api/referral ──────────────────────────────────────────────────────
app.post('/api/referral', async (req, res) => {
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    if (rateLimit(ip, 5)) return res.status(429).json({ error: 'Too many requests. Please try again later.' });

    const { name, referralName, relationship, urgency, situation } = req.body;
    if (!name || !referralName || !situation) {
        return res.status(400).json({ error: 'Required fields missing.' });
    }

    const { error } = await supabase.from('referrals').insert({
        name,
        referral_name: referralName,
        relationship: relationship || '',
        urgency: urgency || 'unspecified',
        situation
    });

    if (error) {
        console.error('[G-LINE] Supabase error:', error.message);
        return res.status(500).json({ error: 'Failed to save referral.' });
    }

    console.log(`[G-LINE] ${name} → re: ${referralName} (${urgency})`);
    res.json({ success: true });
});

// ─── POST /api/portal-login ──────────────────────────────────────────────────
app.post('/api/portal-login', async (req, res) => {
    const { email, code } = req.body;
    if (!email || !code) {
        return res.status(400).json({ error: 'Email and access code required.' });
    }

    const { data, error } = await supabase
        .from('members')
        .select('tier, created_at')
        .eq('code', code.toUpperCase().trim())
        .single();

    if (error || !data) {
        return res.status(401).json({ error: 'Invalid access code. Check your welcome email.' });
    }

    const { tier } = data;

    // Update email on the member record
    await supabase.from('members').update({ email }).eq('code', code.toUpperCase().trim());

    const payload = JSON.stringify({ email, tier, memberSince: data.created_at, issued: Date.now(), exp: Date.now() + 86400000 });
    const token = Buffer.from(payload).toString('base64');

    console.log(`[PORTAL] ${email} logged in as ${tier}`);
    res.json({ success: true, tier, memberSince: data.created_at, token });
});

// ─── GET /api/steps ──────────────────────────────────────────────────────────
app.get('/api/steps', async (req, res) => {
    const { data, error } = await supabase
        .from('steps')
        .select('*')
        .order('created_at', { ascending: false });

    if (error) {
        console.error('[STEPS] Supabase error:', error.message);
        return res.status(500).json({ error: 'Failed to fetch steps.' });
    }

    res.json({ steps: data });
});

// ─── POST /api/steps (admin only) ────────────────────────────────────────────
app.post('/api/steps', async (req, res) => {
    const auth = req.headers['x-admin-key'];
    if (auth !== process.env.ADMIN_KEY && process.env.NODE_ENV !== 'development') {
        return res.status(403).json({ error: 'Forbidden.' });
    }

    const { location, city, area, steppers, status, startTime, endTime, purpose, outcome, coordinatedBy } = req.body;

    const { data, error } = await supabase.from('steps').insert({
        location, city, area,
        steppers: parseInt(steppers) || 0,
        status: status || 'upcoming',
        start_time: startTime,
        end_time: endTime || null,
        purpose,
        outcome: outcome || null,
        coordinated_by: coordinatedBy || 'SOS Team'
    }).select().single();

    if (error) {
        console.error('[STEP] Supabase error:', error.message);
        return res.status(500).json({ error: 'Failed to save step.' });
    }

    console.log(`[STEP] New step added: ${location} (${status})`);
    res.json({ success: true, step: data });
});

// ─── PUT /api/steps/:id (admin only) ─────────────────────────────────────────
app.put('/api/steps/:id', async (req, res) => {
    const auth = req.headers['x-admin-key'];
    if (auth !== process.env.ADMIN_KEY && process.env.NODE_ENV !== 'development') {
        return res.status(403).json({ error: 'Forbidden.' });
    }

    const allowed = ['title','description','location','date','status','image_url','media'];
    const update = {};
    allowed.forEach(k => { if (req.body[k] !== undefined) update[k] = req.body[k]; });

    const { data, error } = await supabase
        .from('steps')
        .update(update)
        .eq('id', req.params.id)
        .select()
        .single();

    if (error) {
        console.error('[STEP] Supabase update error:', error.message);
        return res.status(500).json({ error: 'Failed to update step.' });
    }
    if (!data) return res.status(404).json({ error: 'Step not found.' });

    res.json({ success: true, step: data });
});

// ─── GET /api/submissions (admin view) ───────────────────────────────────────
app.get('/api/submissions', async (req, res) => {
    const auth = req.headers['x-admin-key'];
    if (auth !== process.env.ADMIN_KEY && process.env.NODE_ENV !== 'development') {
        return res.status(403).json({ error: 'Forbidden.' });
    }

    const [{ data: submissions }, { data: referrals }] = await Promise.all([
        supabase.from('submissions').select('*').order('created_at', { ascending: false }),
        supabase.from('referrals').select('*').order('created_at', { ascending: false })
    ]);

    res.json({ submissions: submissions || [], referrals: referrals || [] });
});

// ─── POST /api/quiz-results ───────────────────────────────────────────────────
app.post('/api/quiz-results', async (req, res) => {
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    if (rateLimit(ip, 30)) return res.status(429).json({ error: 'Too many requests. Please try again later.' });

    const { sessionId, module, score, total, label } = req.body;
    if (!module || score === undefined || !label) {
        return res.status(400).json({ error: 'Required fields missing.' });
    }

    const { error } = await supabase.from('quiz_results').insert({
        session_id: sessionId || null,
        module,
        score: parseInt(score) || 0,
        total: parseInt(total) || 10,
        label
    });

    if (error) {
        console.error('[QUIZ] Supabase error:', error.message);
        return res.status(500).json({ error: 'Failed to save result.' });
    }

    console.log(`[QUIZ] ${module}: ${score}/${total} (${label})`);
    res.json({ success: true });
});

// ─── Catch-all: serve HTML pages ─────────────────────────────────────────────
const fs = require('fs');
app.get('*', (req, res) => {
    const cleanPath = req.path.replace(/^\//, '');

    if (cleanPath.endsWith('.html')) {
        const filePath = path.join(__dirname, cleanPath);
        if (fs.existsSync(filePath)) return res.sendFile(filePath);
    }

    if (!cleanPath.includes('.') && cleanPath.length > 0) {
        const htmlPath = path.join(__dirname, cleanPath + '.html');
        if (fs.existsSync(htmlPath)) return res.sendFile(htmlPath);
    }

    res.sendFile(path.join(__dirname, 'index.html'));
});

if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`\n  Forever Family — Server running`);
        console.log(`  Local: http://localhost:${PORT}\n`);
    });
}

module.exports = app;
