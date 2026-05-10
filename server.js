require('dotenv').config();
const express = require('express');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');
const { Resend } = require('resend');

const app = express();
const PORT = process.env.PORT || 3000;

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY
);

// ── Email notifications (Resend) ─────────────────────────────────────────────
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;
// Trim defensively — env values pasted via the Vercel CLI sometimes carry a
// trailing newline that breaks SMTP From/To parsing.
const RESEND_FROM = (process.env.RESEND_FROM || 'Forever Family <onboarding@resend.dev>').trim();
const RESEND_TO   = (process.env.RESEND_TO   || '').trim();

// Fire-and-forget email helper. Never blocks or breaks the form response.
function sendNotification({ subject, html, replyTo }) {
    if (!resend || !RESEND_TO) return;
    const payload = { from: RESEND_FROM, to: [RESEND_TO], subject, html };
    if (replyTo) payload.reply_to = replyTo;
    Promise.resolve().then(async () => {
        try {
            const { error } = await resend.emails.send(payload);
            if (error) console.error('[EMAIL] Resend error:', error.message || error);
        } catch (e) {
            console.error('[EMAIL] Send failed:', e.message);
        }
    });
}

function escapeHtml(s) {
    if (s === null || s === undefined) return '';
    return String(s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;')
        .replace(/\n/g, '<br>');
}

const _rl = new Map();
function rateLimit(ip, max = 10, windowMs = 60000) {
    const now = Date.now();
    const e = _rl.get(ip) || { n: 0, t: now + windowMs };
    if (now > e.t) { e.n = 0; e.t = now + windowMs; }
    e.n++;
    _rl.set(ip, e);
    return e.n > max;
}

const fs = require('fs');

app.use(express.json());
app.use('/images', express.static(path.join(__dirname, 'images')));
app.use(express.static(__dirname));

// Explicit route ensures tailwind.css is served with correct MIME type
// even if express.static can't find it in the Lambda bundle
app.get('/tailwind.css', (req, res) => {
    const cssPath = path.join(__dirname, 'tailwind.css');
    res.setHeader('Content-Type', 'text/css');
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    res.sendFile(cssPath);
});

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

    sendNotification({
        subject: `[Forever Family] New signup — ${name}`,
        replyTo: email,
        html: `
            <h2 style="font-family:sans-serif">New signup</h2>
            <p style="font-family:sans-serif"><strong>Name:</strong> ${escapeHtml(name)}<br>
            <strong>Email:</strong> ${escapeHtml(email)}<br>
            <strong>Phone:</strong> ${escapeHtml(phone || '—')}<br>
            <strong>City:</strong> ${escapeHtml(city)}<br>
            <strong>Interest:</strong> ${escapeHtml(interest)}</p>
            <p style="font-family:sans-serif"><strong>Message:</strong><br>${escapeHtml(message || '—')}</p>
        `
    });

    console.log(`[JOIN] ${name} <${email}> — ${interest}`);
    res.json({ success: true });
});

// ─── GET /api/testimonials (public) ─────────────────────────────────────────
app.get('/api/testimonials', async (req, res) => {
    const { data, error } = await supabase
        .from('testimonials')
        .select('*')
        .order('position', { ascending: true })
        .order('created_at', { ascending: false });

    if (error) {
        // If the table isn't created yet, return empty list rather than 500
        // so the page falls back to its static seed posts.
        return res.json({ testimonials: [] });
    }
    res.json({ testimonials: data || [] });
});

// ─── POST /api/admin/testimonials (admin) ───────────────────────────────────
app.post('/api/admin/testimonials', async (req, res) => {
    const auth = req.headers['x-admin-key'];
    if (auth !== process.env.ADMIN_KEY && process.env.NODE_ENV !== 'development') {
        return res.status(403).json({ error: 'Forbidden.' });
    }
    const { name, role_label, date_label, image_url, headline, body, pull_quote, position } = req.body;
    if (!name || !body) return res.status(400).json({ error: 'Name and body are required.' });

    const { data, error } = await supabase.from('testimonials').insert({
        name, role_label: role_label || '', date_label: date_label || '',
        image_url: image_url || '', headline: headline || '', body,
        pull_quote: pull_quote || '', position: parseInt(position) || 0
    }).select().single();

    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true, testimonial: data });
});

// ─── PUT /api/admin/testimonials/:id (admin) ────────────────────────────────
app.put('/api/admin/testimonials/:id', async (req, res) => {
    const auth = req.headers['x-admin-key'];
    if (auth !== process.env.ADMIN_KEY && process.env.NODE_ENV !== 'development') {
        return res.status(403).json({ error: 'Forbidden.' });
    }
    const allowed = ['name','role_label','date_label','image_url','headline','body','pull_quote','position'];
    const update = {};
    allowed.forEach(k => { if (req.body[k] !== undefined) update[k] = req.body[k]; });

    const { data, error } = await supabase.from('testimonials')
        .update(update).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    if (!data) return res.status(404).json({ error: 'Not found.' });
    res.json({ success: true, testimonial: data });
});

// ─── DELETE /api/admin/testimonials/:id (admin) ─────────────────────────────
app.delete('/api/admin/testimonials/:id', async (req, res) => {
    const auth = req.headers['x-admin-key'];
    if (auth !== process.env.ADMIN_KEY && process.env.NODE_ENV !== 'development') {
        return res.status(403).json({ error: 'Forbidden.' });
    }
    const { error } = await supabase.from('testimonials').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
});

// ─── POST /api/feedback ─────────────────────────────────────────────────────
app.post('/api/feedback', async (req, res) => {
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    if (rateLimit(ip, 10)) return res.status(429).json({ error: 'Too many requests. Please try again later.' });

    const { name, message } = req.body;
    if (!name || !message) {
        return res.status(400).json({ error: 'Name and message are required.' });
    }

    const { error } = await supabase.from('feedback').insert({
        name: String(name).trim().slice(0, 120),
        message: String(message).trim().slice(0, 2000)
    });

    if (error) {
        console.error('[FEEDBACK] Supabase error:', error.message);
        return res.status(500).json({ error: 'Failed to save feedback.' });
    }

    sendNotification({
        subject: `[Forever Family] Feedback from ${name}`,
        html: `
            <h2 style="font-family:sans-serif">New feedback</h2>
            <p style="font-family:sans-serif"><strong>From:</strong> ${escapeHtml(name)}</p>
            <p style="font-family:sans-serif"><strong>Message:</strong><br>${escapeHtml(message)}</p>
        `
    });

    console.log(`[FEEDBACK] ${name}: ${String(message).slice(0, 80)}`);
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

    const urgencyLabel = (urgency === 'urgent') ? '🚨 URGENT' : (urgency === 'asap' ? '⚠️ ASAP' : 'Standard');
    sendNotification({
        subject: `[Forever Family · G-LINE · ${urgencyLabel}] Referral re: ${referralName}`,
        html: `
            <h2 style="font-family:sans-serif">G-Line referral — ${urgencyLabel}</h2>
            <p style="font-family:sans-serif"><strong>Reported by:</strong> ${escapeHtml(name)}<br>
            <strong>Concerning:</strong> ${escapeHtml(referralName)}<br>
            <strong>Relationship:</strong> ${escapeHtml(relationship || '—')}<br>
            <strong>Urgency:</strong> ${escapeHtml(urgency || 'unspecified')}</p>
            <p style="font-family:sans-serif"><strong>Situation:</strong><br>${escapeHtml(situation)}</p>
        `
    });

    console.log(`[G-LINE] ${name} → re: ${referralName} (${urgency})`);
    res.json({ success: true });
});

// ─── POST /api/portal-login ──────────────────────────────────────────────────
app.post('/api/portal-login', async (req, res) => {
    const { email, code } = req.body;
    if (!email || !code) {
        return res.status(400).json({ error: 'Email and access code required.' });
    }

    const submittedEmail = email.toLowerCase().trim();

    const { data, error } = await supabase
        .from('members')
        .select('*')
        .eq('code', code.toUpperCase().trim())
        .single();

    if (error || !data) {
        return res.status(401).json({ error: 'Invalid access code.' });
    }

    // If the row already has an email bound to this code, require it to match.
    // Otherwise (first login for that code) bind the supplied email to the row.
    if (data.email && data.email.toLowerCase().trim() !== submittedEmail) {
        return res.status(401).json({ error: 'Email and access code do not match.' });
    }

    if (!data.email) {
        await supabase.from('members').update({ email: submittedEmail }).eq('code', code.toUpperCase().trim());
    }

    const { tier } = data;
    const payload = JSON.stringify({ email: submittedEmail, tier, memberSince: data.created_at, issued: Date.now(), exp: Date.now() + 86400000 });
    const token = Buffer.from(payload).toString('base64');

    console.log(`[PORTAL] ${submittedEmail} logged in as ${tier}`);
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

// ─── GET /api/admin/data (one-shot dashboard fetch) ─────────────────────────
app.get('/api/admin/data', async (req, res) => {
    const auth = req.headers['x-admin-key'];
    if (auth !== process.env.ADMIN_KEY && process.env.NODE_ENV !== 'development') {
        return res.status(403).json({ error: 'Forbidden.' });
    }

    // Each query is allowed to fail independently (e.g. the feedback table may
    // not have been created yet) — we surface what we can and report the rest as empty.
    const safe = async (p) => {
        try {
            const { data, error } = await p;
            return error ? [] : (data || []);
        } catch (_) { return []; }
    };

    const [submissions, referrals, feedback, quiz] = await Promise.all([
        safe(supabase.from('submissions').select('*').order('created_at', { ascending: false })),
        safe(supabase.from('referrals').select('*').order('created_at', { ascending: false })),
        safe(supabase.from('feedback').select('*').order('created_at', { ascending: false })),
        safe(supabase.from('quiz_results').select('*').order('created_at', { ascending: false }))
    ]);

    res.json({
        submissions, referrals, feedback, quiz,
        stats: {
            submissions: submissions.length,
            referrals: referrals.length,
            feedback: feedback.length,
            quiz: quiz.length
        }
    });
});

// ─── POST /api/quiz-results ───────────────────────────────────────────────────
app.post('/api/quiz-results', async (req, res) => {
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    if (rateLimit(ip, 30)) return res.status(429).json({ error: 'Too many requests. Please try again later.' });

    const { sessionId, module, score, total, label, durationSeconds } = req.body;
    if (!module || score === undefined || !label) {
        return res.status(400).json({ error: 'Required fields missing.' });
    }

    const row = {
        session_id: sessionId || null,
        module,
        score: parseInt(score) || 0,
        total: parseInt(total) || 10,
        label
    };
    const dur = parseInt(durationSeconds);
    if (Number.isFinite(dur) && dur >= 0) row.duration_seconds = dur;

    let { error } = await supabase.from('quiz_results').insert(row);
    // If the duration_seconds column hasn't been added yet, retry without it
    // so the rest of the row still saves.
    if (error && /duration_seconds/.test(error.message)) {
        delete row.duration_seconds;
        ({ error } = await supabase.from('quiz_results').insert(row));
    }

    if (error) {
        console.error('[QUIZ] Supabase error:', error.message);
        return res.status(500).json({ error: 'Failed to save result.' });
    }

    console.log(`[QUIZ] ${module}: ${score}/${total} (${label})`);
    res.json({ success: true });
});

// ─── Catch-all: serve HTML pages ─────────────────────────────────────────────
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
