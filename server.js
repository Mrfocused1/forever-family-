require('dotenv').config({ path: '.env.local' });
const express = require('express');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');
const { Resend } = require('resend');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');

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

async function sendOtpEmail(toEmail, code) {
    if (!resend || !RESEND_FROM || !toEmail) {
        console.warn('[AUTH] Resend not configured or no recipient; OTP not sent.');
        return;
    }
    const html = `
<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0d0d0d;font-family:Arial,Helvetica,sans-serif;color:#F5F2EB;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0d0d0d;">
    <tr><td align="center" style="padding:40px 20px;">
      <table role="presentation" width="100%" style="max-width:480px;background:#111;border:1px solid #2A2A2A;border-radius:4px;">
        <tr><td style="padding:32px;">
          <div style="font-size:11px;letter-spacing:3px;text-transform:uppercase;color:#D4AF37;margin-bottom:8px;">FOREVER FAMILY</div>
          <h1 style="margin:0 0 24px;font-family:'Oswald','Arial Narrow',sans-serif;font-size:28px;letter-spacing:1px;text-transform:uppercase;color:#F5F2EB;">Your access code</h1>
          <div style="background:#0d0d0d;border:1px solid #D4AF37;padding:24px;text-align:center;letter-spacing:14px;font-size:36px;font-weight:bold;color:#D4AF37;margin-bottom:24px;font-family:'Courier New',monospace;">${code}</div>
          <p style="margin:0 0 12px;color:#cfcfcf;font-size:14px;line-height:1.6;">Enter this code on the Forever Family portal to sign in.</p>
          <p style="margin:0 0 20px;color:#888;font-size:13px;">Expires in 10 minutes. If you didn't request this, you can safely ignore this email.</p>
          <div style="border-top:1px solid #2A2A2A;padding-top:16px;color:#666;font-size:11px;text-transform:uppercase;letter-spacing:2px;">Forever Family — PIA · FFCA · SOS</div>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
    const text = `Forever Family — Access Code\n\nYour code: ${code}\n\nEnter this on the Forever Family portal to sign in. Code expires in 10 minutes.\n\nIf you didn't request this, ignore this email.`;
    try {
        await resend.emails.send({
            from: RESEND_FROM,
            to: [toEmail],
            subject: `Your Forever Family code: ${code}`,
            html, text
        });
    } catch (e) { console.error('[AUTH] sendOtpEmail failed:', e.message); }
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
app.use(cookieParser());
app.use('/images', express.static(path.join(__dirname, 'images')));

app.get('/learn', (req, res, next) => {
    const token = req.cookies && req.cookies[COOKIE_NAME];
    const payload = token && verifySession(token);
    if (!payload) {
        return res.redirect(302, '/portal?next=/learn');
    }
    next();
});

// Admin page is gated to ADMIN_EMAIL only. No session → /portal?next=/admin.
// Wrong email → /portal?error=not_admin (don't reveal valid admin identity).
app.get('/admin', (req, res, next) => {
    const token = req.cookies && req.cookies[COOKIE_NAME];
    const payload = token && verifySession(token);
    if (!payload) {
        return res.redirect(302, '/portal?next=/admin');
    }
    const sessionEmail = (payload.email || '').toLowerCase().trim();
    if (!ADMIN_EMAIL || sessionEmail !== ADMIN_EMAIL) {
        return res.redirect(302, '/portal?error=not_admin');
    }
    next();
});

app.use(express.static(__dirname));

// Explicit route ensures tailwind.css is served with correct MIME type
// even if express.static can't find it in the Lambda bundle
app.get('/tailwind.css', (req, res) => {
    const cssPath = path.join(__dirname, 'tailwind.css');
    res.setHeader('Content-Type', 'text/css');
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    res.sendFile(cssPath);
});

// ─── AUTH HELPERS ────────────────────────────────────────────────────────────
const JWT_SECRET = process.env.AUTH_JWT_SECRET;
if (!JWT_SECRET) console.warn('[AUTH] AUTH_JWT_SECRET is not set — auth will fail.');

const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').toLowerCase().trim();
if (!ADMIN_EMAIL) console.warn('[ADMIN] ADMIN_EMAIL not set — admin access will be denied to everyone.');

const COOKIE_NAME = 'ff_session';
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days
const OTP_TTL_MS = 10 * 60 * 1000; // 10 minutes
const OTP_MAX_ATTEMPTS = 6;
const RATE_LIMIT_PER_EMAIL_PER_HOUR = 5;
const RATE_LIMIT_PER_IP_PER_HOUR    = 20;

function generateOtp() {
    return String(require('crypto').randomInt(0, 1_000_000)).padStart(6, '0');
}

async function hashOtp(code) { return bcrypt.hash(code, 10); }
async function verifyOtp(code, hash) { return bcrypt.compare(code, hash); }

function signSession({ id, email, tier }) {
    return jwt.sign({ sub: id, email, tier }, JWT_SECRET, { expiresIn: SESSION_TTL_SECONDS });
}

function verifySession(token) {
    try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}

function setSessionCookie(res, token) {
    res.cookie(COOKIE_NAME, token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: SESSION_TTL_SECONDS * 1000,
        path: '/'
    });
}

function clearSessionCookie(res) {
    res.clearCookie(COOKIE_NAME, { path: '/' });
}

function getClientIp(req) {
    return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip || '';
}

// Origin check: defence-in-depth against logout-CSRF and other authenticated
// POSTs. SameSite=Lax already blocks top-level cross-site POSTs in modern
// browsers, but the spec promised this and it costs nothing.
function requireSameOrigin(req, res, next) {
    const origin = req.headers.origin || req.headers.referer || '';
    if (!origin) return next(); // server-to-server / curl with no origin: allow
    const host = req.headers.host;
    try {
        const u = new URL(origin);
        if (u.host === host) return next();
    } catch { /* fall through */ }
    return res.status(403).json({ error: 'Cross-origin POST blocked.' });
}

async function logAuthEvent({ type, email = null, memberId = null, req = null, metadata = null }) {
    try {
        await supabase.from('auth_events').insert({
            event_type: type,
            email: email ? email.toLowerCase().trim() : null,
            member_id: memberId,
            ip: req ? getClientIp(req) : null,
            user_agent: req ? (req.headers['user-agent'] || '').slice(0, 500) : null,
            metadata
        });
    } catch (e) { console.error('[AUTH] logAuthEvent failed:', e.message); }
}

async function rateLimitOtpRequest(email, ip) {
    const sinceIso = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    const [{ count: emailCount }, { count: ipCount }] = await Promise.all([
        supabase.from('auth_events').select('id', { count: 'exact', head: true })
            .eq('event_type', 'otp_requested').eq('email', email).gte('created_at', sinceIso),
        supabase.from('auth_events').select('id', { count: 'exact', head: true })
            .eq('event_type', 'otp_requested').eq('ip', ip).gte('created_at', sinceIso)
    ]);
    if ((emailCount || 0) >= RATE_LIMIT_PER_EMAIL_PER_HOUR) return 'email';
    if ((ipCount || 0) >= RATE_LIMIT_PER_IP_PER_HOUR) return 'ip';
    return null;
}

async function requireMember(req, res, next) {
    const token = req.cookies && req.cookies[COOKIE_NAME];
    if (!token) return res.status(401).json({ error: 'Not authenticated.' });
    const payload = verifySession(token);
    if (!payload || !payload.sub) return res.status(401).json({ error: 'Session invalid.' });
    // Re-read fresh tier from DB so admin edits take effect immediately.
    const { data, error } = await supabase.from('members').select('id, email, tier, name, phone, created_at, last_login_at').eq('id', payload.sub).single();
    if (error || !data) return res.status(401).json({ error: 'Member not found.' });
    req.member = data;
    next();
}

// Admin gate. Single allowlisted email (ADMIN_EMAIL env var). Reads the
// session cookie; rejects anyone whose email doesn't match exactly.
function requireAdmin(req, res, next) {
    const token = req.cookies && req.cookies[COOKIE_NAME];
    const payload = token && verifySession(token);
    const sessionEmail = ((payload && payload.email) || '').toLowerCase().trim();
    if (!payload || !ADMIN_EMAIL || sessionEmail !== ADMIN_EMAIL) {
        return res.status(403).json({ error: 'Forbidden.' });
    }
    next();
}

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
app.post('/api/admin/testimonials', requireAdmin, async (req, res) => {
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
app.put('/api/admin/testimonials/:id', requireAdmin, async (req, res) => {
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
app.delete('/api/admin/testimonials/:id', requireAdmin, async (req, res) => {
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

// ─── AUTH ROUTES ─────────────────────────────────────────────────────────────
app.post('/api/auth/request-otp', async (req, res) => {
    const email = (req.body && req.body.email || '').toLowerCase().trim();
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
        return res.status(400).json({ error: 'A valid email is required.' });
    }
    const ip = getClientIp(req);

    const limited = await rateLimitOtpRequest(email, ip);
    if (limited) {
        await logAuthEvent({ type: 'login_failed', email, req, metadata: { reason: `rate_limit_${limited}` } });
        return res.status(429).json({ error: 'Too many code requests. Try again later.' });
    }

    const code = generateOtp();
    const codeHash = await hashOtp(code);
    const expiresAt = new Date(Date.now() + OTP_TTL_MS).toISOString();

    const { error } = await supabase.from('otp_codes').insert({
        email, code_hash: codeHash, expires_at: expiresAt
    });
    if (error) {
        console.error('[AUTH] insert otp_codes failed:', error.message);
        return res.status(500).json({ error: 'Could not issue code. Try again.' });
    }

    await sendOtpEmail(email, code);
    await logAuthEvent({ type: 'otp_requested', email, req });

    const body = { success: true };
    if (process.env.NODE_ENV === 'development') body.devCode = code; // only in dev for E2E tests
    res.json(body);
});

app.post('/api/auth/verify-otp', async (req, res) => {
    const email = (req.body && req.body.email || '').toLowerCase().trim();
    const code = (req.body && req.body.code || '').toString().trim();
    if (!email || !/^\d{6}$/.test(code)) {
        return res.status(400).json({ error: 'Email and 6-digit code required.' });
    }

    const nowIso = new Date().toISOString();
    const { data: otpRow, error: findErr } = await supabase
        .from('otp_codes')
        .select('*')
        .eq('email', email).eq('used', false).gt('expires_at', nowIso)
        .order('created_at', { ascending: false }).limit(1).single();

    if (findErr || !otpRow) {
        await logAuthEvent({ type: 'login_failed', email, req, metadata: { reason: 'no_active_code' } });
        return res.status(401).json({ error: 'Code expired or not found. Request a new one.' });
    }

    const match = await verifyOtp(code, otpRow.code_hash);
    if (!match) {
        const newAttempts = (otpRow.attempts || 0) + 1;
        const burn = newAttempts >= OTP_MAX_ATTEMPTS;
        await supabase.from('otp_codes').update({ attempts: newAttempts, used: burn }).eq('id', otpRow.id);
        await logAuthEvent({ type: 'login_failed', email, req, metadata: { reason: 'bad_code', attempts: newAttempts } });
        return res.status(401).json({ error: burn ? 'Too many attempts. Request a new code.' : 'Incorrect code.' });
    }

    await supabase.from('otp_codes').update({ used: true }).eq('id', otpRow.id);

    let { data: member } = await supabase.from('members').select('*').eq('email', email).single();
    let isSignup = false;
    if (!member) {
        const { data: created, error: createErr } = await supabase.from('members').insert({
            email, tier: 'bronze', email_verified: true, last_login_at: nowIso
        }).select('*').single();
        if (createErr) {
            console.error('[AUTH] create member failed:', createErr.message);
            return res.status(500).json({ error: 'Could not create account.' });
        }
        member = created;
        isSignup = true;
    } else {
        await supabase.from('members').update({
            email_verified: true, last_login_at: nowIso
        }).eq('id', member.id);
    }

    const token = signSession({ id: member.id, email: member.email, tier: member.tier });
    setSessionCookie(res, token);
    await logAuthEvent({
        type: isSignup ? 'signup' : 'login',
        email, memberId: member.id, req
    });

    res.json({ success: true, member: {
        email: member.email,
        tier: member.tier,
        name: member.name || '',
        phone: member.phone || '',
        profileComplete: !!(member.name && member.phone),
        memberSince: member.created_at
    }});
});

app.get('/api/auth/me', requireMember, (req, res) => {
    res.json({ member: {
        email: req.member.email,
        tier: req.member.tier,
        name: req.member.name || '',
        phone: req.member.phone || '',
        profileComplete: !!(req.member.name && req.member.phone),
        memberSince: req.member.created_at,
        lastLoginAt: req.member.last_login_at
    }});
});

// Update name + phone on the current member. Used by the one-time profile
// form shown to new portal users.
app.put('/api/auth/profile', requireSameOrigin, requireMember, async (req, res) => {
    const name  = ((req.body && req.body.name)  || '').toString().trim().slice(0, 120);
    const phone = ((req.body && req.body.phone) || '').toString().trim().slice(0, 40);
    if (!name)  return res.status(400).json({ error: 'Name is required.' });
    if (!phone) return res.status(400).json({ error: 'Phone is required.' });

    const { error } = await supabase.from('members').update({ name, phone }).eq('id', req.member.id);
    if (error) return res.status(500).json({ error: 'Could not save profile.' });

    res.json({ success: true, member: { email: req.member.email, tier: req.member.tier, name, phone, profileComplete: true } });
});

app.post('/api/auth/logout', requireSameOrigin, async (req, res) => {
    const token = req.cookies && req.cookies[COOKIE_NAME];
    const payload = token && verifySession(token);
    clearSessionCookie(res);
    if (payload) await logAuthEvent({ type: 'logout', email: payload.email, memberId: payload.sub, req });
    res.json({ success: true });
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
app.post('/api/steps', requireAdmin, async (req, res) => {
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
app.put('/api/steps/:id', requireAdmin, async (req, res) => {
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
app.get('/api/submissions', requireAdmin, async (req, res) => {
    const [{ data: submissions }, { data: referrals }] = await Promise.all([
        supabase.from('submissions').select('*').order('created_at', { ascending: false }),
        supabase.from('referrals').select('*').order('created_at', { ascending: false })
    ]);

    res.json({ submissions: submissions || [], referrals: referrals || [] });
});

// ─── GET /api/admin/data (one-shot dashboard fetch) ─────────────────────────
app.get('/api/admin/data', requireAdmin, async (req, res) => {
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

// ─── ADMIN: members + auth events ────────────────────────────────────────────
app.get('/api/admin/members', requireAdmin, async (req, res) => {
    const { data, error } = await supabase
        .from('members')
        .select('id, email, name, phone, tier, email_verified, created_at, last_login_at')
        .order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json({ members: data || [] });
});

app.put('/api/admin/members/:id', requireAdmin, async (req, res) => {
    const { tier } = req.body || {};
    if (!['bronze','silver','gold','platinum'].includes(tier)) {
        return res.status(400).json({ error: 'Invalid tier.' });
    }
    const { data, error } = await supabase
        .from('members').update({ tier }).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    if (!data) return res.status(404).json({ error: 'Not found.' });
    res.json({ success: true, member: data });
});

app.get('/api/admin/auth-events', requireAdmin, async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 200, 500);
    const { data, error } = await supabase
        .from('auth_events')
        .select('id, event_type, email, member_id, ip, user_agent, metadata, created_at')
        .order('created_at', { ascending: false })
        .limit(limit);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ events: data || [] });
});

// ─── POST /api/quiz-results ───────────────────────────────────────────────────
app.post('/api/quiz-results', requireMember, async (req, res) => {
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
        label,
        member_id: req.member.id,
        member_email: req.member.email,
        member_name: req.member.name || null
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
