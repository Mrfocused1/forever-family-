# Member Auth — Design Spec

Date: 2026-05-18
Status: Approved for implementation

## Goal

Gate `/portal` and `/learn` behind a member login. Self-serve signup, no
passwords — verification by 6-digit one-time code sent via Resend. Surface
all auth activity on `/admin`.

## Decisions made during brainstorming

| Question | Decision |
|---|---|
| Signup model | Self-serve. Anyone can register; default tier `bronze`. |
| Auth mechanism | Email + 6-digit OTP. No passwords stored. |
| `/learn` access | Any logged-in member (no tier gate at this stage). |
| Admin logging | Members tab + Auth Activity tab. |
| Architecture | Custom auth in `server.js` (Approach A). |
| Existing data | Delete 4 placeholder tier-code rows; keep `ras@gmail.com`. |

## Schema

```sql
ALTER TABLE public.members
  ADD COLUMN created_at      timestamptz DEFAULT now(),
  ADD COLUMN email_verified  boolean     DEFAULT false,
  ADD COLUMN last_login_at   timestamptz;

CREATE TABLE public.otp_codes (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email       text NOT NULL,
  code_hash   text NOT NULL,
  expires_at  timestamptz NOT NULL,
  used        boolean DEFAULT false,
  attempts    int     DEFAULT 0,
  created_at  timestamptz DEFAULT now()
);
CREATE INDEX otp_codes_email_idx ON public.otp_codes (email, expires_at DESC);

CREATE TABLE public.auth_events (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type  text NOT NULL,   -- otp_requested | signup | login | login_failed | logout
  email       text,
  member_id   bigint REFERENCES public.members(id) ON DELETE SET NULL,
  ip          text,
  user_agent  text,
  metadata    jsonb,
  created_at  timestamptz DEFAULT now()
);
CREATE INDEX auth_events_created_idx ON public.auth_events (created_at DESC);

ALTER TABLE public.otp_codes   ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.auth_events ENABLE ROW LEVEL SECURITY;
-- Service role bypasses RLS; no anon access policies needed.
```

Migration: delete the 4 placeholder tier-code rows (id 1–4); backfill
`email_verified=true, created_at=now()` for id 5 (ras@gmail.com).

## API surface

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/auth/request-otp` | public | Generate code, send email |
| POST | `/api/auth/verify-otp`  | public | Validate code, set session cookie |
| POST | `/api/auth/logout`      | session | Clear session cookie |
| GET  | `/api/auth/me`          | session | Return current member or 401 |
| GET  | `/api/admin/members`        | admin-key | Member roster |
| GET  | `/api/admin/auth-events`    | admin-key | Activity log |
| PUT  | `/api/admin/members/:id`    | admin-key | Edit tier |

Existing `/api/portal-login` is removed.

### Middleware

`requireMember(req, res, next)`: read `ff_session` cookie → verify JWT →
attach `req.member = { id, email, tier }` or `401`.

Server route `/learn` wrapped: if no valid cookie → 302 redirect to
`/portal?next=/learn`.

## Auth flow

```
[ /portal | /learn (logged out) ]
              │
              ▼
   Enter email → POST /api/auth/request-otp
              │
              ├─ rate limit: 5/email/hour, 20/IP/hour
              ├─ generate 6-digit code (000000–999999, leading zeros OK)
              ├─ bcrypt-hash with cost 10
              ├─ insert otp_codes row, expires_at = now() + 10 min
              ├─ Resend email: "Your Forever Family code: 123456"
              └─ log auth_events { type: 'otp_requested', email, ip, ua }
              │
              ▼
   Enter 6-digit code → POST /api/auth/verify-otp
              │
              ├─ find newest unused, unexpired otp_codes row for email
              ├─ bcrypt.compare; on mismatch → attempts++ → if ≥6, mark used
              ├─ on miss → log 'login_failed'; return 401
              ├─ on hit  → mark otp row used
              ├─ if no members row for email → insert (tier=bronze, email_verified=true)
              │            → log 'signup'
              ├─ else      → update last_login_at; log 'login'
              ├─ sign JWT { sub, email, tier, iat, exp }, 30-day expiry
              └─ Set-Cookie: ff_session=<jwt>; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000
              │
              ▼
   UI calls /api/auth/me → renders logged-in panel.
   If origin had ?next=/learn, redirect to /learn.
```

## UI changes

**`portal.html`**

- Form has two visible states (one stays in the existing `#login-screen` container):
  1. **Email** — single input + `SEND CODE` button.
  2. **Code** — `Check your inbox at <email>` heading, 6-digit input,
     `VERIFY` button, `Resend code` link, `Use a different email` link.
- After verify, hide login screen, populate the existing logged-in panel
  via `/api/auth/me` (tier badge, member-since, etc.).
- On load, `GET /api/auth/me` — if 200, skip login screen entirely.
- Logout button calls `/api/auth/logout` then reloads.

**`learn.html`**

- Server-side: `app.get('/learn', requireMemberOrRedirect, …)` — if no
  session, send to `/portal?next=/learn`.
- No client-side gating logic needed (server enforces).

**`admin.html`**

- Two new tabs added between Quiz Results and Testimonials:
  - **Members** — table: Email · Tier · Verified · Signed Up · Last Login ·
    `Edit tier` button (cycles bronze→silver→gold→platinum).
  - **Auth Activity** — chronological table: Time · Event · Email · IP ·
    User-Agent (truncated).
- Existing demo-data fallback pattern reused if tables empty.
- Two new stat cards next to existing ones: `Members` count, `Logins (24h)`.

## Email template

Subject: `Your Forever Family code: 123456`

HTML body (palette match — `#0d0d0d` bg, `#D4AF37` gold accent, Oswald
heading via web-safe stack since most clients strip @font-face):

```
[FF logo]
YOUR ACCESS CODE
┌──────────────┐
│   123456     │
└──────────────┘
Expires in 10 minutes.
Enter it on the Forever Family portal to sign in.
If you didn't request this, ignore this email.
```

Plain-text fallback for clients that block HTML.

Sent via the existing `sendNotification()` helper, FROM `RESEND_FROM`, TO
the user's submitted email (not `RESEND_TO`).

## Security details

- **OTP code**: cryptographically random 6 digits via `crypto.randomInt(0, 1_000_000)`, zero-padded.
- **Code storage**: bcrypt cost 10. Plaintext code only exists in memory before send.
- **Single-use**: `used=true` once consumed OR after 6 failed attempts.
- **Expiry**: 10 minutes hard; verification checks `expires_at > now()`.
- **Rate limits** (count `auth_events` rows in last 60 min):
  - `otp_requested` per email ≤ 5 → return 429
  - `otp_requested` per IP   ≤ 20 → return 429
- **Session JWT**: HS256, secret `AUTH_JWT_SECRET` (32-byte hex), 30-day expiry.
  Tier in token is *display only* — server re-reads tier from DB on every
  request needing it, so admin tier-edits take effect immediately on next
  request (no token revocation needed).
- **Cookie**: `HttpOnly`, `Secure` (when `NODE_ENV=production`), `SameSite=Lax`.
- **CSRF**: SameSite=Lax + Origin check on POST endpoints. No third-party
  embedding (CSP `frame-ancestors 'none'` already set in `vercel.json`).
- **Logout**: clears cookie, logs event. No server-side session store to
  revoke (stateless JWT) — acceptable trade-off for 30-day token.

## Dependencies

```
npm i jsonwebtoken bcryptjs cookie-parser
```

## Env

```
AUTH_JWT_SECRET=<openssl rand -hex 32>
# RESEND_* env vars already set
```

Adding to `.env.local` and Vercel envs (preview + production).

## Out of scope (deliberate)

- Password reset / recovery (no passwords).
- Tier upgrades from member-side (admin-only for now).
- OAuth / social login.
- 2FA beyond the OTP itself.
- Magic link variant alongside OTP.
- Email change flow (members table has one email; admin can edit it).
- Rate-limit by exact device fingerprint (IP is enough at this scale).

## Open questions

None — design approved 2026-05-18.

## Acceptance criteria

1. New user can register from `/portal` using only their email; receives
   code within 30s; verifies; sees logged-in panel.
2. `/learn` 302s to `/portal?next=/learn` for logged-out visitors.
3. Returning member with `ff_session` cookie skips the login screen.
4. Five OTP requests in an hour from the same email get rate-limited.
5. Admin `/admin` shows a Members tab with at least the founder row, and
   an Auth Activity tab with a row for every login above.
6. Admin can change a member's tier via the UI; member's next request
   sees the new tier.
7. Logout clears the cookie and the next page load shows the login form.
8. All four placeholder tier-code rows (`FF-BRONZE-2025` etc.) are gone
   from the members table.
