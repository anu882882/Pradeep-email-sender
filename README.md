# Secure Mail Console

## Vercel Environment Variables

Open Vercel → Project → Settings → Environment Variables.

Add the following variables:

- LOGIN_PASSWORD
- SESSION_SECRET
- TURNSTILE_SITE_KEY
- TURNSTILE_SECRET_KEY
- MAIL_GAP_SECONDS

### LOGIN_PASSWORD
Your private dashboard login password.

### SESSION_SECRET
Use a long, random secret value. Do not use the example fallback value in production.

### TURNSTILE_SITE_KEY
The Cloudflare Turnstile site key for your deployed domain.

### TURNSTILE_SECRET_KEY
The Cloudflare Turnstile secret key. Keep this on the server only.

Never put SESSION_SECRET, TURNSTILE_SECRET_KEY, or your Gmail App Password in frontend JavaScript or a public repository.

## Features

- Password-protected login.
- Cloudflare Turnstile verification on login and sending.
- Secure session cookie settings and security headers.
- Basic instance-local rate limiting.
- Up to 25 unique valid recipients per request.
- Two concurrent SMTP sending workers.
- Plain-text and HTML message modes.
- Message editor with font options and adjustable size.
- Dark theme.

## Project Files

- api/index.py
- templates/index.html
- templates/login.html
- static/style.css
- requirements.txt
- vercel.json
- README.md

## Deploy

1. Keep the folder structure exactly as shown above.
2. Configure the Vercel environment variables.
3. Make sure your Cloudflare Turnstile keys allow your deployed domain.
4. Deploy or redeploy the project on Vercel.
5. Test login and email delivery with an address you control.

Note: The in-memory rate limiter is best-effort and is not shared across all Vercel serverless instances.
For global rate limiting, configure Cloudflare rules or a shared data store.
