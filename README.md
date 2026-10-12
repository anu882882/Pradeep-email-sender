# Secure Mail Console

A dark-mode Flask email dashboard deployed on Vercel.

## Project structure

- api/index.py — Flask routes, login, Turnstile validation and SMTP sending
- templates/login.html — Sign-in page
- templates/index.html — Email dashboard
- static/style.css — Dark-only interface
- requirements.txt — Python dependencies
- vercel.json — Vercel deployment configuration

## Required Vercel environment variables

Set these in Vercel Project Settings → Environment Variables:

- LOGIN_PASSWORD
- SESSION_SECRET
- TURNSTILE_SITE_KEY
- TURNSTILE_SECRET_KEY

Use a long, random SESSION_SECRET. Never put the Turnstile secret
or your login password in HTML or JavaScript.

## Cloudflare Turnstile

1. Create a Turnstile widget in Cloudflare.
2. Add your deployed domain to its allowed hostnames.
3. Set the site key as TURNSTILE_SITE_KEY.
4. Set the secret key as TURNSTILE_SECRET_KEY.
5. Redeploy after adding or changing environment variables.

## Gmail sending

Use your Gmail address and a Google App Password.
Do not use your normal Google account password.

## Deploy

1. Push all project files to your GitHub repository.
2. Import the repository into Vercel.
3. Add the required environment variables.
4. Deploy and test the login page.
5. Send a test message to an address you control.

## Important notes

- The application accepts up to 25 recipients per request.
- Messages are processed in groups of up to five concurrent sends.
- A successful SMTP send means the receiving server accepted the
  message; it does not guarantee inbox placement.
- Stopping the browser request may not cancel emails already being
  processed by the server.
- Vercel runtime limits can affect long-running requests.
- Test deployment and SMTP delivery before relying on the application.
