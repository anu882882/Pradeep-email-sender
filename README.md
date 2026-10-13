# Secure Mail Console

A dark-only Flask email dashboard deployed on Vercel.

## Required environment variables

Configure these in Vercel Project Settings → Environment Variables:

- LOGIN_PASSWORD
- SESSION_SECRET
- TURNSTILE_SITE_KEY
- TURNSTILE_SECRET_KEY

Use a long, random SESSION_SECRET.
Never expose private keys in frontend code.

## Cloudflare Turnstile

1. Create a Turnstile widget in Cloudflare.
2. Add your deployment domain to its allowed hostnames.
3. Set TURNSTILE_SITE_KEY to the public site key.
4. Set TURNSTILE_SECRET_KEY to the private secret key.
5. Redeploy after changing environment variables.

## Gmail

Use your Gmail address and Google App Password.
Do not enter your regular Google account password.

## Deployment

1. Push the project files to your Git repository.
2. Import the repository into Vercel.
3. Configure the required environment variables.
4. Deploy and test the login page.
5. Send a test email to an address you control.

## Features

- Dark-only dashboard.
- Compose Message and Recipients panels.
- Plain Text and HTML message modes.
- Total, Sent, Failed and Remaining counters.
- Progress bar and Stop Sending button.
- No Delivery Results section.
- Maximum 25 recipients per request.
- Up to five concurrent sends per group.

## Important

Stopping the browser request does not guarantee that emails
already being processed by the server will be cancelled.

SMTP acceptance does not guarantee inbox delivery. Test the
deployment and email delivery before relying on it.
