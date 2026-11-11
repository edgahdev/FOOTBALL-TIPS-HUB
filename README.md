# Football Tips Hub — deployable full-stack project

This is a Node.js + SQLite website. `public/index.html` is the front end; `server.js` handles accounts, secure password hashes, the database, admin routes, Daraja STK Push and Safaricom callbacks.

## Important security note
The Daraja production consumer secret and Lipa Na M-Pesa passkey were pasted into a chat. Treat them as exposed: regenerate/rotate them in the Daraja portal before use. Do not put credentials in `public/index.html`, GitHub, browser JavaScript or a public repository. Use the fresh values only in the hosting provider's private environment variables or `.env` on your server.

## Requirements
- Node.js 20 or newer
- A hosting provider that runs persistent Node.js applications
- A persistent disk/volume for `data/football-tips.sqlite`
- Public HTTPS domain for the callback
- A Daraja app approved/configured for the chosen production or sandbox environment

## Install locally
1. Extract this ZIP.
2. Open a terminal in the extracted `football-tips-hub` folder.
3. Run `npm install`.
4. Copy `.env.example` to `.env`.
5. Generate a long random `JWT_SECRET`.
6. Set `ADMIN_EMAIL`.
7. Run `npm run make-admin-hash` and put the resulting bcrypt hash into `ADMIN_PASSWORD_HASH`.
8. Set Daraja credentials in `.env` only after rotating them.
9. For initial testing, set `DARAJA_ENV=sandbox` and use sandbox credentials/shortcode/passkey. Do not mix production keys with sandbox endpoints.
10. Set `DARAJA_ENABLED=true` only after all required values and a public HTTPS callback URL are in place.
11. Run `npm start`; visit `http://localhost:3000`.

## Production deployment
- Deploy this folder as a Node.js web service, not static HTML hosting.
- Build/install command: `npm install`
- Start command: `npm start`
- Add every `.env` value as a private environment variable in your host dashboard.
- Set `DB_FILE` to a path on the host's persistent disk, for example `/var/data/football-tips.sqlite`; create/attach the persistent disk before launching.
- Set `MPESA_CALLBACK_URL` to `https://YOUR-DOMAIN/api/mpesa/callback`.
- Confirm your Safaricom configuration supports CustomerBuyGoodsOnline with the supplied shortcode/Till pairing. The code sends `BusinessShortCode=MPESA_SHORTCODE`, `PartyB=MPESA_TILL_NUMBER`, and `TransactionType=CustomerBuyGoodsOnline`.
- Set `DARAJA_ENV=production` only when using approved production credentials and ready to collect real payments.
- Set `DARAJA_ENABLED=true` to enable the STK button.
- Do not run more than one server instance against the same SQLite file unless you migrate to a network database such as PostgreSQL.

## Payment flow
The server creates a pending payment using the plan price stored in SQLite (not a client-supplied amount), requests an STK Push, stores the `CheckoutRequestID`, then waits for `/api/mpesa/callback`. Only a successful callback with matching amount, phone and receipt activates the membership. The member dashboard polls payment status. Failed/cancelled pushes do not activate access.

## Admin
Admin login is at the bottom of the public page. Credentials are `ADMIN_EMAIL` and the password corresponding to `ADMIN_PASSWORD_HASH`. The admin can create/edit/delete fixtures, set decimal odds and analysis, change the three plan prices, and view payment/member records.

## Database
SQLite creates itself in `data/football-tips.sqlite` on first run. Back up this file regularly. Keep the `data` directory persistent on the hosting platform.

## Important limitations / launch checks
- The callback URL must be reachable over HTTPS from Safaricom.
- Confirm exact Buy Goods shortcode/Till mapping and production STK permissions with Safaricom before launch. The provided `1400139` and `1868026` values are configured separately, but their relationship must be valid in your Daraja merchant setup.
- Test one low-value payment on sandbox first. For production, a successful STK prompt and Safaricom callback must be verified before opening subscriptions to customers.
- The current project intentionally does not accept manual screenshot claims as proof of payment. Use M-Pesa callback/merchant statements for real verification.
- Odds and predictions are admin-entered editorial content, not live bookmaker odds. Never describe a tip as guaranteed or sure.
- Add a privacy policy, terms, support contact, and age/responsible-gambling disclosures before public launch.
- Use a reputable host with backups, HTTPS, environment-variable secrets and server logs.
