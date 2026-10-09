# Loraearn MVP — Backend Starter

This is a runnable backend-first MVP starter for Loraearn, including a responsive member portal at `/`. It includes registration/login, server-side sessions, SQLite persistence, referral codes, configurable plans, member dashboard data, deposit requests with admin review, withdrawal reservations/review, settings, support tickets, and audit logs.

**Important:** This is a development MVP, not a production-ready financial service. It does not promise returns, does not generate earnings automatically, and does not yet implement referral commission posting, payment gateway integration, email/SMS verification, CSRF tokens, or a polished web frontend. Do not accept real customer funds until a qualified engineer completes security, accounting, legal, and payment-provider reviews.

## Requirements
- Python 3.10+
- pip

## Run locally
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
Open `http://127.0.0.1:5000/api/health`. The API initializes its SQLite database on first start.

## Create the first administrator
Set a temporary setup token before launching the server:
```bash
export LORAearn_SETUP_TOKEN='use-a-long-random-temporary-token'
export LORAearn_SECRET_KEY='use-a-long-random-secret'
python app.py
```
Then send a JSON POST request to `/api/setup/first-admin`:
```json
{
  "setup_token": "use-a-long-random-temporary-token",
  "name": "Site Owner",
  "email": "owner@example.com",
  "phone": "+92...",
  "password": "a-unique-password-at-least-14-chars"
}
```
Remove `LORAearn_SETUP_TOKEN` immediately after the first admin is created, and restart the service. Never publish secrets or commit them to source control.

## Main API routes
- `POST /api/register` — name, email, phone, password, optional referral_code
- `POST /api/login` / `POST /api/logout`
- `GET /api/me`
- `GET /api/plans`
- `GET /api/dashboard`
- `POST /api/deposits` — amount, transaction_ref; pending only, no instant credit
- `POST /api/withdrawals` — amount, payout_method, payout_details
- `POST /api/support` — subject, message
- `GET /api/admin/overview`
- `GET /api/admin/members`
- `POST /api/admin/plans` and `PATCH /api/admin/plans/<id>`
- `POST /api/admin/settings`
- `GET /api/admin/deposits` and `POST /api/admin/deposits/<id>/review`
- `GET /api/admin/withdrawals` and `POST /api/admin/withdrawals/<id>/review`
- `GET /api/admin/audit-logs`

Protected routes use the authenticated session cookie. Admin routes enforce role checks on the server. Use a CSRF protection strategy before exposing cookie-authenticated POST/PATCH routes publicly.

## Current MVP boundaries
- Default currency is PKR; minimum withdrawal defaults to PKR 500.
- Deposits are only credited after an admin manually approves them.
- Withdrawal amounts are reserved from the available balance; rejected requests release the reserved amount. A withdrawal is marked paid only after an admin supplies a payout reference.
- Referral codes and referral relationships are stored, but commission crediting is intentionally not automated until the eligible revenue source, budget, reversal process, and accounting controls are specified.
- Plan management stores configurable rules; no plan generates money by itself.
- SQLite is suitable for local testing. Use PostgreSQL or another managed production database, migrations, backups, monitoring, and concurrency testing before production.
- The initial admin bootstrap route is disabled unless `LORAearn_SETUP_TOKEN` is set and refuses to create a second admin.
- Do not use `debug=True` in deployment.

## Before production
1. Add CSRF protection, rate limiting, email/phone verification, password reset, MFA for admins, and robust session expiry.
2. Add a real double-entry accounting ledger with balanced debit/credit postings and immutable journal semantics. Have an accountant review the chart of accounts.
3. Implement referral commission calculation only for eligible verified business revenue or an explicitly budgeted promotion; include idempotency keys and reversal entries.
4. Add official payment gateway integrations with verified webhooks, signed requests, idempotency, and reconciliation.
5. Encrypt sensitive payout details at rest, restrict their display, and define retention/deletion rules.
6. Add migration tooling, automated backups, restore drills, staging deployments, tests, logs, monitoring, and incident response.
7. Review Pakistani legal, tax, consumer protection, privacy, and payment-provider requirements with qualified local professionals.
8. Build the responsive member/admin frontend and accessibility-tested Urdu/English localization.
