import os, sqlite3, secrets, string
from functools import wraps
from decimal import Decimal, InvalidOperation
from flask import Flask, g, request, jsonify, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash

APP_SECRET = os.environ.get("LORAearn_SECRET_KEY")
if not APP_SECRET:
    APP_SECRET = secrets.token_urlsafe(48)  # Set a persistent secret in production.
DB_PATH = os.environ.get("LORAearn_DB", "loraearn.sqlite3")

app = Flask(__name__)
app.secret_key = APP_SECRET
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=15)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(_):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT, member_id TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, phone TEXT NOT NULL,
      password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'member',
      referral_code TEXT UNIQUE NOT NULL, referred_by INTEGER REFERENCES users(id),
      status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS plans(
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
      qualifying_amount_cents INTEGER NOT NULL DEFAULT 0, reward_rule TEXT NOT NULL DEFAULT '',
      active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS enrollments(
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id),
      plan_id INTEGER NOT NULL REFERENCES plans(id), status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS wallets(
      user_id INTEGER PRIMARY KEY REFERENCES users(id), available_cents INTEGER NOT NULL DEFAULT 0,
      pending_cents INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS ledger(
      id INTEGER PRIMARY KEY AUTOINCREMENT, ref TEXT UNIQUE NOT NULL, user_id INTEGER NOT NULL REFERENCES users(id),
      entry_type TEXT NOT NULL, amount_cents INTEGER NOT NULL, status TEXT NOT NULL,
      description TEXT NOT NULL, related_ref TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS deposits(
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id),
      amount_cents INTEGER NOT NULL, transaction_ref TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, reviewed_by INTEGER REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS withdrawals(
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id),
      amount_cents INTEGER NOT NULL, payout_method TEXT NOT NULL, payout_details TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending', payout_ref TEXT, rejection_reason TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, reviewed_by INTEGER REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS commissions(
      id INTEGER PRIMARY KEY AUTOINCREMENT, earner_id INTEGER NOT NULL REFERENCES users(id),
      source_user_id INTEGER NOT NULL REFERENCES users(id), level INTEGER NOT NULL,
      amount_cents INTEGER NOT NULL, source_ledger_ref TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(earner_id, source_ledger_ref, level)
    );
    CREATE TABLE IF NOT EXISTS settings(
      key TEXT PRIMARY KEY, value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_logs(
      id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER REFERENCES users(id),
      action TEXT NOT NULL, details TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS support_tickets(
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id),
      subject TEXT NOT NULL, message TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    """)
    for key, value in [
        ("currency", "PKR"), ("direct_commission_percent", "10"),
        ("indirect_commission_percent", "5"), ("minimum_withdrawal_pkr", "500"),
        ("maintenance_mode", "false")
    ]:
        conn.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (key, value))
    conn.commit()
    conn.close()

def money_to_cents(value):
    try:
        amount = Decimal(str(value))
        if not amount.is_finite() or amount <= 0 or amount > Decimal("100000000"):
            raise ValueError()
        return int(amount * 100)
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError("Enter a valid positive amount.")

def new_ref(prefix="TX"):
    return prefix + "-" + secrets.token_hex(8).upper()

def referral_code():
    alphabet = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(8))

def audit(actor_id, action, details):
    db().execute("INSERT INTO audit_logs(actor_id,action,details) VALUES(?,?,?)",
                 (actor_id, action, details[:500]))

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return db().execute("SELECT * FROM users WHERE id=? AND status='active'", (uid,)).fetchone()

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not current_user():
            return jsonify(error="Authentication required"), 401
        return fn(*args, **kwargs)
    return wrapped

def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            return jsonify(error="Authentication required"), 401
        if user["role"] != "admin":
            return jsonify(error="Administrator permission required"), 403
        return fn(*args, **kwargs)
    return wrapped

def user_json(user):
    return {"id": user["id"], "member_id": user["member_id"], "name": user["name"],
            "email": user["email"], "phone": user["phone"], "role": user["role"],
            "referral_code": user["referral_code"], "status": user["status"]}

@app.get("/")
def index():
    return send_from_directory("static", "index.html")

@app.get("/api/health")
def health():
    return jsonify(ok=True)

@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    name, email, phone, password = [str(data.get(k, "")).strip() for k in ("name","email","phone","password")]
    ref_code = str(data.get("referral_code", "")).strip().upper()
    if not name or len(name) > 100 or "@" not in email or len(email) > 190 or not phone or len(phone) > 30:
        return jsonify(error="Enter valid name, email and phone."), 400
    if len(password) < 10:
        return jsonify(error="Password must contain at least 10 characters."), 400
    conn = db()
    referrer = None
    if ref_code:
        referrer = conn.execute("SELECT id FROM users WHERE referral_code=? AND status='active'", (ref_code,)).fetchone()
        if not referrer:
            return jsonify(error="Referral code is invalid."), 400
    code = referral_code()
    try:
        cur = conn.execute("""INSERT INTO users(member_id,name,email,phone,password_hash,referral_code,referred_by)
                              VALUES(?,?,?,?,?,?,?)""",
                           ("LR-" + secrets.token_hex(5).upper(), name, email.lower(), phone,
                            generate_password_hash(password), code, referrer["id"] if referrer else None))
        uid = cur.lastrowid
        conn.execute("INSERT INTO wallets(user_id) VALUES(?)", (uid,))
        audit(uid, "account_registered", "New member registration")
        conn.commit()
        return jsonify(message="Registration successful.", user_id=uid), 201
    except sqlite3.IntegrityError:
        conn.rollback()
        return jsonify(error="An account with that email already exists."), 409

@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    user = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not user or user["status"] != "active" or not check_password_hash(user["password_hash"], password):
        return jsonify(error="Invalid credentials or inactive account."), 401
    session.clear()
    session["user_id"] = user["id"]
    return jsonify(message="Login successful.", user=user_json(user))

@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(message="Logged out.")

@app.get("/api/me")
@login_required
def me():
    user = current_user()
    return jsonify(user=user_json(user))

@app.get("/api/plans")
def plans():
    rows = db().execute("SELECT * FROM plans WHERE active=1 ORDER BY id DESC").fetchall()
    return jsonify(plans=[dict(r) for r in rows])

@app.get("/api/dashboard")
@login_required
def dashboard():
    user = current_user()
    conn = db()
    wallet = conn.execute("SELECT * FROM wallets WHERE user_id=?", (user["id"],)).fetchone()
    ledger = conn.execute("SELECT ref,entry_type,amount_cents,status,description,created_at FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT 50", (user["id"],)).fetchall()
    deposits = conn.execute("SELECT id,amount_cents,transaction_ref,status,created_at FROM deposits WHERE user_id=? ORDER BY id DESC LIMIT 20", (user["id"],)).fetchall()
    withdrawals = conn.execute("SELECT id,amount_cents,payout_method,status,payout_ref,rejection_reason,created_at FROM withdrawals WHERE user_id=? ORDER BY id DESC LIMIT 20", (user["id"],)).fetchall()
    commissions = conn.execute("SELECT level,amount_cents,status,source_ledger_ref,created_at FROM commissions WHERE earner_id=? ORDER BY id DESC LIMIT 50", (user["id"],)).fetchall()
    referrals = conn.execute("SELECT COUNT(*) n FROM users WHERE referred_by=?", (user["id"],)).fetchone()["n"]
    return jsonify(
        user=user_json(user),
        wallet={"available_pkr": wallet["available_cents"]/100, "pending_pkr": wallet["pending_cents"]/100},
        ledger=[dict(r) for r in ledger],
        deposits=[dict(r) for r in deposits],
        withdrawals=[dict(r) for r in withdrawals],
        commissions=[dict(r) for r in commissions],
        direct_referrals=referrals
    )

@app.post("/api/deposits")
@login_required
def create_deposit():
    data = request.get_json(silent=True) or {}
    try:
        amount = money_to_cents(data.get("amount"))
    except ValueError as e:
        return jsonify(error=str(e)), 400
    txref = str(data.get("transaction_ref", "")).strip()
    if not txref or len(txref) > 120:
        return jsonify(error="Provide a valid payment transaction reference."), 400
    user = current_user()
    cur = db().execute("INSERT INTO deposits(user_id,amount_cents,transaction_ref) VALUES(?,?,?)",
                       (user["id"], amount, txref))
    audit(user["id"], "deposit_submitted", f"deposit_id={cur.lastrowid}")
    db().commit()
    return jsonify(message="Deposit request submitted for manual verification. No balance has been credited yet.", deposit_id=cur.lastrowid), 201

@app.post("/api/withdrawals")
@login_required
def create_withdrawal():
    data = request.get_json(silent=True) or {}
    try:
        amount = money_to_cents(data.get("amount"))
    except ValueError as e:
        return jsonify(error=str(e)), 400
    method = str(data.get("payout_method", "")).strip()
    details = str(data.get("payout_details", "")).strip()
    if not method or len(method) > 40 or not details or len(details) > 300:
        return jsonify(error="Enter a valid payout method and payout details."), 400
    user = current_user()
    conn = db()
    min_row = conn.execute("SELECT value FROM settings WHERE key='minimum_withdrawal_pkr'").fetchone()
    min_cents = int(Decimal(min_row["value"]) * 100) if min_row else 50000
    if amount < min_cents:
        return jsonify(error=f"Minimum withdrawal is PKR {min_cents/100:.2f}."), 400
    try:
        conn.execute("BEGIN IMMEDIATE")
        wallet = conn.execute("SELECT * FROM wallets WHERE user_id=?", (user["id"],)).fetchone()
        if wallet["available_cents"] < amount:
            conn.rollback()
            return jsonify(error="Insufficient available balance."), 400
        conn.execute("UPDATE wallets SET available_cents=available_cents-?, pending_cents=pending_cents+? WHERE user_id=?",
                     (amount, amount, user["id"]))
        cur = conn.execute("INSERT INTO withdrawals(user_id,amount_cents,payout_method,payout_details) VALUES(?,?,?,?)",
                           (user["id"], amount, method, details))
        ref = new_ref("WD")
        conn.execute("INSERT INTO ledger(ref,user_id,entry_type,amount_cents,status,description,related_ref) VALUES(?,?,?,?,?,?,?)",
                     (ref, user["id"], "withdrawal_hold", -amount, "pending", "Withdrawal reserved pending admin review", str(cur.lastrowid)))
        audit(user["id"], "withdrawal_requested", f"withdrawal_id={cur.lastrowid}")
        conn.commit()
        return jsonify(message="Withdrawal request submitted for review.", withdrawal_id=cur.lastrowid), 201
    except Exception:
        conn.rollback()
        raise

@app.post("/api/support")
@login_required
def support():
    data = request.get_json(silent=True) or {}
    subject = str(data.get("subject", "")).strip()
    message = str(data.get("message", "")).strip()
    if not subject or len(subject) > 150 or not message or len(message) > 4000:
        return jsonify(error="Enter a subject and message."), 400
    user = current_user()
    cur = db().execute("INSERT INTO support_tickets(user_id,subject,message) VALUES(?,?,?)",
                       (user["id"], subject, message))
    db().commit()
    return jsonify(ticket_id=cur.lastrowid, message="Support ticket submitted."), 201

# Admin bootstrap: create the first admin only when the environment secret is set and no admin exists.
@app.post("/api/setup/first-admin")
def first_admin():
    if not os.environ.get("LORAearn_SETUP_TOKEN"):
        return jsonify(error="First-admin setup is disabled. Set LORAearn_SETUP_TOKEN temporarily."), 403
    data = request.get_json(silent=True) or {}
    if not secrets.compare_digest(str(data.get("setup_token", "")), os.environ["LORAearn_SETUP_TOKEN"]):
        return jsonify(error="Invalid setup token."), 403
    conn = db()
    if conn.execute("SELECT id FROM users WHERE role='admin' LIMIT 1").fetchone():
        return jsonify(error="An administrator already exists."), 409
    name, email, phone, password = [str(data.get(k, "")).strip() for k in ("name","email","phone","password")]
    if not name or "@" not in email or len(password) < 14 or not phone:
        return jsonify(error="Provide valid details and a password of at least 14 characters."), 400
    code = referral_code()
    try:
        cur = conn.execute("INSERT INTO users(member_id,name,email,phone,password_hash,role,referral_code) VALUES(?,?,?,?,?,'admin',?)",
                           ("LR-ADMIN-" + secrets.token_hex(4).upper(), name, email.lower(), phone,
                            generate_password_hash(password), code))
        conn.execute("INSERT INTO wallets(user_id) VALUES(?)", (cur.lastrowid,))
        audit(cur.lastrowid, "first_admin_created", "First administrator bootstrap")
        conn.commit()
        return jsonify(message="Admin created. Remove LORAearn_SETUP_TOKEN from the environment now."), 201
    except sqlite3.IntegrityError:
        conn.rollback()
        return jsonify(error="Email already exists."), 409

@app.get("/api/admin/overview")
@admin_required
def admin_overview():
    conn = db()
    return jsonify(
        members=conn.execute("SELECT COUNT(*) n FROM users WHERE role='member'").fetchone()["n"],
        pending_deposits=conn.execute("SELECT COUNT(*) n FROM deposits WHERE status='pending'").fetchone()["n"],
        pending_withdrawals=conn.execute("SELECT COUNT(*) n FROM withdrawals WHERE status='pending'").fetchone()["n"],
        active_plans=conn.execute("SELECT COUNT(*) n FROM plans WHERE active=1").fetchone()["n"],
        settings={r["key"]:r["value"] for r in conn.execute("SELECT key,value FROM settings")}
    )

@app.get("/api/admin/members")
@admin_required
def admin_members():
    rows = db().execute("SELECT id,member_id,name,email,phone,role,referral_code,status,created_at FROM users ORDER BY id DESC LIMIT 500").fetchall()
    return jsonify(members=[dict(r) for r in rows])

@app.post("/api/admin/plans")
@admin_required
def admin_create_plan():
    data = request.get_json(silent=True) or {}
    name, description, reward_rule = [str(data.get(k, "")).strip() for k in ("name","description","reward_rule")]
    try:
        amount = money_to_cents(data.get("qualifying_amount", 0.01))
    except ValueError as e:
        return jsonify(error=str(e)), 400
    if not name or len(name) > 120:
        return jsonify(error="Plan name is required and must be under 120 characters."), 400
    user = current_user()
    cur = db().execute("INSERT INTO plans(name,description,qualifying_amount_cents,reward_rule,active) VALUES(?,?,?,?,?)",
                       (name, description[:2000], amount, reward_rule[:2000], 1 if data.get("active", True) else 0))
    audit(user["id"], "plan_created", f"plan_id={cur.lastrowid}")
    db().commit()
    return jsonify(plan_id=cur.lastrowid, message="Plan created."), 201

@app.patch("/api/admin/plans/<int:plan_id>")
@admin_required
def admin_update_plan(plan_id):
    data = request.get_json(silent=True) or {}
    conn = db()
    plan = conn.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
    if not plan:
        return jsonify(error="Plan not found."), 404
    name = str(data.get("name", plan["name"])).strip()
    description = str(data.get("description", plan["description"]))[:2000]
    reward_rule = str(data.get("reward_rule", plan["reward_rule"]))[:2000]
    active = int(bool(data.get("active", plan["active"])))
    if "qualifying_amount" in data:
        try: amount = money_to_cents(data["qualifying_amount"])
        except ValueError as e: return jsonify(error=str(e)), 400
    else:
        amount = plan["qualifying_amount_cents"]
    conn.execute("UPDATE plans SET name=?,description=?,reward_rule=?,active=?,qualifying_amount_cents=? WHERE id=?",
                 (name, description, reward_rule, active, amount, plan_id))
    user = current_user()
    audit(user["id"], "plan_updated", f"plan_id={plan_id}")
    conn.commit()
    return jsonify(message="Plan updated.")

@app.post("/api/admin/settings")
@admin_required
def admin_settings():
    data = request.get_json(silent=True) or {}
    allowed = {"currency", "direct_commission_percent", "indirect_commission_percent",
               "minimum_withdrawal_pkr", "maintenance_mode"}
    conn = db()
    for key, value in data.items():
        if key not in allowed:
            return jsonify(error=f"Setting not allowed: {key}"), 400
        val = str(value).strip()
        if key.endswith("_commission_percent") or key == "minimum_withdrawal_pkr":
            try:
                n = Decimal(val)
                if not n.is_finite() or n < 0 or (key.endswith("_commission_percent") and n > 100):
                    raise ValueError()
            except Exception:
                return jsonify(error=f"Invalid value for {key}."), 400
        conn.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                     (key, val))
    user = current_user()
    audit(user["id"], "settings_updated", ",".join(data.keys()))
    conn.commit()
    return jsonify(message="Settings saved.")

@app.get("/api/admin/deposits")
@admin_required
def admin_deposits():
    rows = db().execute("""SELECT d.*,u.member_id,u.name,u.email FROM deposits d JOIN users u ON u.id=d.user_id
                           ORDER BY d.id DESC LIMIT 500""").fetchall()
    return jsonify(deposits=[dict(r) for r in rows])

@app.post("/api/admin/deposits/<int:deposit_id>/review")
@admin_required
def review_deposit(deposit_id):
    data = request.get_json(silent=True) or {}
    decision = str(data.get("decision", "")).lower()
    if decision not in ("approve", "reject"):
        return jsonify(error="Decision must be approve or reject."), 400
    conn = db()
    admin = current_user()
    try:
        conn.execute("BEGIN IMMEDIATE")
        dep = conn.execute("SELECT * FROM deposits WHERE id=?", (deposit_id,)).fetchone()
        if not dep or dep["status"] != "pending":
            conn.rollback()
            return jsonify(error="Deposit not found or already reviewed."), 409
        status = "approved" if decision == "approve" else "rejected"
        conn.execute("UPDATE deposits SET status=?,reviewed_by=? WHERE id=?", (status, admin["id"], deposit_id))
        if decision == "approve":
            conn.execute("UPDATE wallets SET available_cents=available_cents+? WHERE user_id=?",
                         (dep["amount_cents"], dep["user_id"]))
            conn.execute("INSERT INTO ledger(ref,user_id,entry_type,amount_cents,status,description,related_ref) VALUES(?,?,?,?,?,?,?)",
                         (new_ref("DP"), dep["user_id"], "deposit", dep["amount_cents"], "approved",
                          "Admin-approved deposit", str(deposit_id)))
        audit(admin["id"], "deposit_reviewed", f"deposit_id={deposit_id};decision={decision}")
        conn.commit()
        return jsonify(message=f"Deposit {status}.")
    except Exception:
        conn.rollback()
        raise

@app.get("/api/admin/withdrawals")
@admin_required
def admin_withdrawals():
    rows = db().execute("""SELECT w.*,u.member_id,u.name,u.email FROM withdrawals w JOIN users u ON u.id=w.user_id
                           ORDER BY w.id DESC LIMIT 500""").fetchall()
    # Do not expose payout details in the listing endpoint; retrieve only when needed via restricted admin workflow.
    safe = []
    for r in rows:
        item = dict(r); item.pop("payout_details", None); safe.append(item)
    return jsonify(withdrawals=safe)

@app.post("/api/admin/withdrawals/<int:withdrawal_id>/review")
@admin_required
def review_withdrawal(withdrawal_id):
    data = request.get_json(silent=True) or {}
    decision = str(data.get("decision", "")).lower()
    if decision not in ("approve", "reject", "paid"):
        return jsonify(error="Decision must be approve, reject, or paid."), 400
    payout_ref = str(data.get("payout_ref", "")).strip()[:120]
    reason = str(data.get("rejection_reason", "")).strip()[:500]
    conn = db()
    admin = current_user()
    try:
        conn.execute("BEGIN IMMEDIATE")
        w = conn.execute("SELECT * FROM withdrawals WHERE id=?", (withdrawal_id,)).fetchone()
        if not w or w["status"] not in ("pending", "processing"):
            conn.rollback()
            return jsonify(error="Withdrawal not found or cannot be reviewed in its current state."), 409
        if decision == "approve":
            conn.execute("UPDATE withdrawals SET status='processing',reviewed_by=? WHERE id=?", (admin["id"], withdrawal_id))
        elif decision == "paid":
            if not payout_ref:
                conn.rollback()
                return jsonify(error="A verified payout reference is required."), 400
            conn.execute("UPDATE withdrawals SET status='paid',payout_ref=?,reviewed_by=? WHERE id=?", (payout_ref, admin["id"], withdrawal_id))
            conn.execute("UPDATE wallets SET pending_cents=pending_cents-? WHERE user_id=?", (w["amount_cents"], w["user_id"]))
            conn.execute("INSERT INTO ledger(ref,user_id,entry_type,amount_cents,status,description,related_ref) VALUES(?,?,?,?,?,?,?)",
                         (new_ref("PAID"), w["user_id"], "withdrawal_paid", 0, "paid",
                          "Payout confirmed by administrator; reserved amount already deducted", str(withdrawal_id)))
        else:
            conn.execute("UPDATE withdrawals SET status='rejected',rejection_reason=?,reviewed_by=? WHERE id=?", (reason or "Rejected by administrator", admin["id"], withdrawal_id))
            conn.execute("UPDATE wallets SET available_cents=available_cents+?,pending_cents=pending_cents-? WHERE user_id=?",
                         (w["amount_cents"], w["amount_cents"], w["user_id"]))
            conn.execute("UPDATE ledger SET status='reversed' WHERE related_ref=? AND entry_type='withdrawal_hold'", (str(withdrawal_id),))
            conn.execute("INSERT INTO ledger(ref,user_id,entry_type,amount_cents,status,description,related_ref) VALUES(?,?,?,?,?,?,?)",
                         (new_ref("REV"), w["user_id"], "withdrawal_release", w["amount_cents"], "posted",
                          "Reserved withdrawal released after rejection", str(withdrawal_id)))
        audit(admin["id"], "withdrawal_reviewed", f"withdrawal_id={withdrawal_id};decision={decision}")
        conn.commit()
        return jsonify(message="Withdrawal updated.")
    except Exception:
        conn.rollback()
        raise

@app.get("/api/admin/audit-logs")
@admin_required
def audit_logs():
    rows = db().execute("SELECT id,actor_id,action,details,created_at FROM audit_logs ORDER BY id DESC LIMIT 500").fetchall()
    return jsonify(logs=[dict(r) for r in rows])

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
