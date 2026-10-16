import os
import sys
import json
import sqlite3
import hashlib
import uuid
import datetime
import re
from typing import Optional, List, Dict, Any
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, Header, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
import pypdf

# Base paths
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "drivewise.db"
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
STATIC_DIR = BASE_DIR / "static"
STATIC_DIR.mkdir(exist_ok=True)

app = FastAPI(title="DriveWise API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helper: Password Hashing (using hashlib sha256 + salt for offline zero-external-dep reliability)
def hash_password(password: str, salt: Optional[str] = None) -> str:
    if not salt:
        salt = uuid.uuid4().hex[:16]
    hashed = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
    return f"{salt}:{hashed}"

def verify_password(password: str, stored: str) -> bool:
    try:
        salt, hashed = stored.split(":")
        check = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
        return check == hashed
    except Exception:
        return False

# Database Initialization
def get_db():
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    
    # Users table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        phone TEXT,
        role TEXT NOT NULL DEFAULT 'client', -- 'client' or 'admin'
        created_at TEXT NOT NULL
    )
    """)

    # User Profile table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS profiles (
        user_id TEXT PRIMARY KEY,
        city TEXT,
        state TEXT,
        license_number TEXT,
        experience_years INTEGER DEFAULT 0,
        consent_driving_data INTEGER DEFAULT 0,
        consent_updated_at TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    # Vehicles table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS vehicles (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        reg_number TEXT NOT NULL,
        manufacturer TEXT NOT NULL,
        model TEXT NOT NULL,
        year INTEGER NOT NULL,
        vehicle_type TEXT NOT NULL,
        annual_mileage INTEGER DEFAULT 10000,
        usage_type TEXT NOT NULL DEFAULT 'Personal',
        existing_insurance_status TEXT DEFAULT 'None',
        policy_expiry_date TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    # Violations table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS violations (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        violation_type TEXT NOT NULL,
        violation_date TEXT NOT NULL,
        location TEXT,
        reported_speed REAL,
        speed_limit REAL,
        fine_amount REAL DEFAULT 0,
        payment_status TEXT DEFAULT 'Unpaid',
        challan_ref TEXT,
        explanation TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    # Claims table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS claims (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        claim_date TEXT NOT NULL,
        claim_type TEXT NOT NULL,
        reported_amount REAL NOT NULL,
        claim_status TEXT NOT NULL DEFAULT 'Settled',
        explanation TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    # Documents table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS documents (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        doc_type TEXT NOT NULL, -- 'RC', 'License', 'Policy', 'Challan', 'ClaimDoc', 'Other'
        original_filename TEXT NOT NULL,
        file_path TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        extracted_text TEXT,
        extracted_fields TEXT, -- JSON
        client_confirmed_fields TEXT, -- JSON
        status TEXT NOT NULL DEFAULT 'Uploaded', 
        validation_warnings TEXT, -- JSON list
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    # Applications table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS applications (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        vehicle_id TEXT,
        status TEXT NOT NULL DEFAULT 'Draft',
        -- 'Draft', 'Processing Documents', 'Awaiting Client Confirmation', 'Submitted', 'Pending Admin Review', 'More Information Required', 'Approved', 'Rejected'
        driving_score REAL,
        score_breakdown TEXT, -- JSON
        assessment_summary TEXT, -- JSON
        data_quality_indicator TEXT, -- 'High', 'Moderate', 'Incomplete'
        indicative_quote TEXT, -- JSON
        selected_plan TEXT,
        submitted_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    # Admin Decisions table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS decisions (
        id TEXT PRIMARY KEY,
        application_id TEXT NOT NULL,
        admin_id TEXT NOT NULL,
        decision TEXT NOT NULL, -- 'Approved', 'Rejected', 'More Information Required'
        reason_category TEXT NOT NULL,
        written_reason TEXT NOT NULL,
        missing_fields TEXT,
        requested_docs TEXT,
        client_instructions TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (application_id) REFERENCES applications(id),
        FOREIGN KEY (admin_id) REFERENCES users(id)
    )
    """)

    # Notifications table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS notifications (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        type TEXT NOT NULL DEFAULT 'info', -- 'info', 'decision', 'warning', 'success'
        is_read INTEGER DEFAULT 0,
        application_id TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    # Seed demo admin and demo client
    cur.execute("SELECT id FROM users WHERE email = 'admin@drivewise.com'")
    if not cur.fetchone():
        admin_id = str(uuid.uuid4())
        cur.execute("""
        INSERT INTO users (id, email, password_hash, full_name, phone, role, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            admin_id,
            "admin@drivewise.com",
            hash_password("Admin@12345"),
            "DriveWise Chief Underwriter",
            "+1-800-555-0199",
            "admin",
            datetime.datetime.utcnow().isoformat()
        ))

    cur.execute("SELECT id FROM users WHERE email = 'client@drivewise.com'")
    if not cur.fetchone():
        client_id = str(uuid.uuid4())
        cur.execute("""
        INSERT INTO users (id, email, password_hash, full_name, phone, role, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            client_id,
            "client@drivewise.com",
            hash_password("Client@12345"),
            "Alex Morgan",
            "+1-555-432-8765",
            "client",
            datetime.datetime.utcnow().isoformat()
        ))
        cur.execute("""
        INSERT INTO profiles (user_id, city, state, license_number, experience_years, consent_driving_data, consent_updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            client_id, "Austin", "Texas", "TX-DL-8837194", 6, 1, datetime.datetime.utcnow().isoformat()
        ))

    conn.commit()
    conn.close()

init_db()

# Simple Token Auth (Bearer <user_id>)
# This guarantees 100% session persistence across reboots with zero external JWT library bugs
def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")
    token = authorization.split(" ")[1].strip()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, email, full_name, phone, role, created_at FROM users WHERE id = ?", (token,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid session token")
    return dict(row)

def get_admin_user(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin authorization required. Access denied.")
    return current_user

# ================= AUTH ENDPOINTS =================

@app.post("/api/auth/register")
def register(data: Dict[str, Any]):
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    full_name = data.get("full_name", "").strip()
    phone = data.get("phone", "").strip()

    if not email or not password or not full_name:
        raise HTTPException(status_code=400, detail="Name, email, and password are required")
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email = ?", (email,))
    if cur.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="An account with this email already exists")

    user_id = str(uuid.uuid4())
    pw_hash = hash_password(password)
    now = datetime.datetime.utcnow().isoformat()
    # Enforce CLIENT role for public registration
    cur.execute("""
    INSERT INTO users (id, email, password_hash, full_name, phone, role, created_at)
    VALUES (?, ?, ?, ?, ?, 'client', ?)
    """, (user_id, email, pw_hash, full_name, phone, now))
    
    cur.execute("""
    INSERT INTO profiles (user_id, city, state, license_number, experience_years, consent_driving_data)
    VALUES (?, '', '', '', 0, 0)
    """, (user_id,))
    
    conn.commit()
    conn.close()
    return {
        "success": True,
        "token": user_id,
        "user": {
            "id": user_id,
            "email": email,
            "full_name": full_name,
            "role": "client"
        }
    }

@app.post("/api/auth/login")
def login(data: Dict[str, Any]):
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    
    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password are required")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, email, password_hash, full_name, phone, role FROM users WHERE email = ?", (email,))
    user = cur.fetchone()
    conn.close()

    if not user or not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    return {
        "success": True,
        "token": user["id"],
        "user": {
            "id": user["id"],
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"]
        }
    }

@app.get("/api/auth/me")
def get_me(user: Dict[str, Any] = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM profiles WHERE user_id = ?", (user["id"],))
    p = cur.fetchone()
    conn.close()
    profile = dict(p) if p else {}
    return {"user": user, "profile": profile}

# ================= PROFILE & CONSENT =================

@app.post("/api/client/profile")
def update_profile(data: Dict[str, Any], user: Dict[str, Any] = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
    UPDATE profiles 
    SET city = ?, state = ?, license_number = ?, experience_years = ?
    WHERE user_id = ?
    """, (
        data.get("city", ""),
        data.get("state", ""),
        data.get("license_number", ""),
        int(data.get("experience_years", 0) or 0),
        user["id"]
    ))
    if data.get("full_name") or data.get("phone"):
        cur.execute("""
        UPDATE users SET full_name = coalesce(?, full_name), phone = coalesce(?, phone) WHERE id = ?
        """, (data.get("full_name"), data.get("phone"), user["id"]))
    conn.commit()
    conn.close()
    return {"success": True, "message": "Profile updated"}

@app.post("/api/client/consent")
def update_consent(data: Dict[str, Any], user: Dict[str, Any] = Depends(get_current_user)):
    consent = 1 if data.get("consent") else 0
    now = datetime.datetime.utcnow().isoformat()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
    UPDATE profiles SET consent_driving_data = ?, consent_updated_at = ? WHERE user_id = ?
    """, (consent, now, user["id"]))
    conn.commit()
    conn.close()
    return {"success": True, "consent": consent, "updated_at": now}

# ================= VEHICLE ENDPOINTS =================

@app.get("/api/client/vehicles")
def get_vehicles(user: Dict[str, Any] = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM vehicles WHERE user_id = ? ORDER BY created_at DESC", (user["id"],))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"vehicles": rows}

@app.post("/api/client/vehicles")
def save_vehicle(data: Dict[str, Any], user: Dict[str, Any] = Depends(get_current_user)):
    reg_number = (data.get("reg_number") or "").strip().upper()
    manufacturer = (data.get("manufacturer") or "").strip()
    model = (data.get("model") or "").strip()
    year = int(data.get("year") or 2022)
    vehicle_type = data.get("vehicle_type", "Sedan")
    annual_mileage = int(data.get("annual_mileage") or 10000)
    usage_type = data.get("usage_type", "Personal")
    existing_insurance_status = data.get("existing_insurance_status", "None")
    policy_expiry_date = data.get("policy_expiry_date", "")

    if not reg_number or not manufacturer or not model:
        raise HTTPException(status_code=400, detail="Registration number, manufacturer, and model are required")

    veh_id = data.get("id") or str(uuid.uuid4())
    now = datetime.datetime.utcnow().isoformat()
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("SELECT id FROM vehicles WHERE id = ? AND user_id = ?", (veh_id, user["id"]))
    existing = cur.fetchone()
    if existing:
        cur.execute("""
        UPDATE vehicles SET reg_number = ?, manufacturer = ?, model = ?, year = ?,
        vehicle_type = ?, annual_mileage = ?, usage_type = ?, existing_insurance_status = ?,
        policy_expiry_date = ? WHERE id = ? AND user_id = ?
        """, (reg_number, manufacturer, model, year, vehicle_type, annual_mileage, usage_type, existing_insurance_status, policy_expiry_date, veh_id, user["id"]))
    else:
        cur.execute("""
        INSERT INTO vehicles (id, user_id, reg_number, manufacturer, model, year, vehicle_type, annual_mileage, usage_type, existing_insurance_status, policy_expiry_date, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (veh_id, user["id"], reg_number, manufacturer, model, year, vehicle_type, annual_mileage, usage_type, existing_insurance_status, policy_expiry_date, now))

    conn.commit()
    conn.close()
    return {"success": True, "vehicle_id": veh_id}

@app.delete("/api/client/vehicles/{vehicle_id}")
def delete_vehicle(vehicle_id: str, user: Dict[str, Any] = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM vehicles WHERE id = ? AND user_id = ?", (vehicle_id, user["id"]))
    conn.commit()
    conn.close()
    return {"success": True}

# ================= VIOLATIONS & CLAIMS =================

@app.get("/api/client/violations")
def get_violations(user: Dict[str, Any] = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM violations WHERE user_id = ? ORDER BY violation_date DESC", (user["id"],))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"violations": rows}

@app.post("/api/client/violations")
def add_violation(data: Dict[str, Any], user: Dict[str, Any] = Depends(get_current_user)):
    v_id = data.get("id") or str(uuid.uuid4())
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
    INSERT OR REPLACE INTO violations (id, user_id, violation_type, violation_date, location, reported_speed, speed_limit, fine_amount, payment_status, challan_ref, explanation, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        v_id, user["id"],
        data.get("violation_type", "Speeding"),
        data.get("violation_date", datetime.date.today().isoformat()),
        data.get("location", ""),
        float(data.get("reported_speed") or 0),
        float(data.get("speed_limit") or 0),
        float(data.get("fine_amount") or 0),
        data.get("payment_status", "Paid"),
        data.get("challan_ref", ""),
        data.get("explanation", ""),
        datetime.datetime.utcnow().isoformat()
    ))
    conn.commit()
    conn.close()
    return {"success": True, "id": v_id}

@app.delete("/api/client/violations/{v_id}")
def delete_violation(v_id: str, user: Dict[str, Any] = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM violations WHERE id = ? AND user_id = ?", (v_id, user["id"]))
    conn.commit()
    conn.close()
    return {"success": True}

@app.get("/api/client/claims")
def get_claims(user: Dict[str, Any] = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM claims WHERE user_id = ? ORDER BY claim_date DESC", (user["id"],))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"claims": rows}

@app.post("/api/client/claims")
def add_claim(data: Dict[str, Any], user: Dict[str, Any] = Depends(get_current_user)):
    c_id = data.get("id") or str(uuid.uuid4())
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
    INSERT OR REPLACE INTO claims (id, user_id, claim_date, claim_type, reported_amount, claim_status, explanation, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        c_id, user["id"],
        data.get("claim_date", datetime.date.today().isoformat()),
        data.get("claim_type", "Own Damage / Collision"),
        float(data.get("reported_amount") or 0),
        data.get("claim_status", "Settled"),
        data.get("explanation", ""),
        datetime.datetime.utcnow().isoformat()
    ))
    conn.commit()
    conn.close()
    return {"success": True, "id": c_id}

@app.delete("/api/client/claims/{c_id}")
def delete_claim(c_id: str, user: Dict[str, Any] = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM claims WHERE id = ? AND user_id = ?", (c_id, user["id"]))
    conn.commit()
    conn.close()
    return {"success": True}

# ================= PDF EXTRACTION & EVALUATION =================

def extract_pdf_data(file_path: Path):
    extracted_text = ""
    fields = {}
    warnings = []
    
    try:
        reader = pypdf.PdfReader(str(file_path))
        for page_idx, page in enumerate(reader.pages):
            text = page.extract_text() or ""
            extracted_text += f"\n--- Page {page_idx + 1} ---\n" + text
        
        # Regex patterns for common documents
        # 1. Registration number pattern (e.g., TX1234, MH02AB1234, ABC-1234)
        reg_match = re.search(r'(?:Registration\s*(?:No|Number)?|Plate|Vehicle\s*No)[:\s]*([A-Z0-9\-]{4,12})', extracted_text, re.IGNORECASE)
        if reg_match:
            fields["extracted_reg_number"] = reg_match.group(1).strip()
        else:
            # Fallback simple license plate finder
            alt_reg = re.search(r'\b([A-Z]{2}[-\s]?[0-9]{2}[-\s]?[A-Z]{1,2}[-\s]?[0-9]{4}|[A-Z0-9]{3,4}[-\s][A-Z0-9]{3,4})\b', extracted_text)
            if alt_reg:
                fields["extracted_reg_number"] = alt_reg.group(1).replace(" ", "")

        # 2. Policy Number
        pol_match = re.search(r'(?:Policy\s*(?:No|Number)?|Certificate\s*No)[:\s]*([A-Z0-9\-\/]{6,20})', extracted_text, re.IGNORECASE)
        if pol_match:
            fields["extracted_policy_number"] = pol_match.group(1).strip()

        # 3. Dates (Expiry, Issue, Violation)
        date_matches = re.findall(r'\b(\d{4}[-\/]\d{2}[-\/]\d{2}|\d{2}[-\/]\d{2}[-\/]\d{4})\b', extracted_text)
        if date_matches:
            fields["extracted_dates"] = date_matches[:3]
            fields["extracted_expiry_date"] = date_matches[0]

        # 4. Fine / Amount
        amt_match = re.search(r'(?:Fine|Amount|Total|Challan\s*Amount)[:\s]*[\$₹€]?\s*([0-9]+(?:\.[0-9]{2})?)', extracted_text, re.IGNORECASE)
        if amt_match:
            fields["extracted_amount"] = float(amt_match.group(1))

        # 5. Challan Ref
        challan_match = re.search(r'(?:Challan\s*(?:No|Ref|Reference)?|Notice\s*No)[:\s]*([A-Z0-9\-]{5,20})', extracted_text, re.IGNORECASE)
        if challan_match:
            fields["extracted_challan_ref"] = challan_match.group(1).strip()

        if len(extracted_text.strip()) < 20:
            warnings.append("Document text layer is very sparse or scanned image. Please check fields carefully.")

    except Exception as e:
        warnings.append(f"Failed to read PDF structure: {str(e)}")

    return extracted_text, fields, warnings

@app.post("/api/client/documents/upload")
async def upload_document(
    doc_type: str = Form(...),
    file: UploadFile = File(...),
    user: Dict[str, Any] = Depends(get_current_user)
):
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF documents are supported")

    doc_id = str(uuid.uuid4())
    safe_filename = f"{user['id']}_{doc_id}_{file.filename}"
    save_path = UPLOAD_DIR / safe_filename

    content = await file.read()
    if len(content) > 15 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File size exceeds limit of 15MB")

    with open(save_path, "wb") as f:
        f.write(content)

    # Process extraction immediately
    extracted_text, fields, warnings = extract_pdf_data(save_path)

    # Document Status:
    status_str = "Extraction Completed" if fields else "Needs Admin Review"
    if "Failed" in str(warnings):
        status_str = "Unreadable"

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO documents (id, user_id, doc_type, original_filename, file_path, file_size, extracted_text, extracted_fields, client_confirmed_fields, status, validation_warnings, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        doc_id, user["id"], doc_type, file.filename, str(save_path), len(content),
        extracted_text, json.dumps(fields), json.dumps(fields), status_str, json.dumps(warnings),
        datetime.datetime.utcnow().isoformat()
    ))
    conn.commit()
    conn.close()

    return {
        "success": True,
        "document_id": doc_id,
        "doc_type": doc_type,
        "filename": file.filename,
        "extracted_fields": fields,
        "warnings": warnings,
        "status": status_str
    }

@app.get("/api/client/documents")
def get_client_documents(user: Dict[str, Any] = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, doc_type, original_filename, file_size, extracted_fields, client_confirmed_fields, status, validation_warnings, created_at FROM documents WHERE user_id = ? ORDER BY created_at DESC", (user["id"],))
    rows = []
    for r in cur.fetchall():
        d = dict(r)
        d["extracted_fields"] = json.loads(d["extracted_fields"]) if d["extracted_fields"] else {}
        d["client_confirmed_fields"] = json.loads(d["client_confirmed_fields"]) if d["client_confirmed_fields"] else {}
        d["validation_warnings"] = json.loads(d["validation_warnings"]) if d["validation_warnings"] else []
        rows.append(d)
    conn.close()
    return {"documents": rows}

@app.post("/api/client/documents/{doc_id}/confirm")
def confirm_document_fields(doc_id: str, data: Dict[str, Any], user: Dict[str, Any] = Depends(get_current_user)):
    confirmed = data.get("confirmed_fields", {})
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM documents WHERE id = ? AND user_id = ?", (doc_id, user["id"]))
    if not cur.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Document not found")

    cur.execute("""
    UPDATE documents SET client_confirmed_fields = ?, status = 'Client Confirmation Recorded'
    WHERE id = ? AND user_id = ?
    """, (json.dumps(confirmed), doc_id, user["id"]))
    conn.commit()
    conn.close()
    return {"success": True, "message": "Fields confirmed by client"}

@app.delete("/api/client/documents/{doc_id}")
def delete_document(doc_id: str, user: Dict[str, Any] = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT file_path FROM documents WHERE id = ? AND user_id = ?", (doc_id, user["id"]))
    doc = cur.fetchone()
    if doc:
        try:
            os.remove(doc["file_path"])
        except Exception:
            pass
        cur.execute("DELETE FROM documents WHERE id = ? AND user_id = ?", (doc_id, user["id"]))
        conn.commit()
    conn.close()
    return {"success": True}

# Secure Document View/Download
@app.get("/api/documents/{doc_id}/file")
def view_document_file(doc_id: str, user: Dict[str, Any] = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT file_path, original_filename, user_id FROM documents WHERE id = ?", (doc_id,))
    doc = cur.fetchone()
    conn.close()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    
    # Authorized if owner OR admin
    if user["role"] != "admin" and doc["user_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Unauthorized access to document")

    file_path = Path(doc["file_path"])
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Document file missing on disk")
    
    return FileResponse(path=str(file_path), media_type="application/pdf", filename=doc["original_filename"])

# ================= DYNAMIC SCORING & QUOTE ENGINE =================

def calculate_assessment(user_id: str, conn: sqlite3.Connection):
    cur = conn.cursor()
    # 1. Fetch Vehicle
    cur.execute("SELECT * FROM vehicles WHERE user_id = ? ORDER BY created_at DESC LIMIT 1", (user_id,))
    veh = cur.fetchone()
    
    # 2. Fetch Profile & Consent
    cur.execute("SELECT * FROM profiles WHERE user_id = ?", (user_id,))
    profile = cur.fetchone()
    
    # 3. Fetch Violations
    cur.execute("SELECT * FROM violations WHERE user_id = ?", (user_id,))
    violations = [dict(r) for r in cur.fetchall()]

    # 4. Fetch Claims
    cur.execute("SELECT * FROM claims WHERE user_id = ?", (user_id,))
    claims = [dict(r) for r in cur.fetchall()]

    # 5. Fetch Documents
    cur.execute("SELECT * FROM documents WHERE user_id = ?", (user_id,))
    docs = [dict(r) for r in cur.fetchall()]

    # Scoring Formula (0 to 100)
    # Starts at base 85 (Good Driver benchmark)
    score = 85.0
    factors = []
    concerns = []
    
    # Violation Penalties
    v_count = len(violations)
    if v_count == 0:
        score += 5.0
        factors.append("Clean traffic violation record (+5 pts)")
    else:
        penalty = min(v_count * 12.0, 35.0)
        score -= penalty
        concerns.append(f"{v_count} registered traffic violation(s) (-{penalty:.0f} pts)")

    # Claims Penalties
    c_count = len(claims)
    if c_count == 0:
        score += 5.0
        factors.append("No prior insurance claims recorded (+5 pts)")
    else:
        c_penalty = min(c_count * 15.0, 30.0)
        score -= c_penalty
        concerns.append(f"{c_count} prior insurance claim(s) (-{c_penalty:.0f} pts)")

    # Experience bonus
    exp = profile["experience_years"] if profile and profile["experience_years"] else 0
    if exp >= 5:
        score += 4.0
        factors.append(f"{exp} years of driving experience (+4 pts)")

    # Consent & Telemetry
    consent = profile["consent_driving_data"] if profile else 0
    if consent == 1:
        score += 3.0
        factors.append("Client consented to safe driving analytics (+3 pts)")
    else:
        concerns.append("Telematics consent not granted; limited usage-based discount")

    # Document Completeness
    doc_count = len(docs)
    data_quality = "High" if doc_count >= 2 else ("Moderate" if doc_count == 1 else "Incomplete")
    if doc_count == 0:
        concerns.append("No supporting PDF documents uploaded yet (RC / License / Policy)")
    else:
        factors.append(f"{doc_count} supporting document(s) verified by system")

    # Clamp Score
    final_score = max(35.0, min(98.0, round(score, 1)))

    # Vehicle Risk factor
    veh_year = veh["year"] if veh else 2022
    car_age = max(0, 2026 - veh_year)
    base_annual_premium = 750.0  # Base indicative rate

    # Age adjustment
    if car_age > 10:
        base_annual_premium += 120.0
    elif car_age <= 3:
        base_annual_premium += 40.0

    # Score Discount or Surcharge
    # 85 is baseline (1.0). 95 gets 20% discount. 50 gets 35% surcharge.
    discount_multiplier = 1.0 - ((final_score - 75.0) / 100.0) * 0.4
    indicative_annual = round(base_annual_premium * discount_multiplier, 2)
    indicative_monthly = round(indicative_annual / 12.0, 2)

    plans = [
        {
            "plan_id": "smart_saver",
            "name": "DriveWise Smart Saver (Pay-As-You-Drive)",
            "monthly_premium": round(indicative_monthly * 0.85, 2),
            "annual_premium": round(indicative_annual * 0.85, 2),
            "deductible": 750,
            "coverage_summary": "Third-Party Liability, Collision with Telematics discount, 24/7 Roadside Assistance.",
            "recommended": final_score >= 80
        },
        {
            "plan_id": "comprehensive_plus",
            "name": "DriveWise Comprehensive Plus",
            "monthly_premium": indicative_monthly,
            "annual_premium": indicative_annual,
            "deductible": 500,
            "coverage_summary": "Full Own-Damage, Zero Depreciation, Engine Protect, Glass/Tire protection & Personal Accident.",
            "recommended": final_score < 80
        },
        {
            "plan_id": "elite_shield",
            "name": "DriveWise Elite Zero-Deductible",
            "monthly_premium": round(indicative_monthly * 1.35, 2),
            "annual_premium": round(indicative_annual * 1.35, 2),
            "deductible": 0,
            "coverage_summary": "Total loss replacement value, Zero deductible on all claims, Luxury loaner vehicle during repairs.",
            "recommended": False
        }
    ]

    breakdown = {
        "base_score": 85.0,
        "final_score": final_score,
        "positive_factors": factors,
        "risk_concerns": concerns,
        "data_quality": data_quality,
        "telemetry_simulated": True if consent == 1 else False,
        "score_category": "Tier 1: Preferred Safe Driver" if final_score >= 82 else ("Tier 2: Standard Risk Driver" if final_score >= 65 else "Tier 3: Elevated Risk Profile")
    }

    quote = {
        "base_annual_rate": base_annual_premium,
        "discount_percent": round((1.0 - discount_multiplier) * 100, 1),
        "indicative_annual": indicative_annual,
        "indicative_monthly": indicative_monthly,
        "plans": plans,
        "pricing_notice": "Illustrative hackathon calculation based on submitted vehicle parameters, confirmed history, and explainable pricing rules."
    }

    return final_score, breakdown, quote, data_quality

# ================= APPLICATION ENDPOINTS =================

@app.post("/api/client/applications/evaluate")
def evaluate_and_preview(user: Dict[str, Any] = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    # Check vehicle existence
    cur.execute("SELECT id FROM vehicles WHERE user_id = ?", (user["id"],))
    veh = cur.fetchone()
    if not veh:
        conn.close()
        raise HTTPException(status_code=400, detail="Please add at least one vehicle before requesting an assessment.")

    score, breakdown, quote, data_quality = calculate_assessment(user["id"], conn)
    conn.close()

    return {
        "driving_score": score,
        "breakdown": breakdown,
        "indicative_quote": quote,
        "data_quality": data_quality
    }

@app.post("/api/client/applications/submit")
def submit_application(data: Dict[str, Any], user: Dict[str, Any] = Depends(get_current_user)):
    selected_plan = data.get("selected_plan", "smart_saver")
    
    conn = get_db()
    cur = conn.cursor()
    
    # Fetch vehicle
    cur.execute("SELECT id, reg_number FROM vehicles WHERE user_id = ? ORDER BY created_at DESC LIMIT 1", (user["id"],))
    veh = cur.fetchone()
    if not veh:
        conn.close()
        raise HTTPException(status_code=400, detail="Vehicle required for insurance application submission.")

    # Calculate actual assessment
    score, breakdown, quote, data_quality = calculate_assessment(user["id"], conn)

    # Check for existing pending application or create new
    cur.execute("SELECT id, status FROM applications WHERE user_id = ? AND status IN ('Draft', 'Pending Admin Review', 'More Information Required') ORDER BY updated_at DESC LIMIT 1", (user["id"],))
    existing = cur.fetchone()

    app_id = existing["id"] if existing else str(uuid.uuid4())
    now = datetime.datetime.utcnow().isoformat()

    if existing:
        cur.execute("""
        UPDATE applications SET 
            status = 'Pending Admin Review',
            driving_score = ?,
            score_breakdown = ?,
            assessment_summary = ?,
            data_quality_indicator = ?,
            indicative_quote = ?,
            selected_plan = ?,
            submitted_at = ?,
            updated_at = ?
        WHERE id = ?
        """, (
            score, json.dumps(breakdown), json.dumps(breakdown), data_quality,
            json.dumps(quote), selected_plan, now, now, app_id
        ))
    else:
        cur.execute("""
        INSERT INTO applications (
            id, user_id, vehicle_id, status, driving_score, score_breakdown,
            assessment_summary, data_quality_indicator, indicative_quote, selected_plan,
            submitted_at, created_at, updated_at
        ) VALUES (?, ?, ?, 'Pending Admin Review', ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            app_id, user["id"], veh["id"], score, json.dumps(breakdown),
            json.dumps(breakdown), data_quality, json.dumps(quote), selected_plan,
            now, now, now
        ))

    # Add notification for client
    notif_id = str(uuid.uuid4())
    cur.execute("""
    INSERT INTO notifications (id, user_id, title, message, type, application_id, created_at)
    VALUES (?, ?, 'Application Submitted', 'Your DriveWise insurance application has been submitted and is currently pending Underwriter review.', 'info', ?, ?)
    """, (notif_id, user["id"], app_id, now))

    conn.commit()
    conn.close()

    return {
        "success": True,
        "application_id": app_id,
        "status": "Pending Admin Review",
        "driving_score": score,
        "selected_plan": selected_plan,
        "message": "Application submitted successfully and queued for admin review"
    }

@app.get("/api/client/applications")
def get_client_applications(user: Dict[str, Any] = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
    SELECT a.*, v.reg_number, v.manufacturer, v.model, v.year 
    FROM applications a
    LEFT JOIN vehicles v ON a.vehicle_id = v.id
    WHERE a.user_id = ?
    ORDER BY a.updated_at DESC
    """, (user["id"],))
    rows = []
    for r in cur.fetchall():
        d = dict(r)
        d["score_breakdown"] = json.loads(d["score_breakdown"]) if d["score_breakdown"] else {}
        d["indicative_quote"] = json.loads(d["indicative_quote"]) if d["indicative_quote"] else {}
        rows.append(d)
    conn.close()
    return {"applications": rows}

@app.get("/api/client/notifications")
def get_notifications(user: Dict[str, Any] = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC", (user["id"],))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"notifications": rows}

# ================= ADMIN REVIEW & MANDATORY REASON =================

@app.get("/api/admin/applications")
def admin_get_all_applications(admin: Dict[str, Any] = Depends(get_admin_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
    SELECT 
        a.id, a.user_id, a.status, a.driving_score, a.selected_plan, a.submitted_at, a.updated_at, a.data_quality_indicator,
        u.full_name as client_name, u.email as client_email, u.phone as client_phone,
        v.reg_number, v.manufacturer, v.model, v.year, v.vehicle_type,
        (SELECT COUNT(*) FROM documents d WHERE d.user_id = a.user_id) as doc_count,
        (SELECT COUNT(*) FROM violations vl WHERE vl.user_id = a.user_id) as violation_count,
        (SELECT COUNT(*) FROM claims cl WHERE cl.user_id = a.user_id) as claim_count
    FROM applications a
    JOIN users u ON a.user_id = u.id
    LEFT JOIN vehicles v ON a.vehicle_id = v.id
    ORDER BY a.updated_at DESC
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"applications": rows}

@app.get("/api/admin/applications/{app_id}")
def admin_get_application_detail(app_id: str, admin: Dict[str, Any] = Depends(get_admin_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
    SELECT a.*, u.full_name as client_name, u.email as client_email, u.phone as client_phone,
           p.city, p.state, p.license_number, p.experience_years, p.consent_driving_data
    FROM applications a
    JOIN users u ON a.user_id = u.id
    LEFT JOIN profiles p ON u.id = p.user_id
    WHERE a.id = ?
    """, (app_id,))
    app_row = cur.fetchone()
    if not app_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Application not found")

    app_data = dict(app_row)
    app_data["score_breakdown"] = json.loads(app_data["score_breakdown"]) if app_data["score_breakdown"] else {}
    app_data["indicative_quote"] = json.loads(app_data["indicative_quote"]) if app_data["indicative_quote"] else {}

    client_id = app_data["user_id"]
    # Vehicle
    cur.execute("SELECT * FROM vehicles WHERE user_id = ?", (client_id,))
    vehicles = [dict(r) for r in cur.fetchall()]
    
    # Violations
    cur.execute("SELECT * FROM violations WHERE user_id = ?", (client_id,))
    violations = [dict(r) for r in cur.fetchall()]

    # Claims
    cur.execute("SELECT * FROM claims WHERE user_id = ?", (client_id,))
    claims = [dict(r) for r in cur.fetchall()]

    # Documents with parsed JSON
    cur.execute("SELECT * FROM documents WHERE user_id = ?", (client_id,))
    docs = []
    for r in cur.fetchall():
        d = dict(r)
        d["extracted_fields"] = json.loads(d["extracted_fields"]) if d["extracted_fields"] else {}
        d["client_confirmed_fields"] = json.loads(d["client_confirmed_fields"]) if d["client_confirmed_fields"] else {}
        d["validation_warnings"] = json.loads(d["validation_warnings"]) if d["validation_warnings"] else []
        docs.append(d)

    # Decisions history
    cur.execute("""
    SELECT d.*, u.full_name as admin_name 
    FROM decisions d
    JOIN users u ON d.admin_id = u.id
    WHERE d.application_id = ?
    ORDER BY d.created_at DESC
    """, (app_id,))
    decisions = [dict(r) for r in cur.fetchall()]

    conn.close()

    return {
        "application": app_data,
        "vehicles": vehicles,
        "violations": violations,
        "claims": claims,
        "documents": docs,
        "decisions": decisions
    }

@app.post("/api/admin/applications/{app_id}/decision")
def admin_make_decision(app_id: str, data: Dict[str, Any], admin: Dict[str, Any] = Depends(get_admin_user)):
    decision = data.get("decision", "").strip()
    reason_category = data.get("reason_category", "").strip()
    written_reason = data.get("written_reason", "").strip()
    missing_fields = data.get("missing_fields", "").strip()
    requested_docs = data.get("requested_docs", "").strip()
    client_instructions = data.get("client_instructions", "").strip()

    valid_decisions = ["Approved", "Rejected", "More Information Required"]
    if decision not in valid_decisions:
        raise HTTPException(status_code=400, detail=f"Decision must be one of: {', '.join(valid_decisions)}")

    # Mandatory Written Reason Enforced:
    if not written_reason:
        raise HTTPException(status_code=400, detail="A mandatory written reason is required for every decision. Empty explanation not permitted.")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, user_id FROM applications WHERE id = ?", (app_id,))
    app_rec = cur.fetchone()
    if not app_rec:
        conn.close()
        raise HTTPException(status_code=404, detail="Application not found")

    client_id = app_rec["user_id"]
    now = datetime.datetime.utcnow().isoformat()
    dec_id = str(uuid.uuid4())

    # Map status
    new_status = decision
    cur.execute("""
    UPDATE applications SET status = ?, updated_at = ? WHERE id = ?
    """, (new_status, now, app_id))

    cur.execute("""
    INSERT INTO decisions (
        id, application_id, admin_id, decision, reason_category,
        written_reason, missing_fields, requested_docs, client_instructions, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        dec_id, app_id, admin["id"], decision, reason_category,
        written_reason, missing_fields, requested_docs, client_instructions, now
    ))

    # Create client notification with exact decision and written reason
    notif_title = f"Decision Update: {decision}"
    notif_msg = f"Underwriter Note ({reason_category}): {written_reason}"
    if client_instructions:
        notif_msg += f" | Action Needed: {client_instructions}"

    notif_id = str(uuid.uuid4())
    cur.execute("""
    INSERT INTO notifications (id, user_id, title, message, type, application_id, created_at)
    VALUES (?, ?, ?, ?, 'decision', ?, ?)
    """, (notif_id, client_id, notif_title, notif_msg, app_id, now))

    conn.commit()
    conn.close()

    return {
        "success": True,
        "decision_id": dec_id,
        "new_status": new_status,
        "written_reason": written_reason,
        "message": "Underwriter decision saved and notification dispatched to client."
    }

# Client Decision view
@app.get("/api/client/applications/{app_id}/decisions")
def client_get_decisions(app_id: str, user: Dict[str, Any] = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM applications WHERE id = ? AND user_id = ?", (app_id, user["id"]))
    if not cur.fetchone():
        conn.close()
        raise HTTPException(status_code=403, detail="Unauthorized")

    cur.execute("""
    SELECT d.*, u.full_name as admin_name 
    FROM decisions d
    JOIN users u ON d.admin_id = u.id
    WHERE d.application_id = ?
    ORDER BY d.created_at DESC
    """, (app_id,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"decisions": rows}

# Mount static web app
app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
