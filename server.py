from dotenv import load_dotenv
from pathlib import Path
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

import os
import io
import csv
import uuid
import random
import base64
import logging
import bcrypt
import jwt
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, APIRouter, HTTPException, Request, Response, Depends, UploadFile, File
from fastapi.responses import StreamingResponse, Response as FAResponse
from starlette.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, EmailStr, ConfigDict


# -------------------- DB (MySQL JSON adapter — cPanel deployment) --------------------
from mongo_mysql import db_from_env
db = db_from_env()

app = FastAPI(title="TARA Finserv API")
api = APIRouter(prefix="/api")

JWT_ALGO = "HS256"
JWT_SECRET = os.environ["JWT_SECRET"]

logger = logging.getLogger("tara")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


# -------------------- Helpers --------------------
def now_iso():
    return datetime.now(timezone.utc).isoformat()


def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


def verify_password(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode(), hashed.encode())
    except Exception:
        return False


def create_token(sub: str, email: str, role: str, hours: int = 12) -> str:
    payload = {
        "sub": sub, "email": email, "role": role, "type": "access",
        "exp": datetime.now(timezone.utc) + timedelta(hours=hours),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def _extract_token(request: Request) -> Optional[str]:
    token = request.cookies.get("access_token")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    return token


def _decode(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")


async def get_current_admin(request: Request) -> dict:
    token = _extract_token(request)
    if not token:
        raise HTTPException(401, "Not authenticated")
    payload = _decode(token)
    if payload.get("role") != "admin":
        raise HTTPException(403, "Admin access required")
    user = await db.users.find_one({"id": payload["sub"]}, {"password_hash": 0})
    if not user:
        raise HTTPException(401, "User not found")
    user.pop("_id", None)
    return user


async def get_current_agent(request: Request) -> dict:
    token = _extract_token(request)
    if not token:
        raise HTTPException(401, "Not authenticated")
    payload = _decode(token)
    if payload.get("role") != "agent":
        raise HTTPException(403, "Agent access required")
    ag = await db.agents.find_one({"id": payload["sub"]}, {"password_hash": 0})
    if not ag:
        raise HTTPException(401, "Agent not found")
    ag.pop("_id", None)
    return ag


# -------------------- Pydantic models --------------------
class LoginIn(BaseModel):
    email: EmailStr
    password: str


class AgentLoginIn(BaseModel):
    code: str
    password: str


class AgentRegisterIn(BaseModel):
    name: str
    email: EmailStr
    phone: str
    password: str
    pan: Optional[str] = ""
    aadhaar_last4: Optional[str] = ""
    kyc_doc_base64: Optional[str] = ""
    kyc_doc_name: Optional[str] = ""
    agent_type: str = "Loan Agent"  # Loan Agent | Insurance Agent | Other


class AgentUpdateIn(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    status: Optional[str] = None  # Active | Suspended
    agent_type: Optional[str] = None


class ChangePwIn(BaseModel):
    current_password: str
    new_password: str


class PayoutIn(BaseModel):
    agent_code: str
    amount: float
    status: str = "Pending"  # Pending | Paid
    notes: Optional[str] = ""


class LeadIn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    full_name: str
    pan: Optional[str] = ""
    aadhaar: Optional[str] = ""
    mobile: str
    email: EmailStr
    employment_type: str
    monthly_income: float
    loan_amount: float
    loan_type: str
    tenure_months: Optional[int] = 60
    document_name: Optional[str] = ""
    document_base64: Optional[str] = ""
    consent: bool = True
    agent_code: Optional[str] = ""  # set automatically if agent submits


class LeadStatusUpdate(BaseModel):
    status: str
    notes: Optional[str] = ""


class ContactIn(BaseModel):
    name: str
    email: EmailStr
    phone: Optional[str] = ""
    subject: Optional[str] = ""
    message: str


class OTPSendIn(BaseModel):
    phone: str


class OTPVerifyIn(BaseModel):
    phone: str
    code: str


class MenuItemIn(BaseModel):
    title: str
    slug: str
    parent: Optional[str] = None
    order: int = 0
    is_dynamic: bool = False
    external_url: Optional[str] = ""


class PageIn(BaseModel):
    model_config = ConfigDict(extra="allow")
    slug: str
    title: str
    subtitle: Optional[str] = ""
    hero_image: Optional[str] = ""
    body_html: str
    meta_description: Optional[str] = ""
    gallery: Optional[List[str]] = None
    features: Optional[List[Dict[str, Any]]] = None


class PartnerIn(BaseModel):
    name: str
    category: str
    logo_url: Optional[str] = ""
    description: Optional[str] = ""


class SettingsIn(BaseModel):
    model_config = ConfigDict(extra="allow")
    twilio_account_sid: Optional[str] = None
    twilio_auth_token: Optional[str] = None
    twilio_from_number: Optional[str] = None
    otp_real_enabled: Optional[bool] = None


class ContentIn(BaseModel):
    """Big site_content blob. Any subset can be sent — merged on top."""
    model_config = ConfigDict(extra="allow")
    data: Dict[str, Any]


# -------------------- Auth --------------------
@api.post("/auth/login")
async def login(body: LoginIn, response: Response):
    user = await db.users.find_one({"email": body.email.lower()})
    if not user or not verify_password(body.password, user.get("password_hash", "")):
        raise HTTPException(401, "Invalid email or password")
    token = create_token(user["id"], user["email"], "admin")
    response.set_cookie("access_token", token, httponly=True, secure=False, samesite="lax",
                        max_age=12 * 3600, path="/")
    return {"id": user["id"], "email": user["email"], "name": user.get("name"),
            "role": "admin", "access_token": token}


@api.get("/auth/me")
async def me(user=Depends(get_current_admin)):
    return user


@api.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token", path="/")
    return {"ok": True}


# -------------------- Asset upload (admin) --------------------
ASSET_MAX_BYTES = 10_000_000  # 10 MB
ALLOWED_MIME = {"image/png", "image/jpeg", "image/jpg", "image/webp", "image/gif", "image/svg+xml",
                "application/pdf"}


@api.post("/admin/upload")
async def admin_upload(file: UploadFile = File(...), user=Depends(get_current_admin)):
    data = await file.read()
    if len(data) > ASSET_MAX_BYTES:
        raise HTTPException(400, "File too large (max 4 MB)")
    mime = file.content_type or "application/octet-stream"
    if mime not in ALLOWED_MIME and not mime.startswith("image/"):
        raise HTTPException(400, f"Unsupported file type: {mime}")
    asset_id = str(uuid.uuid4())
    await db.assets.insert_one({
        "id": asset_id,
        "filename": file.filename,
        "mime": mime,
        "size": len(data),
        "data": base64.b64encode(data).decode(),
        "created_at": now_iso(),
        "uploaded_by": user.get("email"),
    })
    return {"id": asset_id, "url": f"/api/assets/{asset_id}", "filename": file.filename, "size": len(data), "mime": mime}


@api.get("/assets/{asset_id}")
async def get_asset(asset_id: str):
    asset = await db.assets.find_one({"id": asset_id})
    if not asset:
        raise HTTPException(404, "Asset not found")
    return FAResponse(content=base64.b64decode(asset["data"]),
                      media_type=asset.get("mime", "application/octet-stream"),
                      headers={"Cache-Control": "public, max-age=31536000"})


# -------------------- OTP --------------------
async def _get_settings() -> dict:
    s = await db.settings.find_one({"_id": "global"}) or {}
    s.pop("_id", None)
    return s


async def _otp_enabled() -> bool:
    s = await _get_settings()
    return bool(s.get("otp_real_enabled") and s.get("twilio_account_sid")
                and s.get("twilio_auth_token") and s.get("twilio_from_number"))


@api.get("/otp/status")
async def otp_status():
    return {"enabled": await _otp_enabled()}


@api.post("/otp/send")
async def otp_send(body: OTPSendIn):
    if not await _otp_enabled():
        raise HTTPException(400, "OTP service is disabled")
    settings = await _get_settings()
    sid = settings.get("twilio_account_sid")
    tok = settings.get("twilio_auth_token")
    frm = settings.get("twilio_from_number")
    code = f"{random.randint(0, 999999):06d}"
    try:
        from twilio.rest import Client as TwilioClient
        tc = TwilioClient(sid, tok)
        tc.messages.create(
            to=body.phone, from_=frm,
            body=f"Your TARA Finserv OTP is {code}. Valid for 5 minutes.",
        )
    except Exception as e:
        logger.exception("Twilio send failed")
        raise HTTPException(502, f"Failed to send OTP: {e}")
    await db.otp_codes.update_one(
        {"phone": body.phone},
        {"$set": {"phone": body.phone, "code": code,
                  "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
                  "verified": False, "created_at": now_iso()}},
        upsert=True,
    )
    return {"ok": True}


@api.post("/otp/verify")
async def otp_verify(body: OTPVerifyIn):
    if not await _otp_enabled():
        raise HTTPException(400, "OTP service is disabled")
    rec = await db.otp_codes.find_one({"phone": body.phone})
    if not rec:
        raise HTTPException(400, "No OTP requested for this number")
    if datetime.fromisoformat(rec["expires_at"]) < datetime.now(timezone.utc):
        raise HTTPException(400, "OTP expired")
    if rec["code"] != body.code:
        raise HTTPException(400, "Invalid OTP")
    await db.otp_codes.update_one({"phone": body.phone}, {"$set": {"verified": True}})
    return {"verified": True}


# -------------------- Leads --------------------
@api.post("/leads")
async def submit_lead(body: LeadIn):
    if not body.consent:
        raise HTTPException(400, "Consent is required")
    # OTP only required when Twilio is active
    if await _otp_enabled():
        otp = await db.otp_codes.find_one({"phone": body.mobile})
        if not otp or not otp.get("verified"):
            raise HTTPException(400, "Mobile number is not OTP verified")
    doc = body.model_dump()
    doc["id"] = str(uuid.uuid4())
    doc["status"] = "Pending"
    doc["created_at"] = now_iso()
    doc["updated_at"] = now_iso()
    if doc.get("document_base64") and len(doc["document_base64"]) > 2_500_000:
        doc["document_base64"] = ""
        doc["document_oversized"] = True
    await db.leads.insert_one(doc)
    doc.pop("_id", None)
    return {"ok": True, "id": doc["id"]}


@api.get("/admin/leads")
async def admin_list_leads(
    user=Depends(get_current_admin),
    status: Optional[str] = None,
    loan_type: Optional[str] = None,
    agent_code: Optional[str] = None,
    q: Optional[str] = None,
):
    query = {}
    if status: query["status"] = status
    if loan_type: query["loan_type"] = loan_type
    if agent_code: query["agent_code"] = agent_code
    if q:
        query["$or"] = [
            {"full_name": {"$regex": q, "$options": "i"}},
            {"email": {"$regex": q, "$options": "i"}},
            {"mobile": {"$regex": q, "$options": "i"}},
            {"pan": {"$regex": q, "$options": "i"}},
            {"agent_code": {"$regex": q, "$options": "i"}},
        ]
    items = await db.leads.find(query, {"_id": 0, "document_base64": 0}).sort("created_at", -1).to_list(2000)
    return items


@api.get("/admin/leads/{lead_id}")
async def admin_get_lead(lead_id: str, user=Depends(get_current_admin)):
    lead = await db.leads.find_one({"id": lead_id}, {"_id": 0})
    if not lead:
        raise HTTPException(404, "Lead not found")
    return lead


@api.patch("/admin/leads/{lead_id}")
async def admin_update_lead(lead_id: str, body: LeadStatusUpdate, user=Depends(get_current_admin)):
    res = await db.leads.update_one({"id": lead_id},
                                    {"$set": {"status": body.status, "notes": body.notes,
                                              "updated_at": now_iso()}})
    if res.matched_count == 0:
        raise HTTPException(404, "Lead not found")
    return {"ok": True}


@api.get("/admin/leads-export")
async def admin_export_leads(user=Depends(get_current_admin)):
    items = await db.leads.find({}, {"_id": 0, "document_base64": 0}).sort("created_at", -1).to_list(5000)
    buff = io.StringIO()
    fields = ["id", "created_at", "status", "full_name", "email", "mobile", "pan",
              "employment_type", "monthly_income", "loan_amount", "loan_type",
              "tenure_months", "agent_code", "notes"]
    w = csv.DictWriter(buff, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    for it in items: w.writerow(it)
    buff.seek(0)
    return StreamingResponse(iter([buff.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": 'attachment; filename="tara_leads.csv"'})


# -------------------- Contact --------------------
@api.post("/contact")
async def submit_contact(body: ContactIn):
    doc = body.model_dump()
    doc["id"] = str(uuid.uuid4()); doc["created_at"] = now_iso()
    await db.contact_messages.insert_one(doc)
    return {"ok": True}


@api.get("/admin/contacts")
async def admin_contacts(user=Depends(get_current_admin)):
    return await db.contact_messages.find({}, {"_id": 0}).sort("created_at", -1).to_list(2000)


# -------------------- Menu --------------------
@api.get("/menu")
async def get_menu():
    return await db.menu_items.find({}, {"_id": 0}).sort("order", 1).to_list(500)


@api.post("/admin/menu")
async def admin_create_menu(body: MenuItemIn, user=Depends(get_current_admin)):
    doc = body.model_dump(); doc["id"] = str(uuid.uuid4()); doc["created_at"] = now_iso()
    await db.menu_items.insert_one(doc); doc.pop("_id", None); return doc


@api.patch("/admin/menu/{item_id}")
async def admin_update_menu(item_id: str, body: MenuItemIn, user=Depends(get_current_admin)):
    res = await db.menu_items.update_one({"id": item_id}, {"$set": body.model_dump()})
    if res.matched_count == 0: raise HTTPException(404, "Menu item not found")
    return {"ok": True}


@api.delete("/admin/menu/{item_id}")
async def admin_delete_menu(item_id: str, user=Depends(get_current_admin)):
    await db.menu_items.delete_one({"id": item_id}); return {"ok": True}


@api.post("/admin/menu-reorder")
async def admin_reorder_menu(body: Dict[str, Any], user=Depends(get_current_admin)):
    order_map = body.get("order", {})  # { menu_id: order_number }
    for mid, idx in order_map.items():
        await db.menu_items.update_one({"id": mid}, {"$set": {"order": int(idx)}})
    return {"ok": True}


# -------------------- Pages --------------------
@api.get("/pages/{slug}")
async def get_page(slug: str):
    page = await db.pages.find_one({"slug": slug}, {"_id": 0})
    if not page: raise HTTPException(404, "Page not found")
    return page


@api.get("/admin/pages")
async def admin_list_pages(user=Depends(get_current_admin)):
    return await db.pages.find({}, {"_id": 0}).sort("slug", 1).to_list(500)


@api.post("/admin/pages")
async def admin_upsert_page(body: PageIn, user=Depends(get_current_admin)):
    doc = body.model_dump(); doc["updated_at"] = now_iso()
    await db.pages.update_one({"slug": body.slug}, {"$set": doc}, upsert=True)
    return {"ok": True}


@api.delete("/admin/pages/{slug}")
async def admin_delete_page(slug: str, user=Depends(get_current_admin)):
    await db.pages.delete_one({"slug": slug}); return {"ok": True}


# -------------------- Partners --------------------
@api.get("/partners")
async def list_partners():
    return await db.partners.find({}, {"_id": 0}).sort("name", 1).to_list(500)


@api.post("/admin/partners")
async def admin_create_partner(body: PartnerIn, user=Depends(get_current_admin)):
    doc = body.model_dump(); doc["id"] = str(uuid.uuid4())
    await db.partners.insert_one(doc); doc.pop("_id", None); return doc


@api.patch("/admin/partners/{partner_id}")
async def admin_update_partner(partner_id: str, body: PartnerIn, user=Depends(get_current_admin)):
    res = await db.partners.update_one({"id": partner_id}, {"$set": body.model_dump()})
    if res.matched_count == 0: raise HTTPException(404, "Partner not found")
    return {"ok": True}


@api.delete("/admin/partners/{partner_id}")
async def admin_delete_partner(partner_id: str, user=Depends(get_current_admin)):
    await db.partners.delete_one({"id": partner_id}); return {"ok": True}


# -------------------- Settings & Content --------------------
@api.get("/settings")
async def get_public_settings():
    s = await _get_settings()
    return {
        "twilio_enabled": bool(s.get("otp_real_enabled") and s.get("twilio_account_sid")),
    }


@api.get("/admin/settings")
async def admin_get_settings(user=Depends(get_current_admin)):
    return await _get_settings()


@api.put("/admin/settings")
async def admin_update_settings(body: SettingsIn, user=Depends(get_current_admin)):
    update = {k: v for k, v in body.model_dump().items() if v is not None}
    update["updated_at"] = now_iso()
    await db.settings.update_one({"_id": "global"}, {"$set": update}, upsert=True)
    return await _get_settings()


@api.get("/content")
async def get_content():
    doc = await db.site_content.find_one({"_id": "main"}) or {}
    doc.pop("_id", None)
    return doc


@api.put("/admin/content")
async def admin_update_content(body: Dict[str, Any], user=Depends(get_current_admin)):
    update = {k: v for k, v in body.items() if k != "_id"}
    update["updated_at"] = now_iso()
    await db.site_content.update_one({"_id": "main"}, {"$set": update}, upsert=True)
    doc = await db.site_content.find_one({"_id": "main"}) or {}
    doc.pop("_id", None); return doc


@api.get("/stats")
async def get_stats():
    leads_total = await db.leads.count_documents({})
    return {"leads_total": leads_total}


@api.get("/health")
async def health():
    return {"ok": True, "service": "tara-finserv", "time": now_iso()}


# -------------------- Agents --------------------
async def _next_agent_code() -> str:
    res = await db.counters.find_one_and_update(
        {"_id": "agent_code"}, {"$inc": {"seq": 1}}, upsert=True, return_document=True,
    )
    seq = res["seq"] if res and "seq" in res else 1
    return f"TF{seq:05d}"


@api.post("/agents/register")
async def agent_register(body: AgentRegisterIn):
    if await db.agents.find_one({"email": body.email.lower()}):
        raise HTTPException(400, "Email already registered")
    code = await _next_agent_code()
    doc = {
        "id": str(uuid.uuid4()),
        "code": code,
        "name": body.name,
        "email": body.email.lower(),
        "phone": body.phone,
        "agent_type": body.agent_type,
        "password_hash": hash_password(body.password),
        "status": "Active",
        "kyc": {
            "pan": body.pan,
            "aadhaar_last4": body.aadhaar_last4,
            "doc_name": body.kyc_doc_name,
            "doc_base64": body.kyc_doc_base64 if body.kyc_doc_base64 and len(body.kyc_doc_base64) < 2_500_000 else "",
        },
        "created_at": now_iso(),
    }
    await db.agents.insert_one(doc)
    return {"ok": True, "code": code}


@api.post("/agents/login")
async def agent_login(body: AgentLoginIn, response: Response):
    ag = await db.agents.find_one({"code": body.code.upper()})
    if not ag or not verify_password(body.password, ag.get("password_hash", "")):
        raise HTTPException(401, "Invalid code or password")
    if ag.get("status") != "Active":
        raise HTTPException(403, "Agent account is not active")
    token = create_token(ag["id"], ag.get("email", ""), "agent")
    response.set_cookie("agent_token", token, httponly=True, secure=False, samesite="lax",
                        max_age=12 * 3600, path="/")
    return {"id": ag["id"], "code": ag["code"], "name": ag["name"], "email": ag["email"],
            "agent_type": ag.get("agent_type"), "role": "agent", "access_token": token}


@api.post("/agents/logout")
async def agent_logout(response: Response):
    response.delete_cookie("agent_token", path="/")
    return {"ok": True}


async def _get_agent_from_request(request: Request) -> dict:
    token = request.cookies.get("agent_token") or _extract_token(request)
    if not token:
        raise HTTPException(401, "Not authenticated")
    payload = _decode(token)
    if payload.get("role") != "agent":
        raise HTTPException(403, "Agent access required")
    ag = await db.agents.find_one({"id": payload["sub"]}, {"password_hash": 0})
    if not ag: raise HTTPException(401, "Agent not found")
    ag.pop("_id", None); return ag


@api.get("/agents/me")
async def agent_me(request: Request):
    return await _get_agent_from_request(request)


@api.post("/agents/change-password")
async def agent_change_pw(body: ChangePwIn, request: Request):
    ag = await _get_agent_from_request(request)
    full = await db.agents.find_one({"id": ag["id"]})
    if not verify_password(body.current_password, full.get("password_hash", "")):
        raise HTTPException(400, "Current password is incorrect")
    if len(body.new_password) < 6:
        raise HTTPException(400, "New password must be at least 6 characters")
    await db.agents.update_one({"id": ag["id"]}, {"$set": {"password_hash": hash_password(body.new_password)}})
    return {"ok": True}


@api.get("/agents/leads")
async def agent_my_leads(request: Request):
    ag = await _get_agent_from_request(request)
    items = await db.leads.find({"agent_code": ag["code"]}, {"_id": 0, "document_base64": 0}).sort("created_at", -1).to_list(2000)
    return items


@api.post("/agents/leads")
async def agent_create_lead(body: LeadIn, request: Request):
    ag = await _get_agent_from_request(request)
    if not body.consent:
        raise HTTPException(400, "Consent is required")
    doc = body.model_dump()
    doc["id"] = str(uuid.uuid4())
    doc["status"] = "Pending"
    doc["agent_code"] = ag["code"]
    doc["created_at"] = now_iso()
    doc["updated_at"] = now_iso()
    if doc.get("document_base64") and len(doc["document_base64"]) > 2_500_000:
        doc["document_base64"] = ""
    await db.leads.insert_one(doc)
    return {"ok": True, "id": doc["id"]}


@api.get("/agents/payouts")
async def agent_payouts(request: Request):
    ag = await _get_agent_from_request(request)
    items = await db.payouts.find({"agent_code": ag["code"]}, {"_id": 0}).sort("created_at", -1).to_list(500)
    # also compute lead-based earnings summary
    approved = await db.leads.count_documents({"agent_code": ag["code"], "status": "Approved"})
    pending = await db.leads.count_documents({"agent_code": ag["code"], "status": {"$in": ["Pending", "In Progress"]}})
    total_paid = sum((p.get("amount", 0) for p in items if p.get("status") == "Paid"))
    total_pending = sum((p.get("amount", 0) for p in items if p.get("status") == "Pending"))
    return {"items": items, "approved_leads": approved, "pending_leads": pending,
            "total_paid": total_paid, "total_pending": total_pending}


# Admin agent endpoints
@api.get("/admin/agents")
async def admin_list_agents(user=Depends(get_current_admin)):
    items = await db.agents.find({}, {"_id": 0, "password_hash": 0, "kyc.doc_base64": 0}).sort("created_at", -1).to_list(2000)
    return items


@api.post("/admin/agents")
async def admin_create_agent(body: AgentRegisterIn, user=Depends(get_current_admin)):
    return await agent_register(body)


@api.patch("/admin/agents/{agent_id}")
async def admin_update_agent(agent_id: str, body: AgentUpdateIn, user=Depends(get_current_admin)):
    update = {k: v for k, v in body.model_dump().items() if v is not None}
    if not update: return {"ok": True}
    res = await db.agents.update_one({"id": agent_id}, {"$set": update})
    if res.matched_count == 0: raise HTTPException(404, "Agent not found")
    return {"ok": True}


@api.post("/admin/agents/{agent_id}/reset-password")
async def admin_reset_agent_password(agent_id: str, body: Dict[str, Any], user=Depends(get_current_admin)):
    new_pw = body.get("new_password") or ""
    if len(new_pw) < 6: raise HTTPException(400, "Password must be at least 6 chars")
    res = await db.agents.update_one({"id": agent_id}, {"$set": {"password_hash": hash_password(new_pw)}})
    if res.matched_count == 0: raise HTTPException(404, "Agent not found")
    return {"ok": True}


@api.delete("/admin/agents/{agent_id}")
async def admin_delete_agent(agent_id: str, user=Depends(get_current_admin)):
    await db.agents.delete_one({"id": agent_id})
    return {"ok": True}


@api.get("/admin/agents-export")
async def admin_export_agents(user=Depends(get_current_admin)):
    items = await db.agents.find({}, {"_id": 0, "password_hash": 0, "kyc.doc_base64": 0}).sort("created_at", -1).to_list(5000)
    buff = io.StringIO()
    fields = ["code", "name", "email", "phone", "agent_type", "status", "created_at"]
    w = csv.DictWriter(buff, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    for it in items: w.writerow(it)
    buff.seek(0)
    return StreamingResponse(iter([buff.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": 'attachment; filename="tara_agents.csv"'})


@api.get("/admin/payouts")
async def admin_list_payouts(user=Depends(get_current_admin), agent_code: Optional[str] = None):
    q = {"agent_code": agent_code} if agent_code else {}
    return await db.payouts.find(q, {"_id": 0}).sort("created_at", -1).to_list(2000)


@api.post("/admin/payouts")
async def admin_add_payout(body: PayoutIn, user=Depends(get_current_admin)):
    doc = body.model_dump()
    doc["id"] = str(uuid.uuid4()); doc["created_at"] = now_iso()
    await db.payouts.insert_one(doc); doc.pop("_id", None); return doc


@api.delete("/admin/payouts/{payout_id}")
async def admin_delete_payout(payout_id: str, user=Depends(get_current_admin)):
    await db.payouts.delete_one({"id": payout_id}); return {"ok": True}


# -------------------- Seed --------------------
DEFAULT_MENU = [
    {"title": "Home", "slug": "home", "parent": None, "order": 1, "is_dynamic": False, "external_url": ""},
    {"title": "About", "slug": "about", "parent": None, "order": 2, "is_dynamic": False, "external_url": ""},
    {"title": "Products", "slug": "products", "parent": None, "order": 3, "is_dynamic": False, "external_url": ""},
    {"title": "CV / CE Loan", "slug": "cv-ce-loan", "parent": "products", "order": 1, "is_dynamic": True, "external_url": ""},
    {"title": "MSME Loan", "slug": "msme-loan", "parent": "products", "order": 2, "is_dynamic": True, "external_url": ""},
    {"title": "Personal Loan", "slug": "personal-loan", "parent": "products", "order": 3, "is_dynamic": True, "external_url": ""},
    {"title": "Home Loan", "slug": "home-loan", "parent": "products", "order": 4, "is_dynamic": True, "external_url": ""},
    {"title": "Business Loan", "slug": "business-loan", "parent": "products", "order": 5, "is_dynamic": True, "external_url": ""},
    {"title": "Loan Against Property", "slug": "lap", "parent": "products", "order": 6, "is_dynamic": True, "external_url": ""},
    {"title": "CC / OD Facility", "slug": "cc-od", "parent": "products", "order": 7, "is_dynamic": True, "external_url": ""},
    {"title": "Services", "slug": "services", "parent": None, "order": 4, "is_dynamic": False, "external_url": ""},
    {"title": "Credit Score Check", "slug": "credit-score", "parent": "services", "order": 1, "is_dynamic": True, "external_url": ""},
    {"title": "Financial Planning", "slug": "financial-planning", "parent": "services", "order": 2, "is_dynamic": True, "external_url": ""},
    {"title": "Debt Consolidation", "slug": "debt-consolidation", "parent": "services", "order": 3, "is_dynamic": True, "external_url": ""},
    {"title": "Partners", "slug": "partners", "parent": None, "order": 5, "is_dynamic": False, "external_url": ""},
    {"title": "Bank & NBFC", "slug": "partners-bank-nbfc", "parent": "partners", "order": 1, "is_dynamic": False, "external_url": ""},
    {"title": "Loan Agent", "slug": "partners-loan-agent", "parent": "partners", "order": 2, "is_dynamic": False, "external_url": ""},
    {"title": "Insurance Agent", "slug": "partners-insurance-agent", "parent": "partners", "order": 3, "is_dynamic": False, "external_url": ""},
    {"title": "EMI Calculator", "slug": "emi-calculator", "parent": None, "order": 6, "is_dynamic": False, "external_url": ""},
    {"title": "Contact", "slug": "contact", "parent": None, "order": 7, "is_dynamic": False, "external_url": ""},
    {"title": "Agent Portal", "slug": "agent-portal", "parent": None, "order": 8, "is_dynamic": False, "external_url": "/agent/login"},
]

DEFAULT_PARTNERS = [
    ("HDFC Bank", "Bank"), ("ICICI Bank", "Bank"), ("Axis Bank", "Bank"),
    ("State Bank of India", "Bank"), ("Kotak Mahindra Bank", "Bank"),
    ("IndusInd Bank", "Bank"), ("Yes Bank", "Bank"), ("IDFC First Bank", "Bank"),
    ("Bajaj Finserv", "NBFC"), ("Tata Capital", "NBFC"), ("Aditya Birla Capital", "NBFC"),
    ("L&T Finance", "NBFC"), ("Mahindra Finance", "NBFC"), ("Cholamandalam", "NBFC"),
    ("Shriram Finance", "NBFC"), ("Hero FinCorp", "NBFC"),
    ("Lendingkart", "Fintech"), ("InCred", "Fintech"), ("CreditAccess Grameen", "Fintech"),
    ("Paytm Postpaid", "Fintech"),
]

PRODUCT_PAGE_TEMPLATES = {
    "cv-ce-loan": ("Commercial Vehicle & Construction Equipment Loans", "Power up your fleet & projects with flexible CV/CE financing."),
    "msme-loan": ("MSME Loan", "Working capital and growth funding for small businesses."),
    "personal-loan": ("Personal Loan", "Instant funds for whatever life throws at you."),
    "home-loan": ("Home Loan", "Make your dream home a reality."),
    "business-loan": ("Business Loan", "Scale faster with capital tailored to your business."),
    "lap": ("Loan Against Property", "Unlock the value of your property."),
    "cc-od": ("Cash Credit / Overdraft Facility", "On-tap working capital."),
    "credit-score": ("Free Credit Score Check", "Know your score before lenders do."),
    "financial-planning": ("Financial Planning & Advisory", "Build wealth with a plan."),
    "debt-consolidation": ("Debt Consolidation", "One EMI. Lower rate. Less stress."),
    "privacy": ("Privacy Policy", "How we collect, use and protect your data."),
    "terms": ("Terms & Conditions", "The fine print, in plain English."),
    "partners-bank-nbfc": ("Bank & NBFC Partners", "35+ trusted lending institutions."),
    "partners-loan-agent": ("Loan Agents", "Join India's largest DSA network."),
    "partners-insurance-agent": ("Insurance Agents", "Cross-sell insurance to your customers."),
}

DEFAULT_CONTENT = {
    "branding": {
        "logo_url": "https://customer-assets.emergentagent.com/job_2ad99d46-1dec-45f4-a987-3453d8d7d4a7/artifacts/h5sqzqza_7.png",
        "logo_height": 40,
        "site_name": "TARA Finserv",
        "tagline": "Trusted finance partner",
    },
    "header": {
        "phone": "+91 98765 43210",
        "call_label": "Call Support",
        "show_call_button": True,
    },
    "hero": {
        "eyebrow_chips": ["DSA", "Loans", "Advisory", "India"],
        "title": "Loans that move at the speed of your ambition.",
        "subtitle": "From a working capital line for your shop to a 30-year home loan — TARA partners with India's top 35+ banks & NBFCs to find you the best rate, fastest.",
        "primary_cta": {"label": "Apply for a loan", "action": "wizard"},
        "secondary_cta": {"label": "Connect with agent", "action": "link", "target": "/agent/login"},
        "photos": [
            "https://customer-assets.emergentagent.com/job_2ad99d46-1dec-45f4-a987-3453d8d7d4a7/artifacts/h5sqzqza_7.png",
        ],
        "top_card": {"eyebrow": "Avg approval", "title": "22 hours"},
        "bottom_card": {"eyebrow": "Now live", "title": "35+ lenders", "sub": "comparing your rate in real-time"},
    },
    "marquee": {
        "heading": "Trusted by India's leading banks & NBFCs",
        "items": [{"name": n, "logo_url": ""} for n, _ in DEFAULT_PARTNERS],
    },
    "stats": [
        {"id": "customers", "label": "Happy customers", "value": 12500, "suffix": "+"},
        {"id": "disbursed", "label": "Disbursed (₹)", "value": 850, "suffix": "Cr+"},
        {"id": "approval", "label": "Approval rate", "value": 96, "suffix": "%"},
        {"id": "cities", "label": "Indian cities", "value": 48, "suffix": "+"},
    ],
    "why_section": {
        "eyebrow": "Why TARA",
        "heading": "Built for borrowers. Trusted by lenders.",
        "blurb": "We aren't a bank. We're your advocate — comparing offers, decoding fine print, and negotiating rates on your behalf, free of cost.",
        "cta_label": "Get my best offer",
        "items": [
            {"icon": "Zap", "title": "24-hour approvals", "desc": "In-principle decision within a single business day."},
            {"icon": "ShieldCheck", "title": "Bank-grade security", "desc": "256-bit encryption, RBI compliant data handling."},
            {"icon": "Sparkles", "title": "Best-rate guarantee", "desc": "We match offers from 35+ partners to find your lowest EMI."},
            {"icon": "Banknote", "title": "Zero hidden charges", "desc": "Transparent fee structure. What you see is what you pay."},
        ],
    },
    "cta_section": {
        "eyebrow": "Ready to start?",
        "heading": "Apply in 4 minutes. Get a decision in 24 hours.",
        "subtitle": "No paperwork chase. No hidden charges. Just the best loan for your need.",
        "primary_label": "Start application",
        "secondary_label": "Talk to advisor",
        "secondary_phone": "+91 98765 43210",
    },
    "products_section": {"eyebrow": "Products", "heading": "One DSA. Every loan India needs.", "see_all_label": "See all products"},
    "products": [
        {"slug": "personal-loan", "title": "Personal Loan", "icon": "Wallet", "blurb": "Up to ₹40L · from 10.49%"},
        {"slug": "home-loan", "title": "Home Loan", "icon": "Home", "blurb": "Up to ₹10Cr · from 8.35%"},
        {"slug": "business-loan", "title": "Business Loan", "icon": "Briefcase", "blurb": "Up to ₹2Cr · 60 months"},
        {"slug": "msme-loan", "title": "MSME Loan", "icon": "Building2", "blurb": "Collateral-free · ₹50L"},
        {"slug": "lap", "title": "Loan Against Property", "icon": "FileText", "blurb": "Up to 70% of value"},
        {"slug": "cv-ce-loan", "title": "CV / CE Loan", "icon": "Truck", "blurb": "Trucks, buses, equipment"},
    ],
    "services": [
        {"slug": "credit-score", "title": "Free Credit Score Check", "icon": "BadgeCheck", "blurb": "Know your CIBIL & Experian scores."},
        {"slug": "financial-planning", "title": "Financial Planning & Advisory", "icon": "LineChart", "blurb": "Goal-based planning, tax savings."},
        {"slug": "debt-consolidation", "title": "Debt Consolidation", "icon": "Layers", "blurb": "Merge multiple loans into one EMI."},
    ],
    "about_page": {
        "hero": {
            "eyebrow": "About TARA Finserv",
            "title": "We turn loan paperwork into a 4-minute conversation.",
            "subtitle": "TARA Finserv is a Direct Selling Agent founded in 2018, with a single mission — make credit access in India fast, fair and friendly.",
            "image_url": "https://images.pexels.com/photos/12903168/pexels-photo-12903168.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940",
        },
        "vision_title": "Our Vision",
        "vision_text": "A future where every Indian — salaried or shopkeeper, metro or mofussil — gets the right loan at the right time.",
        "mission_title": "Our Mission",
        "mission_text": "Combine deep relationships with India's top lenders, an obsessive commitment to transparency, and modern technology so that customers get their best offer in hours, not weeks.",
        "leadership_heading": "The team behind your approval",
        "leadership": [
            {"id": "1", "name": "Arvind Mehta", "role": "Founder & CEO", "photo_url": "", "initials": "AM"},
            {"id": "2", "name": "Priya Iyer", "role": "Chief Risk Officer", "photo_url": "", "initials": "PI"},
            {"id": "3", "name": "Karan Bhatia", "role": "Head of Partnerships", "photo_url": "", "initials": "KB"},
            {"id": "4", "name": "Sneha Rao", "role": "Head of Customer Success", "photo_url": "", "initials": "SR"},
        ],
        "values_heading": "The four principles guiding every decision.",
        "values": [
            {"icon": "ShieldCheck", "title": "Integrity", "desc": "We disclose every fee, every clause, every time."},
            {"icon": "Sparkles", "title": "Speed", "desc": "We respect your time — quick decisions, faster disbursals."},
            {"icon": "Heart", "title": "Empathy", "desc": "Behind every application is a life event. We treat it as such."},
            {"icon": "Users", "title": "Partnership", "desc": "Banks and borrowers — we serve both with equal rigour."},
        ],
    },
    "products_page": {
        "hero": {
            "eyebrow": "Loan Products",
            "title": "Seven products. Built for every chapter of your life.",
            "subtitle": "From a weekend personal loan to a 30-year home loan — explore the full TARA Finserv lineup.",
            "image_url": "",
        },
        "items": [
            {"slug": "personal-loan", "title": "Personal Loan", "icon": "Wallet", "blurb": "Unsecured funds up to ₹40L for any life event.", "rate": "10.49% p.a."},
            {"slug": "home-loan", "title": "Home Loan", "icon": "Home", "blurb": "Buy, build or transfer your dream home.", "rate": "8.35% p.a."},
            {"slug": "business-loan", "title": "Business Loan", "icon": "Briefcase", "blurb": "Scale your business with capital up to ₹2 Cr.", "rate": "13.5% p.a."},
            {"slug": "msme-loan", "title": "MSME Loan", "icon": "Building2", "blurb": "Collateral-free credit for small businesses.", "rate": "11% p.a."},
            {"slug": "lap", "title": "Loan Against Property", "icon": "FileText", "blurb": "Unlock up to 70% of your property's value.", "rate": "9% p.a."},
            {"slug": "cv-ce-loan", "title": "CV / CE Loan", "icon": "Truck", "blurb": "Vehicle & equipment finance.", "rate": "9.5% p.a."},
            {"slug": "cc-od", "title": "CC / OD Facility", "icon": "RotateCcw", "blurb": "On-tap working capital.", "rate": "Bank-linked"},
        ],
    },
    "services_page": {
        "hero": {
            "eyebrow": "Services",
            "title": "Beyond loans — your full financial co-pilot.",
            "subtitle": "From credit health to retirement planning, we help you build a stronger financial life.",
            "image_url": "",
        },
        "items": [
            {"slug": "credit-score", "icon": "BadgeCheck", "title": "Free Credit Score Check", "blurb": "Know your CIBIL & Experian scores. Get actionable improvement tips."},
            {"slug": "financial-planning", "icon": "LineChart", "title": "Financial Planning & Advisory", "blurb": "Goal-based planning, tax savings, retirement readiness."},
            {"slug": "debt-consolidation", "icon": "Layers", "title": "Debt Consolidation", "blurb": "Merge multiple loans into a single low-EMI facility."},
        ],
    },
    "partners_page": {
        "hero": {
            "eyebrow": "Partner Network",
            "title": "35+ lenders. One application.",
            "subtitle": "We've negotiated terms with India's most trusted banks and NBFCs so you get the best rate without the back-and-forth.",
            "image_url": "",
        },
        "marquee_heading": "Our lending partners",
    },
    "contact_page": {
        "hero": {
            "eyebrow": "Contact",
            "title": "Talk to a human, not a chatbot.",
            "subtitle": "Reach our advisors via phone, email or WhatsApp — usually we respond in under 2 hours.",
        },
        "office_heading": "Visit us",
    },
    "emi_page": {
        "hero": {
            "eyebrow": "EMI Calculator",
            "title": "Plan your EMI before you apply.",
            "subtitle": "Toggle between IRR and Flat methods, type values directly or use the elegant sliders.",
        },
    },
    "footer": {
        "blurb": "India's trusted Direct Selling Agent connecting borrowers with 35+ top banks & NBFCs. Fast approvals, transparent rates, lifelong relationships.",
        "columns": [
            {"heading": "Products",
             "links": [{"label": "Personal Loan", "url": "/p/personal-loan"},
                       {"label": "Home Loan", "url": "/p/home-loan"},
                       {"label": "Business Loan", "url": "/p/business-loan"},
                       {"label": "LAP", "url": "/p/lap"},
                       {"label": "MSME Loan", "url": "/p/msme-loan"}]},
            {"heading": "Company",
             "links": [{"label": "About", "url": "/about"},
                       {"label": "Partners", "url": "/partners"},
                       {"label": "Services", "url": "/services"},
                       {"label": "EMI Calculator", "url": "/emi-calculator"},
                       {"label": "Contact", "url": "/contact"}]},
        ],
        "offices": [
            {"heading": "Headquarters", "address": "TARA Finserv HQ, 4th Floor, Maker Maxity, BKC, Mumbai 400051, India"},
        ],
        "socials": [
            {"label": "LinkedIn", "icon": "Linkedin", "url": "#"},
            {"label": "Twitter", "icon": "Twitter", "url": "#"},
            {"label": "Facebook", "icon": "Facebook", "url": "#"},
        ],
        "contact": {
            "phone": "+91 98765 43210",
            "email": "hello@tarafinserv.com",
            "whatsapp": "+919876543210",
        },
        "copyright": "© 2026 TARA Finserv. All rights reserved.",
        "policy_links": [
            {"label": "Privacy", "url": "/p/privacy"},
            {"label": "Terms", "url": "/p/terms"},
        ],
        "map_embed_url": "https://www.google.com/maps/embed?pb=!1m18!1m12!1m3!1d3771.45!2d72.8261!3d19.0596!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x0%3A0x0!2sBKC%2C%20Mumbai!5e0!3m2!1sen!2sin!4v1700000000000",
    },
    "floating_whatsapp": {
        "enabled": True,
        "number": "+919876543210",
        "message": "Hi TARA Finserv, I have a question about loans.",
        "position": "right",
    },
}


async def seed():
    await db.users.create_index("email", unique=True)
    await db.menu_items.create_index([("parent", 1), ("order", 1)])
    await db.pages.create_index("slug", unique=True)
    await db.leads.create_index("created_at")
    await db.agents.create_index("code", unique=True)
    await db.agents.create_index("email", unique=True)

    # admin
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@tarafinserv.com").lower()
    admin_pw = os.environ.get("ADMIN_PASSWORD", "Tara@Admin2026")
    existing = await db.users.find_one({"email": admin_email})
    if not existing:
        await db.users.insert_one({
            "id": str(uuid.uuid4()),
            "email": admin_email, "password_hash": hash_password(admin_pw),
            "name": "Admin", "role": "admin", "created_at": now_iso(),
        })
    else:
        if not verify_password(admin_pw, existing.get("password_hash", "")):
            await db.users.update_one({"email": admin_email},
                                      {"$set": {"password_hash": hash_password(admin_pw)}})

    # menu — refresh if empty
    if await db.menu_items.count_documents({}) == 0:
        for item in DEFAULT_MENU:
            await db.menu_items.insert_one({**item, "id": str(uuid.uuid4()), "created_at": now_iso()})
    else:
        # Migration: rename old slugs/titles if found
        await db.menu_items.update_many({"title": "About Us"}, {"$set": {"title": "About"}})
        await db.menu_items.update_many({"title": "Contact Us"}, {"$set": {"title": "Contact"}})
        # add new partner subitems + agent-portal if missing
        for sub in [m for m in DEFAULT_MENU if m["slug"] in
                    ("partners-bank-nbfc", "partners-loan-agent", "partners-insurance-agent", "agent-portal")]:
            if not await db.menu_items.find_one({"slug": sub["slug"]}):
                await db.menu_items.insert_one({**sub, "id": str(uuid.uuid4()), "created_at": now_iso()})

    # migrate hero secondary CTA from old "Try EMI calculator" to "Connect with agent"
    await db.site_content.update_one(
        {"_id": "main", "hero.secondary_cta.label": "Try EMI calculator"},
        {"$set": {"hero.secondary_cta": {"label": "Connect with agent", "action": "link", "target": "/agent/login"}}}
    )

    # partners
    if await db.partners.count_documents({}) == 0:
        for n, cat in DEFAULT_PARTNERS:
            await db.partners.insert_one({
                "id": str(uuid.uuid4()), "name": n, "category": cat,
                "logo_url": "", "description": "Trusted lending partner of TARA Finserv.",
            })

    # pages
    for slug, (title, subtitle) in PRODUCT_PAGE_TEMPLATES.items():
        if not await db.pages.find_one({"slug": slug}):
            await db.pages.insert_one({
                "slug": slug, "title": title, "subtitle": subtitle,
                "hero_image": "",
                "body_html": f"<p>{subtitle}</p>"
                             f"<h3>Key features</h3>"
                             f"<ul><li>Fast in-principle approval</li>"
                             f"<li>Minimal documentation</li>"
                             f"<li>Tailor-made repayment plans</li>"
                             f"<li>Pan-India presence with 35+ lender tie-ups</li></ul>",
                "meta_description": subtitle, "updated_at": now_iso(),
            })

    # settings — only Twilio + flags
    if not await db.settings.find_one({"_id": "global"}):
        await db.settings.insert_one({
            "_id": "global", "otp_real_enabled": False,
            "twilio_account_sid": "", "twilio_auth_token": "", "twilio_from_number": "",
            "updated_at": now_iso(),
        })

    # content (DEFAULT_CONTENT) — only set if missing
    if not await db.site_content.find_one({"_id": "main"}):
        await db.site_content.insert_one({"_id": "main", **DEFAULT_CONTENT, "updated_at": now_iso()})


# -------------------- App lifecycle --------------------
@app.on_event("startup")
async def on_start():
    await seed()
    logger.info("TARA Finserv API started and seeded.")


@app.on_event("shutdown")
async def on_stop():
    pass


app.include_router(api)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
