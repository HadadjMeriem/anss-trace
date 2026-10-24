from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, create_engine, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

BASE_DIR = Path(__file__).resolve().parent
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR.parent / 'anss_trace.db'}")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "ANSS2026!")
TOKEN_SECRET = os.getenv("TOKEN_SECRET", "change-this-secret-before-production")
TOKEN_TTL_SECONDS = int(os.getenv("TOKEN_TTL_SECONDS", "43200"))
USER_TOKEN_TTL_SECONDS = int(os.getenv("USER_TOKEN_TTL_SECONDS", "2592000")) # 30 days

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    phone: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    full_name: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(128))
    device_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    reports: Mapped[list["CaseReport"]] = relationship(back_populates="user")

class Disease(Base):
    __tablename__ = "diseases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    name_fr: Mapped[str] = mapped_column(String(120))
    name_ar: Mapped[str] = mapped_column(String(120))
    advice_fr: Mapped[str] = mapped_column(Text, default="")
    advice_ar: Mapped[str] = mapped_column(Text, default="")
    threshold_rssi: Mapped[int] = mapped_column(Integer, default=-80)
    min_duration_minutes: Mapped[int] = mapped_column(Integer, default=1)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    reports: Mapped[list["CaseReport"]] = relationship(back_populates="disease")


class CaseReport(Base):
    __tablename__ = "case_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[str] = mapped_column(String(100), index=True)
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    disease_id: Mapped[int] = mapped_column(ForeignKey("diseases.id"))
    classification: Mapped[str] = mapped_column(String(40), default="SYMPTOMS")
    phone: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    wilaya: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recent_keys_json: Mapped[str] = mapped_column(Text, default="[]")
    status: Mapped[str] = mapped_column(String(20), default="PENDING", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    validated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    disease: Mapped[Disease] = relationship(back_populates="reports")
    user: Mapped[Optional[User]] = relationship(back_populates="reports")


class PublishedExposureKey(Base):
    __tablename__ = "published_exposure_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token: Mapped[str] = mapped_column(String(64), index=True)
    disease_id: Mapped[int] = mapped_column(ForeignKey("diseases.id"))
    report_id: Mapped[int] = mapped_column(ForeignKey("case_reports.id"))
    key_timestamp: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc) + timedelta(days=14))


class DiseaseOut(BaseModel):
    id: int
    code: str
    name_fr: str
    name_ar: str
    advice_fr: str
    advice_ar: str
    threshold_rssi: int
    min_duration_minutes: int
    active: bool

    model_config = {"from_attributes": True}

# Initialize Database and handle migrations for MVP
Base.metadata.create_all(bind=engine)

with engine.connect() as conn:
    from sqlalchemy import text
    # Check if user_id exists in case_reports
    try:
        conn.execute(text("SELECT user_id FROM case_reports LIMIT 1"))
    except Exception:
        try:
            print("Adding user_id column to case_reports table...")
            conn.execute(text("ALTER TABLE case_reports ADD COLUMN user_id INTEGER REFERENCES users(id)"))
            conn.commit()
        except Exception as e:
            print(f"Migration failed: {e}")

class KeyIn(BaseModel):
    token: str = Field(min_length=8, max_length=64)
    timestamp: Optional[str] = None


class ReportIn(BaseModel):
    device_id: str = Field(min_length=8, max_length=100)
    disease_id: int
    classification: str = Field(default="SYMPTOMS", max_length=40)
    phone: Optional[str] = Field(default=None, max_length=40)
    wilaya: Optional[str] = Field(default=None, max_length=80)
    notes: Optional[str] = Field(default=None, max_length=1000)
    recent_keys: list[KeyIn] = Field(default_factory=list, max_length=2000)


class LoginIn(BaseModel):
    username: str
    password: str

class UserLoginIn(BaseModel):
    phone: str
    password: str

class UserSignupIn(BaseModel):
    phone: str = Field(min_length=10, max_length=20)
    password: str = Field(min_length=6)
    full_name: Optional[str] = None
    device_id: Optional[str] = None

class DiseaseIn(BaseModel):
    code: str = Field(min_length=2, max_length=40)
    name_fr: str = Field(min_length=2, max_length=120)
    name_ar: str = Field(min_length=2, max_length=120)
    advice_fr: str = ""
    advice_ar: str = ""
    threshold_rssi: int = -80
    min_duration_minutes: int = 1
    active: bool = True


class DiseasePatch(BaseModel):
    name_fr: Optional[str] = None
    name_ar: Optional[str] = None
    advice_fr: Optional[str] = None
    advice_ar: Optional[str] = None
    threshold_rssi: Optional[int] = None
    min_duration_minutes: Optional[int] = None
    active: Optional[bool] = None


app = FastAPI(title="ANSS Trace API", version="0.3.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(engine)
    seed_diseases()


def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def seed_diseases() -> None:
    seeds = [
        {
            "code": "MEASLES",
            "name_fr": "Rougeole",
            "name_ar": "الحصبة",
            "advice_fr": "Surveillez l'apparition de fièvre, toux, écoulement nasal ou éruption. En cas de symptômes, évitez les contacts rapprochés et contactez un professionnel de santé.",
            "advice_ar": "راقب ظهور الحمى أو السعال أو سيلان الأنف أو الطفح الجلدي. عند ظهور أعراض، تجنب المخالطة القريبة واتصل بمهني صحي.",
            "threshold_rssi": -80,
            "min_duration_minutes": 1,
        },
        {
            "code": "WEST_NILE",
            "name_fr": "West Nile",
            "name_ar": "حمى غرب النيل",
            "advice_fr": "Protégez-vous des piqûres de moustiques. Consultez rapidement en cas de fièvre importante, céphalées intenses ou signes neurologiques.",
            "advice_ar": "احم نفسك من لسعات البعوض. استشر بسرعة عند وجود حمى شديدة أو صداع قوي أو أعراض عصبية.",
            "threshold_rssi": -80,
            "min_duration_minutes": 1,
        },
        {
            "code": "MPOX",
            "name_fr": "Mpox",
            "name_ar": "جدري القردة",
            "advice_fr": "Évitez les contacts peau à peau avec une personne symptomatique. En cas de lésions cutanées inexpliquées ou de fièvre, demandez un avis médical.",
            "advice_ar": "تجنب التلامس الجلدي المباشر مع شخص لديه أعراض. عند ظهور طفح جلدي غير مفسر أو حمى، اطلب استشارة طبية.",
            "threshold_rssi": -80,
            "min_duration_minutes": 1,
        },
        {
            "code": "INFLUENZA",
            "name_fr": "Grippe",
            "name_ar": "الإنفلونزا",
            "advice_fr": "Surveillez fièvre, toux, courbatures et fatigue. Limitez les contacts si vous êtes symptomatique et suivez les recommandations sanitaires en vigueur.",
            "advice_ar": "راقب الحمى والسعال وآلام الجسم والتعب. قلل المخالطة عند ظهور الأعراض واتبع التوصيات الصحية المعمول بها.",
            "threshold_rssi": -80,
            "min_duration_minutes": 1,
        },
        {
            "code": "COVID19",
            "name_fr": "COVID-19",
            "name_ar": "كوفيد-19",
            "advice_fr": "En cas de symptômes respiratoires, réduisez les contacts, aérez les espaces et demandez un avis médical si nécessaire.",
            "advice_ar": "عند ظهور أعراض تنفسية، قلل المخالطة وهوِّ الأماكن واطلب استشارة طبية عند الحاجة.",
            "threshold_rssi": -80,
            "min_duration_minutes": 1,
        },
        {
            "code": "DENGUE",
            "name_fr": "Dengue",
            "name_ar": "حمى الضنك",
            "advice_fr": "Utilisez des moyens de protection contre les moustiques. Consultez en cas de forte fièvre, douleurs intenses ou signes inhabituels.",
            "advice_ar": "استخدم وسائل الوقاية من البعوض. استشر عند وجود حمى مرتفعة أو آلام شديدة أو علامات غير معتادة.",
            "threshold_rssi": -80,
            "min_duration_minutes": 1,
        },
        {
            "code": "CHIKUNGUNYA",
            "name_fr": "Chikungunya",
            "name_ar": "شيكونغونيا",
            "advice_fr": "Protégez-vous des moustiques et consultez en cas de fièvre associée à des douleurs articulaires importantes.",
            "advice_ar": "احم نفسك من البعوض واستشر عند وجود حمى مع آلام مفصلية شديدة.",
            "threshold_rssi": -80,
            "min_duration_minutes": 1,
        },
    ]
    with SessionLocal() as db:
        existing = {x.code for x in db.scalars(select(Disease)).all()}
        for item in seeds:
            if item["code"] not in existing:
                db.add(Disease(**item))
        db.commit()


def _sign(data: str) -> str:
    return hmac.new(TOKEN_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()


def create_token(payload_data: dict, ttl: int) -> str:
    payload = {**payload_data, "exp": int(time.time()) + ttl, "n": secrets.token_hex(6)}
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    return f"{encoded}.{_sign(encoded)}"


def verify_token(token: str) -> dict:
    try:
        encoded, signature = token.split(".", 1)
        if not hmac.compare_digest(signature, _sign(encoded)):
            raise ValueError("signature")
        padded = encoded + "=" * (-len(encoded) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
        if int(payload.get("exp", 0)) < int(time.time()):
            raise ValueError("expired")
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Jeton invalide ou expiré")


def require_admin(authorization: Optional[str] = Header(default=None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentification administrateur requise")
    payload = verify_token(authorization.removeprefix("Bearer ").strip())
    if "u" not in payload: # 'u' for admin username
        raise HTTPException(status_code=401, detail="Accès admin requis")
    return payload

def require_user(authorization: Optional[str] = Header(default=None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentification requise")
    payload = verify_token(authorization.removeprefix("Bearer ").strip())
    if "uid" not in payload: # 'uid' for user id
        raise HTTPException(status_code=401, detail="Compte utilisateur requis")
    return payload

@app.get("/")
def root():
    return RedirectResponse(url="/admin/")


@app.get("/api/health")
def health(db: Session = Depends(db_session)):
    try:
        db.execute(text("SELECT 1"))
        return {"ok": True, "service": "ANSS Trace API", "db": "connected", "time": datetime.now(timezone.utc).isoformat()}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database connection failed: {e}")


@app.get("/api/diseases", response_model=list[DiseaseOut])
def diseases(db: Session = Depends(db_session)):
    return db.scalars(select(Disease).where(Disease.active.is_(True)).order_by(Disease.name_fr)).all()

# --- User Auth ---

def hash_password(password: str) -> str:
    return hashlib.sha256((password + TOKEN_SECRET).encode()).hexdigest()

@app.post("/api/auth/signup")
def signup(data: UserSignupIn, db: Session = Depends(db_session)):
    existing = db.scalar(select(User).where(User.phone == data.phone))
    if existing:
        raise HTTPException(status_code=400, detail="Ce numéro de téléphone est déjà utilisé")

    user = User(
        phone=data.phone,
        full_name=data.full_name,
        password_hash=hash_password(data.password),
        device_id=data.device_id
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_token({"uid": user.id, "p": user.phone}, USER_TOKEN_TTL_SECONDS)
    return {"ok": True, "token": token, "user_id": user.id}

@app.post("/api/auth/login")
def login(data: UserLoginIn, db: Session = Depends(db_session)):
    user = db.scalar(select(User).where(User.phone == data.phone))
    if not user or user.password_hash != hash_password(data.password):
        raise HTTPException(status_code=401, detail="Numéro de téléphone ou mot de passe incorrect")

    token = create_token({"uid": user.id, "p": user.phone}, USER_TOKEN_TTL_SECONDS)
    return {"ok": True, "token": token, "user_id": user.id}

@app.get("/api/auth/me")
def get_me(current_user: dict = Depends(require_user), db: Session = Depends(db_session)):
    user = db.get(User, current_user["uid"])
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    return {
        "id": user.id,
        "phone": user.phone,
        "full_name": user.full_name,
        "created_at": user.created_at.isoformat()
    }

# --- Reports ---

@app.post("/api/reports")
def submit_report(data: ReportIn, db: Session = Depends(db_session), current_user: Optional[dict] = Depends(lambda x=Header(default=None): verify_token(x.removeprefix("Bearer ").strip()) if x and x.startswith("Bearer ") else None)):
    disease = db.get(Disease, data.disease_id)
    if not disease or not disease.active:
        raise HTTPException(status_code=404, detail="Maladie inconnue ou inactive")

    user_id = current_user["uid"] if current_user and "uid" in current_user else None

    safe_keys = []
    for key in data.recent_keys:
        safe_keys.append({"token": key.token.upper(), "timestamp": key.timestamp})

    report = CaseReport(
        device_id=data.device_id,
        user_id=user_id,
        disease_id=data.disease_id,
        classification=data.classification.upper(),
        phone=(data.phone or "").strip() or None,
        wilaya=(data.wilaya or "").strip() or None,
        notes=(data.notes or "").strip() or None,
        recent_keys_json=json.dumps(safe_keys, ensure_ascii=False),
        status="PENDING",
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return {"ok": True, "report_id": report.id, "status": report.status}


@app.get("/api/reports/device/{device_id}")
def user_report_history(device_id: str, db: Session = Depends(db_session)):
    # On garde la compatibilité par device_id, mais on pourrait filtrer par user_id
    if len(device_id) < 8 or len(device_id) > 100:
        raise HTTPException(status_code=400, detail="Identifiant appareil invalide")
    rows = db.execute(
        select(CaseReport, Disease)
        .join(Disease, Disease.id == CaseReport.disease_id)
        .where(CaseReport.device_id == device_id)
        .order_by(CaseReport.created_at.desc())
        .limit(100)
    ).all()
    return [
        {
            "id": report.id,
            "disease_code": disease.code,
            "disease_fr": disease.name_fr,
            "disease_ar": disease.name_ar,
            "classification": report.classification,
            "status": report.status,
            "wilaya": report.wilaya,
            "created_at": report.created_at.isoformat(),
            "validated_at": report.validated_at.isoformat() if report.validated_at else None,
        }
        for report, disease in rows
    ]


@app.get("/api/exposure-keys")
def exposure_keys(
    since: Optional[datetime] = Query(default=None),
    db: Session = Depends(db_session),
):
    now = datetime.now(timezone.utc)
    stmt = (
        select(PublishedExposureKey, Disease)
        .join(Disease, Disease.id == PublishedExposureKey.disease_id)
        .where(PublishedExposureKey.expires_at > now)
    )
    if since:
        stmt = stmt.where(PublishedExposureKey.published_at > since)
    rows = db.execute(stmt.order_by(PublishedExposureKey.published_at.desc()).limit(10000)).all()
    return [
        {
            "token": key.token,
            "report_id": key.report_id,
            "key_timestamp": key.key_timestamp.isoformat() if key.key_timestamp else None,
            "published_at": key.published_at.isoformat(),
            "expires_at": key.expires_at.isoformat(),
            "disease": {
                "id": disease.id,
                "code": disease.code,
                "name_fr": disease.name_fr,
                "name_ar": disease.name_ar,
                "threshold_rssi": disease.threshold_rssi,
                "min_duration_minutes": disease.min_duration_minutes,
            },
        }
        for key, disease in rows
    ]


@app.post("/api/admin/login")
def admin_login(data: LoginIn):
    valid_user = hmac.compare_digest(data.username, ADMIN_USER)
    valid_password = hmac.compare_digest(data.password, ADMIN_PASSWORD)
    if not (valid_user and valid_password):
        raise HTTPException(status_code=401, detail="Identifiants incorrects")
    return {"token": create_token({"u": data.username}, TOKEN_TTL_SECONDS), "expires_in": TOKEN_TTL_SECONDS}


@app.get("/api/admin/dashboard")
def admin_dashboard(_: dict = Depends(require_admin), db: Session = Depends(db_session)):
    total_reports = db.scalar(select(func.count()).select_from(CaseReport)) or 0
    pending = db.scalar(select(func.count()).select_from(CaseReport).where(CaseReport.status == "PENDING")) or 0
    validated = db.scalar(select(func.count()).select_from(CaseReport).where(CaseReport.status == "VALIDATED")) or 0
    rejected = db.scalar(select(func.count()).select_from(CaseReport).where(CaseReport.status == "REJECTED")) or 0
    keys = db.scalar(select(func.count()).select_from(PublishedExposureKey)) or 0
    active_diseases = db.scalar(select(func.count()).select_from(Disease).where(Disease.active.is_(True))) or 0
    total_users = db.scalar(select(func.count()).select_from(User)) or 0

    # Reports by wilaya
    wilaya_stats = db.execute(
        select(CaseReport.wilaya, func.count(CaseReport.id))
        .group_by(CaseReport.wilaya)
        .where(CaseReport.wilaya.isnot(None))
    ).all()

    return {
        "total_reports": total_reports,
        "pending_reports": pending,
        "validated_reports": validated,
        "rejected_reports": rejected,
        "published_keys": keys,
        "active_diseases": active_diseases,
        "total_users": total_users,
        "wilaya_stats": {w: c for w, c in wilaya_stats}
    }

@app.get("/api/admin/users")
def admin_users(_: dict = Depends(require_admin), db: Session = Depends(db_session)):
    users = db.scalars(select(User).order_by(User.created_at.desc())).all()
    return [
        {
            "id": u.id,
            "phone": u.phone,
            "full_name": u.full_name,
            "device_id": u.device_id,
            "created_at": u.created_at.isoformat(),
            "reports_count": db.scalar(select(func.count()).select_from(CaseReport).where(CaseReport.user_id == u.id))
        }
        for u in users
    ]

@app.get("/api/admin/reports")
def admin_reports(
    status: Optional[str] = None,
    _: dict = Depends(require_admin),
    db: Session = Depends(db_session),
):
    stmt = select(CaseReport, Disease).join(Disease, Disease.id == CaseReport.disease_id)
    if status:
        stmt = stmt.where(CaseReport.status == status.upper())
    rows = db.execute(stmt.order_by(CaseReport.created_at.desc()).limit(500)).all()
    result = []
    for report, disease in rows:
        result.append(
            {
                "id": report.id,
                "device_id": report.device_id,
                "disease_id": disease.id,
                "disease_fr": disease.name_fr,
                "disease_ar": disease.name_ar,
                "classification": report.classification,
                "phone": report.phone,
                "wilaya": report.wilaya,
                "notes": report.notes,
                "status": report.status,
                "created_at": report.created_at.isoformat(),
                "validated_at": report.validated_at.isoformat() if report.validated_at else None,
                "keys_count": len(json.loads(report.recent_keys_json or "[]")),
            }
        )
    return result


@app.post("/api/admin/reports/{report_id}/validate")
def validate_report(report_id: int, _: dict = Depends(require_admin), db: Session = Depends(db_session)):
    report = db.get(CaseReport, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Signalement introuvable")
    if report.status == "VALIDATED":
        return {"ok": True, "already_validated": True}
    keys = json.loads(report.recent_keys_json or "[]")
    inserted = 0
    for item in keys:
        token = str(item.get("token", "")).upper().strip()
        if not token:
            continue
        exists = db.scalar(
            select(func.count()).select_from(PublishedExposureKey).where(
                PublishedExposureKey.report_id == report.id,
                PublishedExposureKey.token == token,
            )
        )
        if exists:
            continue
        key_ts = None
        raw_ts = item.get("timestamp")
        if raw_ts:
            try:
                key_ts = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))
            except ValueError:
                key_ts = None
        db.add(
            PublishedExposureKey(
                token=token,
                disease_id=report.disease_id,
                report_id=report.id,
                key_timestamp=key_ts,
                expires_at=datetime.now(timezone.utc) + timedelta(days=14),
            )
        )
        inserted += 1
    report.status = "VALIDATED"
    report.validated_at = datetime.now(timezone.utc)
    db.commit()
    return {"ok": True, "published_keys": inserted}


@app.post("/api/admin/reports/{report_id}/reject")
def reject_report(report_id: int, _: dict = Depends(require_admin), db: Session = Depends(db_session)):
    report = db.get(CaseReport, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Signalement introuvable")
    report.status = "REJECTED"
    db.commit()
    return {"ok": True}


@app.get("/api/admin/diseases", response_model=list[DiseaseOut])
def admin_diseases(_: dict = Depends(require_admin), db: Session = Depends(db_session)):
    return db.scalars(select(Disease).order_by(Disease.name_fr)).all()


@app.post("/api/admin/diseases", response_model=DiseaseOut)
def add_disease(data: DiseaseIn, _: dict = Depends(require_admin), db: Session = Depends(db_session)):
    if db.scalar(select(func.count()).select_from(Disease).where(Disease.code == data.code.upper())):
        raise HTTPException(status_code=409, detail="Code déjà utilisé")
    disease = Disease(**data.model_dump(), code=data.code.upper())
    db.add(disease)
    db.commit()
    db.refresh(disease)
    return disease


@app.patch("/api/admin/diseases/{disease_id}", response_model=DiseaseOut)
def patch_disease(
    disease_id: int,
    data: DiseasePatch,
    _: dict = Depends(require_admin),
    db: Session = Depends(db_session),
):
    disease = db.get(Disease, disease_id)
    if not disease:
        raise HTTPException(status_code=404, detail="Maladie introuvable")
    for key, value in data.model_dump(exclude_unset=True).items():
        setattr(disease, key, value)
    db.commit()
    db.refresh(disease)
    return disease


STATIC_ADMIN = BASE_DIR / "static" / "admin"
app.mount("/admin", StaticFiles(directory=STATIC_ADMIN, html=True), name="admin")
