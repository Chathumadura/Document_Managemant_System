from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
import hashlib
import os
import logging
import warnings
from tika import parser

# Suppress pkg_resources deprecation warning from tika
warnings.filterwarnings("ignore", message="pkg_resources is deprecated")
from datetime import datetime, timedelta
from bson import ObjectId
from db import init_db, get_documents_collection, get_audit_collection, get_users_collection, close_db
from enum import Enum
from typing import Optional

app = FastAPI(title="Government Document Management System")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Directory for file storage
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Allowed file extensions
ALLOWED_EXTENSIONS = {".pdf", ".doc", ".docx", ".jpg", ".jpeg", ".png"}

# JWT configuration
SECRET_KEY = "f3d2e4a1b6c7d8e9f0a1b2c3d4e5f67890abcdef1234567890abcdef12345678"  # Replace with a strong, random key in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Document status enum
class DocumentStatus(str, Enum):
    PENDING = "pending"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    REJECTED = "rejected"

# State machine transitions
ALLOWED_TRANSITIONS = {
    DocumentStatus.PENDING: [DocumentStatus.UNDER_REVIEW],
    DocumentStatus.UNDER_REVIEW: [DocumentStatus.APPROVED, DocumentStatus.REJECTED],
    DocumentStatus.APPROVED: [],
    DocumentStatus.REJECTED: []
}

# RBAC roles
ALLOWED_ROLES = {
    "update_status": ["approver", "admin"]
}

def validate_file_extension(filename: str) -> bool:
    return os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS

def calculate_file_hash(file_content: bytes) -> str:
    return hashlib.sha256(file_content).hexdigest()

def scan_file(file_content: bytes) -> bool:
    print("Warning: Virus scanning is disabled")
    return True

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(OAuth2PasswordRequestForm)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        users_collection = get_users_collection()
        user = users_collection.find_one({"username": username})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return {"username": username, "roles": user.get("roles", [])}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def check_user_role(user: dict, required_roles: list) -> bool:
    return any(role in user["roles"] for role in required_roles)

@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    users_collection = get_users_collection()
    user = users_collection.find_one({"username": form_data.username})
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/upload")
async def upload_document(file: UploadFile = File(...)):
    if not validate_file_extension(file.filename):
        raise HTTPException(status_code=400, detail="Invalid file type. Allowed: PDF, DOC, DOCX, JPG, JPEG, PNG")

    file_content = await file.read()
    if not scan_file(file_content):
        raise HTTPException(status_code=400, detail="File contains a virus and cannot be uploaded")

    file_hash = calculate_file_hash(file_content)
    documents_collection = get_documents_collection()
    if documents_collection.find_one({"file_hash": file_hash}):
        raise HTTPException(status_code=400, detail="Duplicate file detected")

    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as f:
        f.write(file_content)

    try:
        parsed = parser.from_file(file_path)
        metadata = parsed.get("metadata", {})
        content = parsed.get("content", "").strip()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Metadata extraction failed: {str(e)}")

    document = {
        "filename": file.filename,
        "file_hash": file_hash,
        "file_path": file_path,
        "metadata": {
            "title": metadata.get("title", file.filename),
            "author": metadata.get("Author", "Unknown"),
            "creation_date": metadata.get("Creation-Date", datetime.utcnow().isoformat()),
            "content_type": metadata.get("Content-Type", "application/octet-stream"),
        },
        "content_snippet": content[:500] if content else "",
        "upload_date": datetime.utcnow().isoformat(),
        "status": DocumentStatus.PENDING.value,
    }

    result = documents_collection.insert_one(document)
    audit_collection = get_audit_collection()
    audit_collection.insert_one({
        "document_id": str(result.inserted_id),
        "action": "status_change",
        "status": DocumentStatus.PENDING.value,
        "user": "system",
        "timestamp": datetime.utcnow().isoformat()
    })

    return {
        "document_id": str(result.inserted_id),
        "filename": file.filename,
        "message": "Document uploaded successfully",
    }

@app.get("/documents")
async def list_documents():
    documents_collection = get_documents_collection()
    documents = list(documents_collection.find({}, {"_id": 1, "filename": 1, "metadata": 1, "upload_date": 1, "status": 1}))
    for doc in documents:
        doc["_id"] = str(doc["_id"])
    return {"documents": documents}

@app.get("/documents/{document_id}")
async def get_document(document_id: str):
    try:
        documents_collection = get_documents_collection()
        document = documents_collection.find_one({"_id": ObjectId(document_id)})
        if not document:
            raise HTTPException(status_code=404, detail="Document not found")
        document["_id"] = str(document["_id"])
        return document
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid document ID")

@app.post("/documents/{document_id}/status")
async def update_document_status(
    document_id: str,
    status: DocumentStatus,
    user: dict = Depends(get_current_user)
):
    if not check_user_role(user, ALLOWED_ROLES["update_status"]):
        raise HTTPException(status_code=403, detail="User not authorized to update status")

    try:
        documents_collection = get_documents_collection()
        document = documents_collection.find_one({"_id": ObjectId(document_id)})
        if not document:
            raise HTTPException(status_code=404, detail="Document not found")

        current_status = document["status"]
        if status not in ALLOWED_TRANSITIONS.get(DocumentStatus(current_status), []):
            raise HTTPException(status_code=400, detail=f"Invalid status transition from {current_status} to {status}")

        documents_collection.update_one(
            {"_id": ObjectId(document_id)},
            {"$set": {"status": status.value}}
        )

        audit_collection = get_audit_collection()
        audit_collection.insert_one({
            "document_id": document_id,
            "action": "status_change",
            "status": status.value,
            "user": user["username"],
            "timestamp": datetime.utcnow().isoformat()
        })

        return {"document_id": document_id, "new_status": status.value, "message": "Status updated successfully"}
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid document ID")

@app.get("/documents/{document_id}/audit")
async def get_document_audit(document_id: str):
    try:
        audit_collection = get_audit_collection()
        audit_logs = list(audit_collection.find({"document_id": document_id}).sort("timestamp", -1))
        for log in audit_logs:
            log["_id"] = str(log["_id"])
        return {"document_id": document_id, "audit_logs": audit_logs}
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid document ID")

@app.get("/")
async def root():
    return {"message": "Government Document Management System API"}

@app.on_event("startup")
async def startup_event():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    try:
        logger.info("Starting up the application...")
        init_db()
        logger.info("Database initialized successfully")
        # Initialize sample user (for testing)
        users_collection = get_users_collection()
        if users_collection.count_documents({}) == 0:
            users_collection.insert_one({
                "username": "admin",
                "password": get_password_hash("admin123"),
                "roles": ["admin", "approver"]
            })
            users_collection.insert_one({
                "username": "user1",
                "password": get_password_hash("user123"),
                "roles": ["user"]
            })
            logger.info("Sample users initialized")
        print("Connected to MongoDB")
        print("Virus scanning is disabled temporarily")
        logger.info("Application startup completed successfully")
    except Exception as e:
        logger.error(f"Error during startup: {str(e)}")
        raise

@app.on_event("shutdown")
async def shutdown_event():
    logger = logging.getLogger(__name__)
    try:
        logger.info("Shutting down the application...")
        close_db()
        logger.info("Database connection closed successfully")
        print("Disconnected from MongoDB")
        logger.info("Application shutdown completed successfully")
    except Exception as e:
        logger.error(f"Error during shutdown: {str(e)}")
        raise
