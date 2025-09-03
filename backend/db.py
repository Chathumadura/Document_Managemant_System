import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

MONGO_URL = os.getenv("MONGO_URL")
MONGO_DB = os.getenv("MONGO_DB")

# MongoDB client
client = None
db = None
documents_collection = None
audit_collection = None
users_collection = None

def init_db():
    global client, db, documents_collection, audit_collection, users_collection
    client = MongoClient(MONGO_URL)
    db = client["gov_dms"]
    documents_collection = db["documents"]
    audit_collection = db["audit_logs"]
    users_collection = db["users"]
    # Create index for file_hash to ensure uniqueness and improve query performance
    documents_collection.create_index("file_hash", unique=True)
    # Create text index for search capabilities
    documents_collection.create_index([("metadata.title", "text"), ("content_snippet", "text")])
    # Create index for audit logs by document_id and timestamp
    audit_collection.create_index([("document_id", 1), ("timestamp", -1)])
    # Create unique index for username in users collection
    users_collection.create_index("username", unique=True)

def get_db():
    if db is None:
        raise Exception("Database not initialized. Call init_db() first.")
    return db

def get_documents_collection():
    if documents_collection is None:
        raise Exception("Documents collection not initialized. Call init_db() first.")
    return documents_collection

def get_audit_collection():
    if audit_collection is None:
        raise Exception("Audit collection not initialized. Call init_db() first.")
    return audit_collection

def get_users_collection():
    if users_collection is None:
        raise Exception("Users collection not initialized. Call init_db() first.")
    return users_collection

def close_db():
    global client
    if client:
        client.close()
        client = None






















