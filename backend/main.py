from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from db import client

app = FastAPI(title="Government Document Management System")

# CORS configuration for government networks (adjust origins as needed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Update with frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "Government Document Management System API"}

@app.on_event("startup")
async def startup_event():
    # Ensure MongoDB connection is active
    client.admin.command("ping")
    print("Connected to MongoDB")

@app.on_event("shutdown")
async def shutdown_event():
    client.close()
    print("Disconnected from MongoDB")