from dotenv import load_dotenv
from pymongo import MongoClient
import os


# Load the existing .env file
load_dotenv()  # by default it looks for .env in project root

# Read MongoDB credentials from environment variables

MONGO_URL = os.getenv("MONGO_URL")
MONGO_DB = os.getenv("MONGO_DB")

# Build MongoDB connection URI


# Connect to MongoDB
client = MongoClient(MONGO_URL)

# Select the database
db = client[MONGO_DB]

# Select the collection
documents_collection = db["documents"]
