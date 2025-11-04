"""
Quick database test - creates tables and shows structure
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

from storage.database import db_manager, init_database
from storage.models import Base

print("="*60)
print("🛡️  ThreatEye Database Test")
print("="*60)

# Initialize database
print("\n1. Initializing database...")
try:
    init_database()
    print("   ✅ Database initialized successfully!")
except Exception as e:
    print(f"   ❌ Error: {e}")
    exit(1)

# Check tables
print("\n2. Checking created tables...")
from sqlalchemy import inspect
engine = db_manager.get_engine()
inspector = inspect(engine)
tables = inspector.get_table_names()

print(f"   Found {len(tables)} tables:")
for table in sorted(tables):
    print(f"      - {table}")

# Health check
print("\n3. Running health check...")
if db_manager.health_check():
    print("   ✅ Database is healthy!")
else:
    print("   ❌ Database health check failed!")

print("\n" + "="*60)
print("✅ Database test completed successfully!")
print("="*60)
