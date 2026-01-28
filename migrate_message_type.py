from app import app, db
from sqlalchemy import text

with app.app_context():
    try:
        # Check if column exists first to avoid error
        # Actually in Postgres ALTER TABLE ADD COLUMN IF NOT EXISTS is valid
        # In SQLite it is not.
        # Let's assume Postgres given psycopg2
        
        # Try finding if it is postgres or sqlite from config or just try/except
        
        with db.engine.connect() as conn:
            conn.execute(text("ALTER TABLE message ADD COLUMN type VARCHAR(20) DEFAULT 'text'"))
            conn.commit()
            print("Migration successful: Added 'type' column to 'message' table.")
    except Exception as e:
        print(f"Migration failed (might already exist): {e}")
