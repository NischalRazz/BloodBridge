"""
Simple script to create the Testimonial and ImpactStat tables
without triggering route conflicts
"""

import os
import sys
import psycopg2
from psycopg2 import sql

# Database connection details - match these with your app configuration
DB_URI = "postgresql://postgres:Ss%40071424@localhost:5432/task_manager"

def create_tables():
    """Create the new tables using direct SQL connection"""
    try:
        # Parse DB_URI to get connection parameters
        # Example URI: postgresql://username:password@hostname:port/database
        parts = DB_URI.split('://', 1)[1]
        auth, rest = parts.split('@', 1)
        
        if ':' in auth:
            username, password = auth.split(':', 1)
        else:
            username, password = auth, None
            
        if '/' in rest:
            host_port, dbname = rest.split('/', 1)
        else:
            host_port, dbname = rest, 'postgres'
            
        if ':' in host_port:
            host, port = host_port.split(':', 1)
            port = int(port)
        else:
            host, port = host_port, 5432
        
        # Connect to the database
        conn = psycopg2.connect(
            dbname=dbname,
            user=username,
            password=password,
            host=host,
            port=port
        )
        
        # Create a cursor
        cursor = conn.cursor()
        
        # Check if the tables already exist
        cursor.execute("SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = 'testimonial')")
        testimonial_exists = cursor.fetchone()[0]
        
        cursor.execute("SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = 'impact_stat')")
        impact_stat_exists = cursor.fetchone()[0]
        
        # Create tables if they don't exist
        if not testimonial_exists:
            print("Creating 'testimonial' table...")
            cursor.execute("""
                CREATE TABLE testimonial (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    role VARCHAR(100) NOT NULL,
                    content TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            print("'testimonial' table created successfully.")
        else:
            print("'testimonial' table already exists.")
        
        if not impact_stat_exists:
            print("Creating 'impact_stat' table...")
            cursor.execute("""
                CREATE TABLE impact_stat (
                    id SERIAL PRIMARY KEY,
                    title VARCHAR(100) NOT NULL,
                    count INTEGER NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            print("'impact_stat' table created successfully.")
        else:
            print("'impact_stat' table already exists.")
        
        # Commit the changes
        conn.commit()
        print("Database changes committed successfully.")
        
        # Close the connection
        cursor.close()
        conn.close()
        return True
        
    except Exception as e:
        print(f"Error creating tables: {str(e)}")
        return False

if __name__ == "__main__":
    print("Creating tables for dynamic homepage content...")
    success = create_tables()
    if success:
        print("Table creation completed successfully.")
    else:
        print("Table creation failed. See error messages above.")
        sys.exit(1)