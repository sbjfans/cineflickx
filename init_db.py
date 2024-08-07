import mysql.connector
import logging

db_name = "cineflickx"

def connect_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        passwd=""
    )

def init_db():
    db = connect_db()
    cursor = db.cursor()
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")
    cursor.execute(f"USE {db_name}")
    
    # 사용자 테이블 생성
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL
    )
    """)

    # 활동 로그 테이블 생성
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS activity_log (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        activity VARCHAR(50) NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    # 삭제된 사용자 테이블 생성
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS deleted_users (
        id INT PRIMARY KEY,
        username VARCHAR(50),
        deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (id) REFERENCES users(id)
    )
    """)


    db.commit()
    cursor.close()
    db.close()
    logging.info("Database initialized successfully.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    init_db()
