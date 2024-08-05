import mysql.connector
import logging

db_name = "cineflickx"

def connect_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        passwd="",
        db=db_name
    )

def query_db(query, args=(), one=False):
    db = connect_db()
    cur = db.cursor()
    logging.debug(f'Executing query: {query} with args: {args}')
    cur.execute(query, args)
    rv = cur.fetchall()
    cur.close()
    db.close()
    return (rv[0] if rv else None) if one else rv

def insert_db(query, args=()):
    db = connect_db()
    cur = db.cursor()
    logging.debug(f'Executing insert: {query} with args: {args}')
    cur.execute(query, args)
    db.commit()
    cur.close()
    db.close()
