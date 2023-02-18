import mysql.connector
import os

def pull_db_details():
    return (os.environ["DB_IP"],os.environ["DB_USER"],os.environ["DB_PASS"],os.environ["DB_SCHEMA"],os.environ["DB_PORT"])

def create_db_connection():
    db_details = pull_db_details()
    return mysql.connector.connect(
        host=db_details[0],
        user=db_details[1],
        password=db_details[2],
        database=db_details[3],
        port=db_details[4]
    )

#READ FROM DB
def query_db(query):
    with create_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query)
        result = cursor.fetchall()
        return(result)

#WRITE TO DB
def update_db(query):
    with create_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query)
        conn.commit()

def select_values(table, value):
    query = 'SELECT id, {} FROM {} ORDER BY {} ASC'
    query = query.format(value, table, value)
    results = query_db(query)
    options = []
    for row  in results:
        tup = [(row[0], row[1])]
        options = options + tup
    return(options)

def add_ip(ip):
    query = "INSERT INTO pfsense_ip (ip) VALUES ('{}')"
    update_db(query.format(ip))
    find_ip(ip)

def find_ip(ip):
    query = "SELECT id FROM pfsense_ip WHERE ip = '{}'"
    ip_id = query_db(query.format(ip))[0][0]
    if(ip_id == "NULL" or ip_id == None):
        add_ip(ip)
    else:
        return(ip_id)

def query_where (where_tuples):
    query_part = "WHERE "
    for item in where_tuples:
        if(item[2] == 1):
            clause = '{} LIKE "%{}%" AND '
            clause = clause.format(item[0], item[1])
            query_part = query_part + clause
        elif(item[2] == 2):
            clause = '{} = {} AND '
            clause = clause.format(item[0], item[1])
            query_part = query_part + clause 
    query_part = query_part[:-4]
    return(query_part)

def return_client_options():
    query = """SELECT id, pfsense_name FROM pfsense_instances ORDER BY pfsense_name ASC"""
    clients = query_db(query)
    return(clients)