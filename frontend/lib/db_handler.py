import mysql.connector
import os

class DB:
    def __init__(self):
        self._ip = os.environ["DB_IP"]
        self._user = os.environ["DB_USER"]
        self._password = os.environ["DB_PASS"]
        self._schema = os.environ["DB_SCHEMA"]
        self._port = os.environ["DB_PORT"]
        self.conn = self._create_db_connection()
        self.cursor = self.conn.cursor()

    def _create_db_connection(self):
        return mysql.connector.connect(
            host=self._ip,
            user=self._user,
            password=self._password,
            database=self._schema,
            port=self._port
        )

    #READ FROM DB
    def query_db(self, query):
        self.cursor.execute(query)
        result = self.cursor.fetchall()
        return(result)

    #WRITE TO DB
    def update_db(self, query):
        self.cursor.execute(query)
        self.conn.commit()

    def select_values(self, table, value):
        query = 'SELECT id, {} FROM {} ORDER BY {} ASC'
        query = query.format(value, table, value)
        results = self.query_db(query)
        options = []
        for row  in results:
            tup = [(row[0], row[1])]
            options = options + tup
        return(options)

    def add_ip(self, ip):
        query = "INSERT INTO pfsense_ip (ip) VALUES ('{}')"
        self.update_db(query.format(ip))
        find_ip(ip)

    def find_ip(self, ip):
        query = "SELECT id FROM pfsense_ip WHERE ip = '{}'"
        ip_id = self.query_db(query.format(ip))[0][0]
        if(ip_id == "NULL" or ip_id == None):
            add_ip(ip)
        else:
            return(ip_id)

    def query_where (self, where_tuples):
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

    def return_client_options(self):
        query = """SELECT id, pfsense_name FROM pfsense_instances ORDER BY pfsense_name ASC"""
        clients = self.query_db(query)
        return(clients)
