#PFSENSE DASHBOARD FRONTEND WEB APP
#REQUIRES UNDERLYING MYSQL DB - ALTER CREDENTIALS VIA ENV VARIABLES AS NEEDED
#HTML TEMPLATES REQUIRED, SHOULD BE PUT IN FOLDER ALONGSIDE PYTHON FILE /TEMPLATES/*

#-----LIBRARIES-----
from flask import Flask, render_template, session, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, DecimalField, SubmitField, PasswordField, HiddenField, DateField, IntegerField, SelectField, RadioField
from wtforms.validators import DataRequired, Optional
import mysql.connector
import datetime
from waitress import serve
import os
import logging
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime

#Establish flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = "ASDSDFDFGHFGJHJKL"
bootstrap = Bootstrap(app)

#SET DB PARAMETERS
db_host = os.environ["DB_IP"]
db_user = os.environ["DB_USER"]
db_password = os.environ["DB_PASS"]
db_schema = os.environ["DB_SCHEMA"]
db_port = os.environ["DB_PORT"]

#SET STORAGE DIRECTORY
dir = "/var/models"

#----------------------------------------------------
#UNDERLYING FUNCTIONS
#----------------------------------------------------
#READ FROM DB
def query_db(query):
    db = mysql.connector.connect(
        host=db_host,
        user=db_user,
        password=db_password,
        database=db_schema,
        port=db_port
    )
    cursor = db.cursor()
    logging.warning(query)
    cursor.execute(query)
    result = cursor.fetchall()
    return(result)

#WRITE TO DB
def update_db(query):
    db = mysql.connector.connect(
        host=db_host,
        user=db_user,
        password=db_password,
        database=db_schema,
        port=db_port
    )
    cursor = db.cursor()
    cursor.execute(query)
    db.commit()

def basic_page_verify(usr_id):
    query = 'SELECT COUNT(*) FROM dashboard_user WHERE id = {}'
    query = query.format(str(session["id"]))
    results = query_db(query)
    for row in results:
        state = row[0]
    if(state != "0"):
        return(True)
    else:
        return(False)

def select_values(table, value):
    query = 'SELECT id, {} FROM {} ORDER BY {} ASC'
    query = query.format(value, table, value)
    results = query_db(query)
    options = []
    for row  in results:
        tup = [(row[0], row[1])]
        options = options + tup
    return(options)

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


def message_build (statement, var):
    string = "{}: {} \n"
    string = string.format(statement, var)
    return(string)

def select_option_generate(table, value, mode):
    options_tup = []
    if(mode == 1):
        options_tup = [("", "Leave Unchanged"), ("NULL", "None")]
    elif(mode == 2):
        options_tup = [("NULL", "None")]
    options_tup = options_tup + select_values(table, value)
    return(options_tup)

#-----PRESET FORMS-----
#Form for login page
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")
    
#Form for buttons on homepage
class HomeForm1(FlaskForm):
    client_search = SubmitField("Search Clients")
    new_client = SubmitField("Create New Client")

#Form for Client Search fields
class ClientSearchForm(FlaskForm):
    client_name = StringField("Client Name", validators=[DataRequired()])
    submit = SubmitField("Search")

#Form for Workstation Details fields
class ClientDetailsForm(FlaskForm):
    holiday = DecimalField("Holiday Entitlement %", validators=[Optional()])
    ni = DecimalField("National Insurance %", validators=[Optional()])
    pension = DecimalField("Pension Rate %", validators=[Optional()])
    apprenticeship = DecimalField("Apprenticeship Rate %", validators=[Optional()])
    margin = DecimalField("Margin %", validators=[Optional()])
    submit = SubmitField("Create New Terms for Client", validators=[Optional()])

#Form for new client page
class NewClientForm(FlaskForm):
    client_name = StringField("Client Name", validators=[DataRequired()])
    submit = SubmitField("Create Client Record")
#-----WEB APP PAGES-----
#LOGIN PAGE
@app.route('/', methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        password = password.encode() 
        salt = os.environ["SALT"].encode()
        kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
        backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password)) 
        key = key.decode()
        query = 'SELECT COUNT(*) FROM dashboard_user WHERE user_name = "{}" AND pass = "{}"'
        query = query.format(username, key)
        results = query_db(query)
        for row in results:
            user_success = int(row[0])
        if(user_success == 1):
            query = 'SELECT id FROM dashboard_user WHERE user_name = "{}" AND pass = "{}"'
            query = query.format(username, key)
            results = query_db(query)
            for row in results:
                session["id"] = int(row[0])
            #query = 'SELECT user_group FROM dashboard_user WHERE user_name = "{}" AND pass = "{}"'
            #query = query.format(username, key)
            #results = query_db(query)
            #for row in results:
                #session["group"] = int(row[0])
            return redirect(url_for("home"))
        else:
            logging.warning("Failed Login")
    return render_template("login.html", heading="PfSense Dashboard", form=form)

#HOMEPAGE
@app.route('/home', methods=["GET","POST"])
def home():
    if(basic_page_verify(session["id"]) == True):
        form = HomeForm1()
        #Forward user to analysis or new stats page depending on button pressed
        if form.validate_on_submit():
            if form.client_search.data:
                return redirect(url_for('client_search'))
            elif form.new_client.data:
                return redirect(url_for('new_client'))
        #Render homepage based on index_form.html template
        return render_template("index_form.html", heading="Homepage", form=form, messages="Welcome to the Anderselite PAYE Admin portal. Please pick from the options below:")
    else:
        return render_template("index.html", heading="Oops!", messages="It looks like you have ended up in the wrong place.")


serve(app, host="0.0.0.0", port=8080, threads=1)