#PFSENSE DASHBOARD FRONTEND WEB APP
#REQUIRES UNDERLYING MYSQL DB - ALTER CREDENTIALS VIA ENV VARIABLES AS NEEDED
#HTML TEMPLATES REQUIRED, SHOULD BE PUT IN FOLDER ALONGSIDE PYTHON FILE /TEMPLATES/*

#-----LIBRARIES-----
from sys import prefix
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
import folium
import geopy

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

def user_auth_error_page():
    return render_template("index.html", heading="Oops!", messages="It looks like you have ended up in the wrong place.")

def percent_process(rate, total):
    dec = rate / total
    percent = int(dec * 100)
    percent = str(percent) + "%"
    return(percent)

def long_lat_calc(address):
    geocoder = geopy.Nominatim(user_agent = os.environ["NOMINATIM_USER"])
    address_data = geocoder.geocode(address)
    lat = address_data.latitude
    long = address_data.longitude
    return(long, lat)

#----------------------------------------------------
#PRESET FORMS
#----------------------------------------------------
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

#Form for Instance Details Fields
class InstanceDetailsForm(FlaskForm):
    instance_name = StringField("Name", validators=[Optional()])
    hostname = StringField("Hostname", validators=[Optional()])
    reachable_ip = StringField("Reachable IP", validators=[Optional()])
    instance_user = StringField("Instance User", validators=[Optional()])
    instance_password = StringField("Instance Password", validators=[Optional()])
    ssh_port = IntegerField("SSH Port", validators=[Optional()])
    address = StringField("Address", validators=[Optional()])
    submit = SubmitField("Alter Record", validators=[Optional()])

#Form for Adding new Instance
class NewInstanceForm(FlaskForm):
    instance_name = StringField("Name", validators=[DataRequired()])
    hostname = StringField("Hostname", validators=[DataRequired()])
    reachable_ip = StringField("Reachable IP", validators=[DataRequired()])
    instance_user = StringField("Instance User", validators=[DataRequired()])
    instance_password = StringField("Instance Password", validators=[DataRequired()])
    ssh_port = IntegerField("SSH Port", validators=[DataRequired()])
    submit = SubmitField("Add Instance to System", validators=[Optional()])

#Form for previous and next pages
class PreviousNext(FlaskForm):
    previous_page = SubmitField("Previous Page", validators=[Optional()])
    next_page = SubmitField("Next Page", validators=[Optional()])

#----------------------------------------------------
#WEB APP PAGES
#----------------------------------------------------
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
        instances_query = """SELECT id, pfsense_name, hostname, reachable_ip FROM pfsense_instances ORDER BY pfsense_name DESC"""
        last_log_query = """SELECT record_time FROM pfsense_logs WHERE pfsense_instance = {} ORDER BY record_time DESC LIMIT 1"""
        count_days_logs = """SELECT COUNT(*) FROM pfsense_logs WHERE pfsense_instance = {} AND record_time < '{}' AND record_time > '{}'"""
        count_days_errors = """SELECT COUNT(*) FROM pfsense_logs WHERE pfsense_instance = {} AND record_time < '{}' AND record_time > '{}' AND previous_day_ml_check = {}"""
        count_week_errors = """SELECT COUNT(*) FROM pfsense_logs WHERE pfsense_instance = {} AND record_time < '{}' AND record_time > '{}' AND previous_week_ml_check = {}"""
        count_both_errors = """SELECT COUNT(*) FROM pfsense_logs WHERE pfsense_instance = {} AND record_time < '{}' AND record_time > '{}' AND previous_day_ml_check = {} AND previous_week_ml_check = {}"""
        instances_raw = query_db(instances_query)
        instances = []
        headings = ["Pfsense Name", "Hostname", "Reachable IP", "Last Log Entry", "Days Errors", "Weeks Errors", "Joint Errors"]
        for instance in instances_raw:
            try:
                last_time = query_db(last_log_query.format(instance[0]))[0][0]
                last_time = last_time.strftime('%Y-%m-%d %H:%M:%S')
                now = datetime.now()
                today = now.strftime('%Y-%m-%d')
                log_count = int(query_db(count_days_logs.format(instance[0], last_time, today))[0][0])
                daily_error_rate = int(query_db(count_days_errors.format(instance[0], last_time, today, "-1"))[0][0])
                weekly_error_rate = int(query_db(count_week_errors.format(instance[0], last_time, today, "-1"))[0][0])
                joint_error_rate = int(query_db(count_both_errors.format(instance[0], last_time, today, "-1", "-1"))[0][0])
                daily_error_percent = percent_process(daily_error_rate, log_count)
                weekly_error_percent = percent_process(weekly_error_rate, log_count)
                joint_error_percent = percent_process(joint_error_rate, log_count)
            except:
                last_time = "No logs"
                daily_error_percent = "NA"
                weekly_error_percent = "NA"
                joint_error_percent = "NA"
            name = ";" + str(instance[1])
            id = str(instance[0])
            instances = instances + [[name, str(instance[2]), str(instance[3]), last_time, daily_error_percent, weekly_error_percent, joint_error_percent, "/instance_logs/" + id + "-0;Logs", "/instance_details/" + id + ";Details"]]
            buttons = [["/map", "Network Map"]]
        #Render homepage based on index_form.html template
        return render_template("vertical_table_page_buttons.html", heading="Homepage", headings=headings, collection=instances, buttons=buttons)
    else:
        user_auth_error_page()

#MAP
@app.route('/map', methods=["GET","POST"])
def map():
    if(basic_page_verify(session["id"]) == True):
        start_coords = (51.75, -1.25)
        folium_map = folium.Map(location=start_coords, zoom_start=6)
        instance_details_query = """SELECT id, pfsense_name, latitude, longtitude FROM pfsense_instances"""
        results = query_db(instance_details_query)
        instance_last_log = """SELECT record_time FROM pfsense_logs WHERE pfsense_instance = {} ORDER BY record_time DESC LIMIT 1"""
        for instance in results:
            logging.warning(str(instance))
            try:
                last_record_time = query_db(instance_last_log.format(str(instance[0])))[0][0]
                now = datetime.now()
                time_delta = (now - last_record_time)
                total_seconds = time_delta.total_seconds()
                if(total_seconds < 121):
                    logging.warning("Success")
                    folium.Marker(
                        [float(instance[2]), float(instance[3])],
                        popup = instance[1],
                        icon=folium.Icon(color="blue", icon="sitemap", prefix="fa")
                    ).add_to(folium_map)
                else:
                    logging.warning("No Recent Logs")
                    folium.Marker(
                        [float(instance[2]), float(instance[3])],
                        popup = instance[1],
                        icon=folium.Icon(color="red", icon="sitemap", prefix="fa")
                    ).add_to(folium_map)
            except:
                logging.warning("Query Failed")
                folium.Marker(
                    [float(instance[2]), float(instance[3])],
                    popup = instance[1],
                    icon=folium.Icon(color="gray", icon="sitemap", prefix="fa")
                ).add_to(folium_map)
        return folium_map._repr_html_()
    else:
        user_auth_error_page()

#ALL INSTANCE OPENVPN PAGE
@app.route("/all_openvpn", methods=["GET", "POST"])
def all_openvpn():
    if(basic_page_verify(session["id"]) == True):
        query = """SELECT record_time, vpn_user.user_name, vpn_user.id, pfsense_instances.pfsense_name, pfsense_instances.id FROM open_vpn_access_log
LEFT JOIN vpn_user ON open_vpn_access_log.vpn_user = vpn_user.id
LEFT JOIN pfsense_instances ON open_vpn_access_log.pfsense_instance = pfsense_instances.id
ORDER BY record_time DESC 
LIMIT 50"""
        results = query_db(query)
        filtered_results = []
        for row in results:
            new_row = []
            for item in row:
                item = str(item)
                new_row = new_row + [item]
            filtered_results = filtered_results + [new_row]
        final_results = []
        for row in filtered_results:
            final_results = final_results + [[row[0], row[1], row[3], "/vpn_user/" + row[2] + ";User Details", "/instance_details/" + row[4] + ";Instance Details"]]
        headings = ["Login Time", "User", "PfSense Instance"]
        return render_template("vertical_table.html", heading="OpenVPN Logins", headings=headings, collection=final_results)
    else:
        user_auth_error_page()

#PER INSTANCE OPENVPN PAGE
@app.route("/instance_openvpn/<id>", methods=["GET", "POST"])
def instance_openvpn(id):
    if(basic_page_verify(session["id"]) == True):
        query = """SELECT record_time, vpn_user.user_name, vpn_user.id FROM open_vpn_access_log
LEFT JOIN vpn_user ON open_vpn_access_log.vpn_user = vpn_user.id
WHERE open_vpn_access_log.pfsense_instance = {}
ORDER BY record_time DESC 
LIMIT 50"""
        results = query_db(query.format(id))
        filtered_results = []
        for row in results:
            new_row = []
            for item in row:
                item = str(item)
                new_row = new_row + [item]
            filtered_results = filtered_results + [new_row]
        final_results = []
        for row in filtered_results:
            final_results = final_results + [[row[0], row[1], "/vpn_user/" + row[2] + ";User Details"]]
        headings = ["Login Time", "User", "PfSense Instance"]
        return render_template("vertical_table.html", heading="OpenVPN Logins", headings=headings, collection=final_results)
    else:
        user_auth_error_page()

#INSTANCE LOGS PAGE
@app.route("/instance_logs/<id>-<offset>", methods=["GET", "POST"])
def instance_logs(id, offset):
    if(basic_page_verify(session["id"]) == True):
        form = PreviousNext()
        if form.validate_on_submit():
            if form.previous_page.data:
                new_offset = int(offset) - 50
                if(new_offset > 0):
                    new_offset = str(new_offset)
                    return redirect("/instance_logs/" + str(id) + "-" + str(new_offset))
                else:
                    pass
            elif form.next_page.data:
                new_offset = int(offset) + 50
                if(new_offset > 0):
                    new_offset = str(new_offset)
                    return redirect("/instance_logs/" + str(id) + "-" + str(new_offset))
                else:
                    pass
        query = """SELECT 
record_time,
rule_number,
pfsense_real_interface.interface,
pfsense_reason.reason,
pfsense_act.act,
pfsense_direction.direction,
ip_version,
pfsense_protocol.protocol,
pfsense_source_ip.ip,
source_port,
pfsense_destination_ip.ip,
destination_port,
previous_day_ml_check,
previous_week_ml_check,
combined_ml_check
FROM pfsense_logs
LEFT JOIN pfsense_real_interface ON pfsense_logs.real_interface = pfsense_real_interface.id
LEFT JOIN pfsense_reason ON pfsense_logs.reason = pfsense_reason.id
LEFT JOIN pfsense_act ON pfsense_logs.act = pfsense_act.id
LEFT JOIN pfsense_direction ON pfsense_logs.direction = pfsense_direction.id
LEFT JOIN pfsense_protocol ON pfsense_logs.protocol = pfsense_protocol.id
LEFT JOIN pfsense_ip AS pfsense_source_ip ON pfsense_logs.source_ip = pfsense_source_ip.id
LEFT JOIN pfsense_ip AS pfsense_destination_ip ON pfsense_logs.destination_ip = pfsense_destination_ip.id
WHERE pfsense_logs.pfsense_instance = {}
ORDER BY pfsense_logs.record_time DESC
LIMIT {}, {}"""
        results = query_db(query.format(id, offset, "50"))
        final_results = []
        for row in results:
            new_row = []
            for item in row:
                item = str(item)
                new_row = new_row + [item]
            final_results = final_results + [new_row]
        headings = ["Time", "Rule Number", "Interface", "Reason", "Act", "Direction", "IP Version", "Protocol", "Source IP", "Source Port", "Destination IP", "Destination Port", "Daily ML Check", "Weekly ML Check", "Combined ML Check"]
        return render_template("table_button-next_back.html", heading="Log Results", table_headings=headings, data_collection=final_results, form=form)
    else:
        user_auth_error_page()

#INSTANCE DETAILS PAGE
@app.route("/instance_details/<id>", methods=["GET", "POST"])
def instance_details(id):
    if(basic_page_verify(session["id"]) == True):
        form = InstanceDetailsForm()
        instance_details_query = """SELECT 
pfsense_name,
hostname,
reachable_ip,
instance_user,
instance_password,
ssh_port,
freebsd_version.freebsd_version,
pfsense_release.pfsense_release
FROM pfsense_instances
LEFT JOIN freebsd_version ON pfsense_instances.freebsd_version = freebsd_version.id
LEFT JOIN pfsense_release ON pfsense_instances.pfsense_release = pfsense_release.id
WHERE pfsense_instances.id = {}"""
        interfaces_query = """SELECT 
`interface_description`,
`interface_name`,
`mac_address`,
`ipv6_address`,
`ipv4_address`,
`interface_type`
FROM `pfsense_instance_interfaces` WHERE pfsense_instance = {}"""
        instance_results = query_db(instance_details_query.format(str(id)))[0]
        pre_amble_tup = ["Name", "Hostname", "Reachable IP", "Instance User", "Instance Password", "SSH Port", "FreeBSD Version", "PfSense Release"]
        final_tup = []
        max_count = len(pre_amble_tup)
        element_count = 0
        buttons_tup = [["/instance_rules/" + str(id), "Firewall Rules"], ["/instance_logs/" + str(id), "Instance Logs"], ["/instance_openvpn/" + str(id), "Instance OpenVPN Log"], ["/instance_users/" + str(id), "Instance Users"]]
        while(element_count < max_count):
            result_element = str(instance_results[element_count])
            item = [[pre_amble_tup[element_count], result_element]]
            final_tup = final_tup + item
            element_count = element_count + 1
        instance_int = query_db(interfaces_query.format(str(id)))
        headings_tup = ["Interface Name", "Interface", "MAC Address", "IPv6", "IPv4", "Interface Type"]
        if form.validate_on_submit():
            fields_tup = [["pfsense_name", form.instance_name.data, 1], ["hostname", form.hostname.data, 1], ["reachable_ip", form.reachable_ip.data, 1], ["instance_user", form.instance_user.data, 1], ["instance_password", form.instance_password.data, 1], ["ssh_port", form.ssh_port.data, 1], ["address", form.address.data, 3]]
            clause = ""
            for item in fields_tup:
                if(item[1] == ""):
                    pass
                elif(item[1] == None):
                    pass
                else:
                    if(item[2] == 1):
                        element = '"' + item[1] + '"'
                    elif(item[2] == 2):
                        element = item[1]
                    elif(item[2] == 3):
                        element = '"' + item[1] + '"'
                        long, lat = long_lat_calc(item[1])
                        query = """UPDATE pfsense_instances SET longtitude = {}, latitude = {} WHERE id = {}"""
                        update_db(query.format(str(long), str(lat), str(id)))
                    clause = clause + item[0] + " = " + element + ", "
            clause = clause[:-2]
            update_query = """UPDATE pfsense_instances SET {} WHERE id = {}"""
            update_db(update_query.format(clause, str(id)))
            return (redirect('/instance_details/' + str(id)))
        return render_template("instance_details.html", heading="Instance Details", headings=headings_tup, collection=instance_int, messages=final_tup, buttons=buttons_tup, form=form)
    else:
      user_auth_error_page()

#INSTANCE FIREWALL RULES PAGE
@app.route("/instance_rules/<id>", methods=["GET", "POST"])
def instance_rules(id):
    if(basic_page_verify(session["id"]) == True):
        query = """SELECT
rule_number,
rule_description
FROM pfsense_firewall_rules
WHERE pfsense_instance = {}
ORDER BY rule_number ASC"""
        results = query_db(query.format(str(id)))
        final_results = []
        for row in results:
            new_row = []
            for item in row:
                item = str(item)
                new_row = new_row + [item]
            final_results = final_results + [new_row]
        headings = ["Rule Number", "Rule Description"]
        return render_template("table_button.html", heading="Log Results", table_headings=headings, data_collection=final_results)
    else:
        user_auth_error_page()


#ADD NEW INSTANCE TO SYSTEM
@app.route("/add_instance", methods=["GET", "POST"])
def add_instance():
    if(basic_page_verify(session["id"]) == True):
        form = NewInstanceForm()
        if form.validate_on_submit():
            insert_query = """INSERT INTO `Dashboard_DB`.`pfsense_instances` (`pfsense_name`, `hostname`, `reachable_ip`, `instance_user`, `instance_password`, `ssh_port`) VALUES ("{}", "{}", "{}", "{}", "{}", {});"""
            update_db(insert_query.format(form.instance_name.data, form.hostname.data, form.reachable_ip.data, form.instance_user.data, form.instance_password.data, str(form.ssh_port.data)))
            select_query = """SELECT id FROM pfsense_instances WHERE
pfsense_name = "{}" 
AND hostname = "{}" 
AND reachable_ip = "{}" 
AND instance_user = "{}" 
AND instance_password = "{}" 
AND ssh_port = {}"""
            id = query_db(select_query.format(form.instance_name.data, form.hostname.data, form.reachable_ip.data, form.instance_user.data, form.instance_password.data, str(form.ssh_port.data)))[0][0]
            return (redirect('/instance_details/' + str(id)))
        return render_template("index_form.html", heading="Add New Instance", form=form)
    else:
        user_auth_error_page()

    
#----------------------------------------------------
#SERVE SITE
#----------------------------------------------------
serve(app, host="0.0.0.0", port=8080, threads=1)
