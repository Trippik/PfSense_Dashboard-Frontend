#PFSENSE DASHBOARD FRONTEND WEB APP
#REQUIRES UNDERLYING MYSQL DB - ALTER CREDENTIALS VIA ENV VARIABLES AS NEEDED
#HTML TEMPLATES REQUIRED, SHOULD BE PUT IN FOLDER ALONGSIDE PYTHON FILE /TEMPLATES/*

#-----LIBRARIES-----
from sys import prefix
from flask import Flask, render_template, session, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, DecimalField, SubmitField, PasswordField, HiddenField, DateField, IntegerField, SelectField, RadioField, TextAreaField
from wtforms.validators import DataRequired, Optional
import datetime
from waitress import serve
import os
import logging
import base64
from datetime import datetime
import folium

from frontend.lib import db_handler, location_handler, password_handler, preset_forms, web_handler

from frontend.blueprints.ovpn_pages import ovpn_pages_blueprint
from frontend.blueprints.instance_pages import instance_pages_blueprint

#Establish flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = "ASDSDFDFGHFGJHJKL"
bootstrap = Bootstrap(app)

#SET STORAGE DIRECTORY
dir = "/var/models"

#----------------------------------------------------
#WEB APP PAGES
#----------------------------------------------------
# Register OVPN pages
app.register_blueprint(ovpn_pages_blueprint)

# Register instance pages
app.register_blueprint(instance_pages_blueprint)

#LOGIN PAGE
@app.route('/', methods=["GET","POST"])
def login():
    form = preset_forms.LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        key = password_handler.password_hash_generate(password, os.environ["SALT"])
        query = 'SELECT COUNT(*) FROM dashboard_user WHERE user_name = "{}" AND pass = "{}"'
        query = query.format(username, key)
        results = db_handler.query_db(query)
        for row in results:
            user_success = int(row[0])
        if(user_success == 1):
            query = 'SELECT id FROM dashboard_user WHERE user_name = "{}" AND pass = "{}"'
            query = query.format(username, key)
            results = db_handler.query_db(query)
            for row in results:
                session["id"] = int(row[0])
            return redirect(url_for("home"))
        else:
            logging.warning("Failed Login")
    return render_template("login.html", heading="PfSense Dashboard", form=form)

#HOMEPAGE
@app.route('/home', methods=["GET","POST"])
def home():
    if(web_handler.basic_page_verify(session["id"]) == True):
        form = preset_forms.HomeForm1()
        instances_query = """SELECT id, pfsense_name, hostname, reachable_ip FROM pfsense_instances ORDER BY pfsense_name DESC"""
        last_log_query = """SELECT record_time FROM pfsense_logs WHERE pfsense_instance = {} ORDER BY record_time DESC LIMIT 1"""
        errors_query = """SELECT daily_error, weekly_error, joint_error FROM error_rates WHERE pfsense_instance = {}"""
        instances_raw = db_handler.query_db(instances_query)
        instances = []
        headings = ["Pfsense Name", "Hostname", "Reachable IP", "Last Log Entry", "Days Errors", "Weeks Errors", "Joint Errors"]
        if(len(instances_raw) == 0):
            instances = [["No Records"]]
            buttons = [["/add_instance", "Add PfSense Instance"], ["/dashboard_user_management", "Dashboard User Manager"]]
        else:
            for instance in instances_raw:
                try:
                    last_time = db_handler.query_db(last_log_query.format(instance[0]))[0][0]
                    last_time = last_time.strftime('%Y-%m-%d %H:%M:%S')
                    daily_error_percent, weekly_error_percent, joint_error_percent = db_handler.query_db(errors_query.format(str(instance[0])))[0]
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
        web_handler.user_auth_error_page()

#MAP
@app.route('/map', methods=["GET","POST"])
def map():
    if(web_handler.basic_page_verify(session["id"]) == True):
        start_coords = (51.75, -1.25)
        folium_map = folium.Map(location=start_coords, zoom_start=6)
        instance_details_query = """SELECT id, pfsense_name, latitude, longtitude FROM pfsense_instances"""
        results = db_handler.query_db(instance_details_query)
        instance_last_log = """SELECT record_time FROM pfsense_logs WHERE pfsense_instance = {} ORDER BY record_time DESC LIMIT 1"""
        for instance in results:
            logging.warning(str(instance))
            try:
                last_record_time = db_handler.query_db(instance_last_log.format(str(instance[0])))[0][0]
                now = datetime.now()
                time_delta = (now - last_record_time)
                total_seconds = time_delta.total_seconds()
                if(total_seconds < 300):
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
                try:
                    ipsec_query_1 = """SELECT remote_connection FROM pfsense_ipsec_connections WHERE pfsense_instance = {}"""
                    ipsec_query_2 = """SELECT pfsense_instance FROM pfsense_instance_interfaces WHERE ipv4_address = '{}'"""
                    ipsec_query_3 = """SELECT latitude, longtitude FROM pfsense_instances WHERE id = {}"""
                    results = db_handler.query_db(ipsec_query_1.format(str(instance[0])))
                    for items in results:
                        for item in items:
                            try:
                                remote_instance = db_handler.query_db(ipsec_query_2.format(str(item)))[0][0]
                                remote_lat, remote_long = db_handler.query_db(ipsec_query_3.format(str(remote_instance)))[0]
                                points = [[float(instance[2]), float(instance[3])], [float(remote_lat), float(remote_long)]]
                                folium.PolyLine(points, weight=2, color="black", opacity=0.3).add_to(folium_map)
                            except:
                                pass
                except:
                    pass
            except:
                logging.warning("Query Failed")
                folium.Marker(
                    [float(instance[2]), float(instance[3])],
                    popup = instance[1],
                    icon=folium.Icon(color="gray", icon="sitemap", prefix="fa")
                ).add_to(folium_map)
        return folium_map._repr_html_()
    else:
        web_handler.user_auth_error_page()

#REPORT CONFIGURATION
@app.route("/report_configuration", methods=["GET", "POST"])
def report_configuration():
    if(web_handler.basic_page_verify(session["id"]) == True):
        buttons = [["/ovpn_report_config", "OpenVPN Report Configuration"], ["/instance_log_report_config", "Per Log Error Report Configuration"]]
        return render_template("index_buttons.html", heading="Report Configuration", messages="Please select the daily report you would like to configure:", buttons=buttons)
    else:
        web_handler.user_auth_error_page()   

#DASHBOARD USERS MANAGEMENT
@app.route("/dashboard_user_management", methods=["GET", "POST"])
def dashboard_user_management():
    if(web_handler.basic_page_verify(session["id"]) == True):
        form = preset_forms.DashboardUsers()
        select_query = """SELECT id, user_name FROM dashboard_user"""
        raw_results = db_handler.query_db(select_query)
        users_lines = []
        for row in raw_results:
            new_line = [row[1], "/dashboard_user_delete/" + str(row[0]) + ";Delete User"]
            users_lines = users_lines + [new_line]
        table_headings = ["Name"]
        if form.validate_on_submit():
            insert_query = """INSERT INTO dashboard_user (user_name, pass) VALUES ("{}", "{}")"""
            user_name = form.name.data
            prov_pass = form.password.data
            salt = os.environ["SALT"]
            salted_pass = password_handler.password_hash_generate(prov_pass, salt)
            db_handler.update_db(insert_query.format(user_name, salted_pass))
            return(redirect("/dashboard_user_management"))
        return render_template("table_form.html", heading="Dashboard User Management", headings=table_headings, collection=users_lines, form=form)
    else:
        web_handler.user_auth_error_page()

#DASHBOARD USER DELETE
@app.route("/dashboard_user_delete/<id>", methods=["GET", "POST"])
def dashboard_user_delete(id):
    if(web_handler.basic_page_verify(session["id"]) == True):
        query = """DELETE FROM dashboard_user WHERE id = {}"""
        db_handler.update_db(query.format(str(id)))
        return(redirect("/dashboard_user_management"))
    else:
        web_handler.user_auth_error_page()

#----------------------------------------------------
#SERVE SITE
#----------------------------------------------------
def main():
    import sys
    logging.warning(sys.executable)
    app.debug=True
    serve(app, host="0.0.0.0", port=8080, threads=str(os.environ["THREADS"]))

if __name__ == '__main__':
    main()
