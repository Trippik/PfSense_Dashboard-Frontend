from flask import Blueprint, session, render_template, redirect, url_for
import logging
import os

from frontend.lib import db_handler, web_handler, preset_forms, password_handler

system_pages_blueprint = Blueprint('system_pages_blueprint', __name__)

database = db_handler.DB()

#LOGIN PAGE
@system_pages_blueprint.route('/', methods=["GET","POST"])
def login():
    form = preset_forms.LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        key = password_handler.password_hash_generate(password, os.environ["SALT"])
        query = 'SELECT COUNT(*) FROM dashboard_user WHERE user_name = "{}" AND pass = "{}"'
        query = query.format(username, key)
        results = database.query_db(query)
        for row in results:
            user_success = int(row[0])
        if(user_success == 1):
            query = 'SELECT id FROM dashboard_user WHERE user_name = "{}" AND pass = "{}"'
            query = query.format(username, key)
            results = database.query_db(query)
            for row in results:
                session["id"] = int(row[0])
            return redirect("/home")
        else:
            logging.warning("Failed Login")
    return render_template("login.html", heading="PfSense Dashboard", form=form)

#HOMEPAGE
@system_pages_blueprint.route('/home', methods=["GET","POST"])
def home():
    if(web_handler.basic_page_verify(session["id"]) == True):
        form = preset_forms.HomeForm1()
        instances_query = """SELECT id, pfsense_name, hostname, reachable_ip FROM pfsense_instances ORDER BY pfsense_name DESC"""
        last_log_query = """SELECT record_time FROM pfsense_logs WHERE pfsense_instance = {} ORDER BY record_time DESC LIMIT 1"""
        errors_query = """SELECT daily_error, weekly_error, joint_error FROM error_rates WHERE pfsense_instance = {}"""
        instances_raw = database.query_db(instances_query)
        instances = []
        headings = ["Pfsense Name", "Hostname", "Reachable IP", "Last Log Entry", "Days Errors", "Weeks Errors", "Joint Errors"]
        if(len(instances_raw) == 0):
            instances = [["No Records"]]
            buttons = [["/add_instance", "Add PfSense Instance"], ["/dashboard_user_management", "Dashboard User Manager"]]
        else:
            for instance in instances_raw:
                try:
                    last_time = database.query_db(last_log_query.format(instance[0]))[0][0]
                    last_time = last_time.strftime('%Y-%m-%d %H:%M:%S')
                    daily_error_percent, weekly_error_percent, joint_error_percent = database.query_db(errors_query.format(str(instance[0])))[0]
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

#REPORT CONFIGURATION
@system_pages_blueprint.route("/report_configuration", methods=["GET", "POST"])
def report_configuration():
    if(web_handler.basic_page_verify(session["id"]) == True):
        buttons = [["/ovpn_report_config", "OpenVPN Report Configuration"], ["/instance_log_report_config", "Per Log Error Report Configuration"]]
        return render_template("index_buttons.html", heading="Report Configuration", messages="Please select the daily report you would like to configure:", buttons=buttons)
    else:
        web_handler.user_auth_error_page()   

#DASHBOARD USERS MANAGEMENT
@system_pages_blueprint.route("/dashboard_user_management", methods=["GET", "POST"])
def dashboard_user_management():
    if(web_handler.basic_page_verify(session["id"]) == True):
        form = preset_forms.DashboardUsers()
        select_query = """SELECT id, user_name FROM dashboard_user"""
        raw_results = database.query_db(select_query)
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
            database.update_db(insert_query.format(user_name, salted_pass))
            return(redirect("/dashboard_user_management"))
        return render_template("table_form.html", heading="Dashboard User Management", headings=table_headings, collection=users_lines, form=form)
    else:
        web_handler.user_auth_error_page()

#DASHBOARD USER DELETE
@system_pages_blueprint.route("/dashboard_user_delete/<id>", methods=["GET", "POST"])
def dashboard_user_delete(id):
    if(web_handler.basic_page_verify(session["id"]) == True):
        query = """DELETE FROM dashboard_user WHERE id = {}"""
        database.update_db(query.format(str(id)))
        return(redirect("/dashboard_user_management"))
    else:
        web_handler.user_auth_error_page()