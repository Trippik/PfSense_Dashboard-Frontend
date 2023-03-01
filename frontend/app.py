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
from frontend.blueprints.system_pages import system_pages_blueprint
from frontend.blueprints.ip_detail_pages import ip_details_pages_blueprint

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

# Register system pages
app.register_blueprint(system_pages_blueprint)

# Register ip details pages
app.register_blueprint(ip_details_pages_blueprint)

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
