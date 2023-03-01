from flask import Blueprint, session, render_template, redirect
import logging

from frontend.lib import web_handler, ip_lookup

ip_details_pages_blueprint = Blueprint('ip_detail_pages_blueprint', __name__)

#PER INSTANCE SYSTEM USERS PAGE
@ip_details_pages_blueprint.route("/ip_details/<ip>", methods=["GET", "POST"])
def ip_details(ip):
    if(web_handler.basic_page_verify(session["id"]) == True):
        logging.error(type(ip))
        logging.error(ip)
        ip_details = ip_lookup.get_ip_details(ip)
        final_tup = [
            ["IP", ip_details["ip"]], 
            ["Country", ip_details["country"]], 
            ["Region", ip_details["region"]], 
            ["City", ip_details["city"]], 
            ["ISP", ip_details["connection"]["isp"]], 
            ["Organisation", ip_details["connection"]["org"]]
            ]
        fol_map = ip_lookup.show_ip_map(ip_details)
        fol_map.get_root().width = "800px"
        fol_map.get_root().height = "600px"
        fol_iframe = fol_map.get_root()._repr_html_()
        return render_template("iframe.html", heading="IP Details", messages=final_tup, iframe=fol_iframe)
    else:
        web_handler.user_auth_error_page()