from flask import Blueprint, session, render_template, redirect
import logging

from frontend.lib import web_handler, ip_lookup

ip_details_pages_blueprint = Blueprint('ip_detail_pages_blueprint', __name__)

#PER INSTANCE SYSTEM USERS PAGE
@ip_details_pages_blueprint.route("/instance_users/<ip>", methods=["GET", "POST"])
def ip_details(ip):
    if(web_handler.basic_page_verify(session["id"]) == True):
        ip_details = ip_lookup.ip_details(ip)
    else:
        web_handler.user_auth_error_page()