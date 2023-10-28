from flask import Blueprint, session, render_template, redirect
import logging

from frontend.lib import db_handler, web_handler, preset_forms

ovpn_pages_blueprint = Blueprint('ovpn_pages_blueprint', __name__)

database = db_handler.DB()

#ALL INSTANCE OPENVPN PAGE
@ovpn_pages_blueprint.route("/all_openvpn", methods=["GET", "POST"])
def all_openvpn():
    if(web_handler.basic_page_verify(session["id"]) == True):
        query = """SELECT record_time, vpn_user.user_name, vpn_user.id, pfsense_instances.pfsense_name, pfsense_instances.id FROM open_vpn_access_log
LEFT JOIN vpn_user ON open_vpn_access_log.vpn_user = vpn_user.id
LEFT JOIN pfsense_instances ON open_vpn_access_log.pfsense_instance = pfsense_instances.id
ORDER BY record_time DESC 
LIMIT 50"""
        results = database.query_db(query)
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
        web_handler.user_auth_error_page()

#PER INSTANCE OPENVPN PAGE
@ovpn_pages_blueprint.route("/instance_openvpn/<id>-<offset>", methods=["GET", "POST"])
def instance_openvpn(id, offset):
    if(web_handler.basic_page_verify(session["id"]) == True):
        form = preset_forms.PreviousNext()
        if form.validate_on_submit():
            if form.previous_page.data:
                new_offset = int(offset) - 50
                if(new_offset > -1):
                    new_offset = str(new_offset)
                    return redirect("/instance_openvpn/" + str(id) + "-" + str(new_offset))
                else:
                    pass
            elif form.next_page.data:
                new_offset = int(offset) + 50
                if(new_offset > 0):
                    new_offset = str(new_offset)
                    return redirect("/instance_openvpn/" + str(id) + "-" + str(new_offset))
                else:
                    pass
        query = """SELECT record_time, vpn_user.user_name, vpn_user.id FROM open_vpn_access_log LEFT JOIN vpn_user ON open_vpn_access_log.vpn_user = vpn_user.id WHERE open_vpn_access_log.pfsense_instance = {} ORDER BY record_time DESC LIMIT {}, {}"""
        logging.warning(query.format(id, offset, "50"))
        results = database.query_db(query.format(id, offset, "50"))
        filtered_results = []
        for row in results:
            new_row = []
            for item in row:
                item = str(item)
                new_row = new_row + [item]
            filtered_results = filtered_results + [new_row]
        logging.warning(filtered_results)
        final_results = []
        for row in filtered_results:
            final_results = final_results + [[row[0], row[1], "/vpn_user/" + row[2] + ";User Details"]]
        logging.warning(final_results)
        headings = ["Login Time", "User", "PfSense Instance"]
        return render_template("table_button-next_back.html", heading="OpenVPN Logins", table_headings=headings, data_collection=final_results, form=form)
    else:
        web_handler.user_auth_error_page()

#OPENVPN REPORT CONFIGURATION
@ovpn_pages_blueprint.route("/ovpn_report_config", methods=["GET", "POST"])
def ovpn_report_config():
    if(web_handler.basic_page_verify(session["id"]) == True):
        form = preset_forms.OpenVPNReportConfig()
        query = """SELECT id, reciever_name, reciever_address FROM open_vpn_report_recievers"""
        insert_reciever = """INSERT INTO open_vpn_report_recievers (reciever_name, reciever_address) VALUES ("{}", "{}")"""
        raw_results = database.query_db(query)
        final_results = []
        for row in raw_results:
            new_row = [row[1], row[2], "/open_vpn_report_reciever_delete/" + str(row[0]) + ";Remove Reciever Entry"]
            final_results = final_results + [new_row]
        headings = ["Name", "Email"]
        if form.validate_on_submit():
            user_name = form.reciever_name.data
            user_address = form.reciever_address.data
            database.update_db(insert_reciever.format(user_name, user_address))
            return(redirect("/ovpn_report_config"))
        return render_template("table_form.html", heading="OpenVPN Report Configuration", headings=headings, collection=final_results, form=form)
    else:
        web_handler.user_auth_error_page()

#OPENVPN RECIEVER DELETE
@ovpn_pages_blueprint.route("/open_vpn_report_reciever_delete/<id>", methods=["GET", "POST"])
def ovpn_report_reciever_delete(id):
    if(web_handler.basic_page_verify(session["id"]) == True):
        query = """DELETE FROM open_vpn_report_recievers WHERE id = {}"""
        database.update_db(query.format(id))
        return(redirect("/ovpn_report_config"))
    else:
        web_handler.user_auth_error_page()

#SEARCH OPENVPN ACCESS LOGS
@ovpn_pages_blueprint.route("/openvpn_access_log_search", methods=["GET", "POST"])
def openvpn_access_log_search():
    if(web_handler.basic_page_verify(session["id"]) == True):
        form = preset_forms.OVPNActivityForm()
        query = """SELECT 
vpn_user.user_name,
record_time,
pfsense_instances.pfsense_name,
FROM open_vpn_access_log
WHERE {} 
LEFT JOIN vpn_user ON open_vpn_access_log.vpn_user = vpn_user.id
LEFT JOIN pfsense_instances ON open_vpn_access_log.pfsense_instance = pfsense_instances.id"""
        if form.validate_on_submit():
            elements = [[form.user_name, "vpn_user.user_name", 1], [form.instance, "open_vpn_access_log.pfsense_instance", 2]]
            where_clause = ""
            for element in elements:
                value = element[0]
                field = element[1]
                mode = element[3]
                if(value != None):
                    if(mode == 1):
                        where_clause = where_clause + field + ' LIKE "' + value + '"'
                    elif(mode == 2):
                        where_clause = where_clause + field + ' = ' + value
            query = query.format(query.where_clause)
            session["query"] = query
            return(redirect("/open_vpn_access_search_results"))
        return render_template("form.html", heading="OpenVPN Access Log Search", form=form)
    else:
        web_handler.user_auth_error_page()