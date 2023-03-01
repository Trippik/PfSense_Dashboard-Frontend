from flask import Blueprint, session, render_template, redirect
import logging

from frontend.lib import db_handler, web_handler, preset_forms, location_handler

instance_pages_blueprint = Blueprint('instance_pages_blueprint', __name__)

#PER INSTANCE SYSTEM USERS PAGE
@instance_pages_blueprint.route("/instance_users/<id>-<offset>", methods=["GET", "POST"])
def instance_users(id, offset):
    if(web_handler.basic_page_verify(session["id"]) == True):
        form = preset_forms.PreviousNext()
        if form.validate_on_submit():
            if form.previous_page.data:
                new_offset = int(offset) - 50
                if(new_offset > -1):
                    new_offset = str(new_offset)
                    return redirect("/instance_users/" + str(id) + "-" + str(new_offset))
                else:
                    pass
            elif form.next_page.data:
                new_offset = int(offset) + 50
                if(new_offset > 0):
                    new_offset = str(new_offset)
                    return redirect("/instance_users/" + str(id) + "-" + str(new_offset))
                else:
                    pass
        query = """SELECT user_name, user_group, user_description FROM pfsense_instance_users WHERE pfsense_instance = {} ORDER BY user_name ASC LIMIT {}, {} """
        logging.warning(query.format(id, offset, "50"))
        results = db_handler.query_db(query.format(id, offset, "50"))
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
            final_results = final_results + [[row[0], row[1], row[2]]]
        logging.warning(final_results)
        headings = ["Username", "User Group", "Description"]
        return render_template("table_button-next_back.html", heading="Instance Users", table_headings=headings, data_collection=final_results, form=form)
    else:
        web_handler.user_auth_error_page()

#PER INSTANCE WHITELIST PAGE
@instance_pages_blueprint.route("/instance_whitelist/<id>", methods=["GET", "POST"])
def instance_whitelist(id):
    if(web_handler.basic_page_verify(session["id"]) == True):
        form = preset_forms.WhitelistForm()
        message = "You can specify exact origin IP addresses and ports that you want put on a whitelist for this instance below."
        query = """SELECT whitelist.id, pfsense_ip.ip, destination_port FROM whitelist LEFT JOIN pfsense_ip ON whitelist.ip = pfsense_ip.id WHERE pfsense_instance = {}"""
        whitelist_results = db_handler.query_db(query.format(str(id)))
        results = []
        logging.warning(str(whitelist_results))
        if(len(whitelist_results) == 0):
            results = [["None"]]
        elif(len(whitelist_results) > 0):
            for row in whitelist_results:
                results = results + [[row[1], str(row[2]), "/whitelist_delete/" + str(row[0]) + "-" + str(id) + ";Delete Entry"]]
        headings_tup = ["IP Address", "Port"]
        if form.validate_on_submit():
            insert_query = """INSERT INTO whitelist (ip, destination_port, pfsense_instance) VALUES ({}, {}, {})"""
            ip_id = db_handler.find_ip(form.ip.data)
            port = form.port.data
            db_handler.update_db(insert_query.format(str(ip_id), str(port), str(id)))
            return redirect("/instance_whitelist/" + str(id))
        return render_template("whitelist_page.html", heading="Instance Whitelist", message=message, form=form, table_headings=headings_tup, data_collection=results)
    else:
        web_handler.user_auth_error_page()

#WHITELIST DELETE
@instance_pages_blueprint.route("/whitelist_delete/<id>-<pf_id>", methods=["GET", "POST"])
def whitelist_delete(id, pf_id):
    if(web_handler.basic_page_verify(session["id"]) == True):
        query = """DELETE FROM whitelist WHERE id = {}"""
        db_handler.update_db(query.format(id))
        return redirect("/instance_whitelist/" + pf_id)
    else:
        web_handler.user_auth_error_page()

#INSTANCE LOGS PAGE
@instance_pages_blueprint.route("/instance_logs/<id>-<offset>", methods=["GET", "POST"])
def instance_logs(id, offset):
    if(web_handler.basic_page_verify(session["id"]) == True):
        form = preset_forms.PreviousNext()
        if form.validate_on_submit():
            if form.previous_page.data:
                new_offset = int(offset) - 50
                if(new_offset > -1):
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
        results = db_handler.query_db(query.format(id, offset, "50"))
        final_results = []
        for row in results:
            new_row = []
            count = 1
            for item in row:
                if count == 9 or count == 11:
                    item = (f'<a href="/ip_details/{str(item)}">{str(item)}</a>')
                else:
                    item = str(item)
                new_row = new_row + [item]
                count = count + 1
            final_results = final_results + [new_row]
        headings = ["Time", "Rule Number", "Interface", "Reason", "Act", "Direction", "IP Version", "Protocol", "Source IP", "Source Port", "Destination IP", "Destination Port", "Daily ML Check", "Weekly ML Check", "Combined ML Check"]
        return render_template("table_button-next_back.html", heading="Log Results", table_headings=headings, data_collection=final_results, form=form)
    else:
        web_handler.user_auth_error_page()

#INSTANCE DETAILS PAGE
@instance_pages_blueprint.route("/instance_details/<id>", methods=["GET", "POST"])
def instance_details(id):
    if(web_handler.basic_page_verify(session["id"]) == True):
        form = preset_forms.InstanceDetailsForm()
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
        ipsec_query = """SELECT 
remote_connection, 
pfsense_instances.pfsense_name, 
local_ranges, 
remote_ranges 
FROM pfsense_ipsec_connections 
LEFT JOIN pfsense_instance_interfaces ON pfsense_ipsec_connections.remote_connection = pfsense_instance_interfaces.ipv4_address 
LEFT JOIN pfsense_instances ON pfsense_instance_interfaces.pfsense_instance = pfsense_instances.id
WHERE pfsense_ipsec_connections.pfsense_instance = {}"""
        instance_results = db_handler.query_db(instance_details_query.format(str(id)))[0]
        pre_amble_tup = ["Name", "Hostname", "Reachable IP", "Instance User", "Instance Password", "SSH Port", "FreeBSD Version", "PfSense Release"]
        final_tup = []
        max_count = len(pre_amble_tup)
        element_count = 0
        buttons_tup = [["/instance_rules/" + str(id), "Firewall Rules"], ["/instance_logs/" + str(id) + "-0", "Instance Logs"], ["/instance_openvpn/" + str(id) + "-0", "Instance OpenVPN Log"], ["/instance_users/" + str(id) + "-0", "Instance Users"], ["/instance_whitelist/" + str(id), "Instance Whitelist"], ["/delete_instance/" + str(id), "Delete Instance"]]
        while(element_count < max_count):
            result_element = str(instance_results[element_count])
            item = [[pre_amble_tup[element_count], result_element]]
            final_tup = final_tup + item
            element_count = element_count + 1
        instance_int = db_handler.query_db(interfaces_query.format(str(id)))
        headings_int = ["Interface Name", "Interface", "MAC Address", "IPv6", "IPv4", "Interface Type"]
        ipsec_results = db_handler.query_db(ipsec_query.format(str(id)))
        results_ipsec = []
        for row in ipsec_results:
            new_row = []
            for item in row:
                if(item == None):
                    new_item = "Not in Database"
                else:
                    new_item = item
                new_row = new_row + [new_item]
            results_ipsec = results_ipsec + [new_row]
        ipsec_headings = ["Remote Connection", "Remote Instance", "Local Ranges", "Remote Ranges"]
        if form.validate_on_submit():
            fields_tup = [["pfsense_name", form.instance_name.data, 1], ["hostname", form.hostname.data, 1], ["reachable_ip", form.reachable_ip.data, 1], ["instance_user", form.instance_user.data, 1], ["instance_password", form.instance_password.data, 1], ["ssh_port", form.ssh_port.data, 1], ["address", form.address.data, 3], ["private_key", form.private_key.data, 1]]
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
                        long, lat = location_handler.long_lat_calc(item[1])
                        query = """UPDATE pfsense_instances SET longtitude = {}, latitude = {} WHERE id = {}"""
                        db_handler.update_db(query.format(str(long), str(lat), str(id)))
                    clause = clause + item[0] + " = " + element + ", "
            clause = clause[:-2]
            update_query = """UPDATE pfsense_instances SET {} WHERE id = {}"""
            db_handler.update_db(update_query.format(clause, str(id)))
            return (redirect('/instance_details/' + str(id)))
        return render_template("instance_details.html", heading="Instance Details", headings_int=headings_int, collection_int=instance_int, headings_ipsec=ipsec_headings, collection_ipsec=results_ipsec, messages=final_tup, buttons=buttons_tup, form=form)
    else:
      web_handler.user_auth_error_page()

#INSTANCE FIREWALL RULES PAGE
@instance_pages_blueprint.route("/instance_rules/<id>", methods=["GET", "POST"])
def instance_rules(id):
    if(web_handler.basic_page_verify(session["id"]) == True):
        query = """SELECT
rule_number,
rule_description
FROM pfsense_firewall_rules
WHERE pfsense_instance = {}
ORDER BY rule_number ASC"""
        results = db_handler.query_db(query.format(str(id)))
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
        web_handler.user_auth_error_page()

#INSTANCE LOGS REPORT CONFIGURATION
@instance_pages_blueprint.route("/instance_log_report_config", methods=["GET", "POST"])
def instance_log_report_config():
    if(web_handler.basic_page_verify(session["id"]) == True):
        form = preset_forms.LogsReportConfig()
        query = """SELECT combined_reports_recievers.id, 
reciever_name, 
receiver_address, 
instance_id, 
pfsense_instances.pfsense_name 
FROM combined_reports_recievers 
LEFT JOIN pfsense_instances ON combined_reports_recievers.instance_id = pfsense_instances.id"""
        insert_reciever = """INSERT INTO combined_reports_recievers (`instance_id`, `reciever_name`, `receiver_address`) VALUES ({}, "{}", "{}");"""
        raw_results = db_handler.query_db(query)
        final_results = []
        for row in raw_results:
            data_tup = []
            for item in row:
                if(item == None):
                    new_item = "NA"
                else:
                    new_item = item
                data_tup = data_tup + [new_item]
            new_row = [data_tup[1], data_tup[2], data_tup[4], "/instance_log_report_reciever_delete/" + str(data_tup[0]) + ";Remove Reciever Entry"]
            final_results = final_results + [new_row]
        headings = ["Name", "Email", "Instance Name"]
        if form.validate_on_submit():
            instance = form.instance.data
            reciever_name = form.reciever_name.data
            reciever_address = form.reciever_address.data
            db_handler.update_db(insert_reciever.format(instance, reciever_name, reciever_address))
            return(redirect("/instance_log_report_config"))
        return render_template("table_form.html", heading="Combined Log Errors Report Configuration", headings=headings, collection=final_results, form=form)
    else:
        web_handler.user_auth_error_page()

#LOGS REPORT RECIEVER DELETE
@instance_pages_blueprint.route("/instance_log_report_reciever_delete/<id>", methods=["GET", "POST"])
def instance_log_report_reciever_delete(id):
    if(web_handler.basic_page_verify(session["id"]) == True):
        query = """DELETE FROM combined_reports_recievers WHERE id = {}"""
        db_handler.update_db(query.format(id))
        return(redirect("/instance_log_report_config"))
    else:
        web_handler.user_auth_error_page()

#ADD NEW INSTANCE TO SYSTEM
@instance_pages_blueprint.route("/add_instance", methods=["GET", "POST"])
def add_instance():
    if(web_handler.basic_page_verify(session["id"]) == True):
        form = preset_forms.NewInstanceForm()
        if form.validate_on_submit():
            insert_query = """INSERT INTO `Dashboard_DB`.`pfsense_instances` (`pfsense_name`, `hostname`, `reachable_ip`, `instance_user`, `instance_password`, `ssh_port`) VALUES ("{}", "{}", "{}", "{}", "{}", {});"""
            db_handler.update_db(insert_query.format(form.instance_name.data, form.hostname.data, form.reachable_ip.data, form.instance_user.data, form.instance_password.data, str(form.ssh_port.data)))
            select_query = """SELECT id FROM pfsense_instances WHERE
pfsense_name = "{}" 
AND hostname = "{}" 
AND reachable_ip = "{}" 
AND instance_user = "{}" 
AND instance_password = "{}" 
AND ssh_port = {}"""
            id = db_handler.query_db(select_query.format(form.instance_name.data, form.hostname.data, form.reachable_ip.data, form.instance_user.data, form.instance_password.data, str(form.ssh_port.data)))[0][0]
            return (redirect('/instance_details/' + str(id)))
        return render_template("index_form.html", heading="Add New Instance", form=form)
    else:
        web_handler.user_auth_error_page()

#INSTANCE DELETE
@instance_pages_blueprint.route("/delete_instance/<id>", methods=["GET", "POST"])
def delete_instance(id):
    if(web_handler.basic_page_verify(session["id"]) == True):
        deletion_queries = ["DELETE FROM combined_reports_recievers WHERE instance_id = {}",
"DELETE FROM open_vpn_access_log WHERE pfsense_instance = {}",
"DELETE FROM pfsense_firewall_rules WHERE pfsense_instance = {}",
"DELETE FROM pfsense_instance_interfaces WHERE pfsense_instance = {}",
"DELETE FROM pfsense_instance_users WHERE pfsense_instance = {}",
"DELETE FROM pfsense_ipsec_connections WHERE pfsense_instance = {}",
"DELETE FROM pfsense_openvpn_logs WHERE pfsense_instance = {}",
"DELETE FROM pfsense_instances WHERE id = {}",
"DELETE FROM pfsense_logs WHERE pfsense_instance = {}"]
        for query in deletion_queries:
            db_handler.update_db(query.format(str(id)))
        return(redirect("/home"))
    else:
        web_handler.user_auth_error_page()
