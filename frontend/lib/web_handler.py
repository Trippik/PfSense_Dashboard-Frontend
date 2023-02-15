from frontend.lib import db_handler
from flask import render_template, session

def basic_page_verify(usr_id):
    query = 'SELECT COUNT(*) FROM dashboard_user WHERE id = {}'
    query = query.format(str(session["id"]))
    results = db_handler.query_db(query)
    for row in results:
        state = row[0]
    if(state != "0"):
        return(True)
    else:
        return(False)

def user_auth_error_page():
    return render_template("index.html", heading="Oops!", messages="It looks like you have ended up in the wrong place.")