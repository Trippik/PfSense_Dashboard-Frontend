from flask_wtf import FlaskForm
from wtforms import StringField, DecimalField, SubmitField, PasswordField, HiddenField, DateField, IntegerField, SelectField, RadioField, TextAreaField
from wtforms.validators import DataRequired, Optional

from frontend.lib import db_handler

database = db_handler.DB()

#Form for login page
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

#Form for buttons on homepage
class HomeForm1(FlaskForm):
    client_search = SubmitField("Search Clients")
    new_client = SubmitField("Create New Client")

#Form for Instance Details Fields
class InstanceDetailsForm(FlaskForm):
    instance_name = StringField("Name", validators=[Optional()])
    hostname = StringField("Hostname", validators=[Optional()])
    reachable_ip = StringField("Reachable IP", validators=[Optional()])
    instance_user = StringField("Instance User", validators=[Optional()])
    instance_password = StringField("Instance Password", validators=[Optional()])
    ssh_port = IntegerField("SSH Port", validators=[Optional()])
    address = StringField("Address", validators=[Optional()])
    private_key = TextAreaField('OpenSSH Private Key', render_kw={"rows": 15, "cols": 11})
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

#Form for OpenVPN report config page
class OpenVPNReportConfig(FlaskForm):
    reciever_name = StringField("Name", validators=[DataRequired()])
    reciever_address = StringField("Email", validators=[DataRequired()])
    submit = SubmitField("Add Reciever", validators=[Optional()])

#Form for logs report config page
class LogsReportConfig(FlaskForm):
    reciever_name = StringField("Name", validators=[DataRequired()])
    reciever_address = StringField("Email", validators=[DataRequired()])
    instance = SelectField("PfSense Instance", choices=database.return_client_options(), validators=[DataRequired()])
    submit = SubmitField("Add Reciever", validators=[Optional()])

#Form for adding new dashboard users
class DashboardUsers(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Add New User", validators=[Optional()])

#Form for whitelist
class WhitelistForm(FlaskForm):
    ip = StringField("IP Address", validators=[DataRequired()])
    port = IntegerField("Destination Port", validators=[DataRequired()])
    submit = SubmitField("Add Entry", validators=[Optional()])

#Form for OpenVPN acitivity search page
class OVPNActivityForm(FlaskForm):
    user_name = StringField("OpenVPN Username", validators=[Optional()])
    instance = SelectField("PfSense Instance", choices=database.return_client_options(), validators=[DataRequired()])
    submit = SubmitField("Search", validators=[Optional()])