from flask import Flask
from app.config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_uuid import FlaskUUID
from flask_mail import Mail
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

app = Flask(__name__, static_url_path='/static')

admin = Admin(app)
app.config.from_object(Config)
app.config['DEBUG'] = True
app.config['TESTING'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['MAIL_SERVER'] = 'smtp.mailgun.org'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = False
# app.config['MAIL_DEBUG'] = True
app.config['MAIL_USERNAME'] = 'postmaster@sandbox00de28c9e8204f41a1093b780c694690.mailgun.org'
app.config['MAIL_PASSWORD'] = 'b481ba4e98d58d1589f9ec9a220b1b2d-ee13fadb-990744f5'
app.config['MAIL_DEFAULT_SENDER'] = 'postmaster@sandbox00de28c9e8204f41a1093b780c694690.mailgun.org'
app.config['MAIL_MAX_EMAILS'] = 100
# app.config['MAIL_SUPPRESS_SEND'] = False
app.config['MAIL_ASCII_ATTACHMENTS'] = False


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
flask_uuid = FlaskUUID()
flask_uuid.init_app(app)
mail = Mail(app)



from app import routes
from app import auth
