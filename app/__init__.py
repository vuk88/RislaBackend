from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_mail import Mail
from config.db_config import DB_KURAC
from config.mail_config import MAIL_SERVER, MAIL_PORT, MAIL_USE_TLS, MAIL_USERNAME, MAIL_PASSWORD, MAIL_USE_SSL
import secrets 
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS 
from datetime import timedelta

app = Flask(__name__)
CORS(app) 
app.config['SQLALCHEMY_DATABASE_URI'] = 'YOUR_DB_URI'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['JWT_SECRET_KEY'] = 'YOUR_SECRET_KEY'

#Mail Server Config 
app.config['MAIL_SERVER'] = 'MAIL_SERVER'
app.config['MAIL_PORT'] = 'MAIL_PORT'
app.config['MAIL_USE_TLS'] = 'MAIL_USE_TLS'
app.config['MAIL_USERNAME'] = 'MAIL_USERNAME'
app.config['MAIL_PASSWORD'] = 'MAIL_PASSWORD'
app.config['MAIL_DEBUG'] = True
app.config['MAIL_USE_SSL'] = 'MAIL_USE_SSL'

#Login Config 
app.config['SECRET_KEY'] = 'YOUR_SECRET'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['ENABLE_MAGIC_LINK'] = False 


#Linkedin Config 
app.config['ENABLE_LN_AUTH'] = True
app.config['LNCLIENT_ID'] = 'YOUR_APP_ID'
app.config['LNCLIENT_SECRET'] = 'YOUR_APP_SECRET'
app.config['LNCALLBACK_URL'] = 'YOUR_CALLBACK_URL '


#AI Config


jwt = JWTManager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
mail = Mail(app)

from app.routes import register_routes
register_routes(app, db)


app.debug = True