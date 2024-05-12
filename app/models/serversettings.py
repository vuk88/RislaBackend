from flask_sqlalchemy import SQLAlchemy
from app import db

class ServerSettings(db.Model):
    __tablename__ = 'server_settings'

    id = db.Column(db.Integer, primary_key=True)
    modelinuse = db.Column(db.String(128))