from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from app import db
from passlib.hash import scrypt



class User(db.Model):
    __tablename__ = 'users'
    
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    hashed_password = db.Column(db.String(128))  # This should be hashed_password, not password
    api_key = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    confirmed = db.Column(db.Boolean, default=False)
    openaitoken = db.Column(db.String(128)) 
    aimodel = db.Column(db.String(128))
    given_name = db.Column(db.String(128))
    family_name = db.Column(db.String(128)) 
    ln_picture  = db.Column(db.String(512))
    linkedinlogin = db.Column(db.Boolean, default=False)
    subscription_model = db.Column(db.String(128))
    onboarded= db.Column(db.String(128))
    

    def set_password(self, password):
        self.hashed_password = scrypt.hash(password)

    def check_password(self, password):
        return scrypt.verify(password, self.hashed_password)
    
    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.user_id)
    
    @classmethod
    def get_email(cls, email):
        user = cls.query.filter_by(email=email).first()
        if user:
            return user.email
        else:
            return None