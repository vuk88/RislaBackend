from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from app import db



class CommentHistory(db.Model):
    __tablename__ = 'comments_history'

    comment_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    comment_type = db.Column(db.String(64), nullable=False)
    primary_context = db.Column(db.Text, nullable=False)
    secondary_context = db.Column(db.Text)
    author_username = db.Column(db.String(64), nullable=False)
    author_title = db.Column(db.String(64))
    generated_comment = db.Column(db.Text, nullable=False)
    comment_settings = db.Column(db.Text)  # consider using db.JSON if your database supports it
    created_at = db.Column(db.DateTime, default=datetime.utcnow)