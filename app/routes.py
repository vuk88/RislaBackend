from flask import request, jsonify, session, url_for, current_app
from sqlalchemy import text  # import the text function
from werkzeug.security import generate_password_hash
from app.models import User, CommentHistory
import secrets
from sqlalchemy.exc import IntegrityError
from flask_login import login_user, current_user, LoginManager, logout_user
from datetime import timedelta, datetime
from flask_jwt_extended import create_access_token,jwt_required, get_jwt_identity
from app import mail, app
from flask_mail import Message
from itsdangerous import SignatureExpired, URLSafeTimedSerializer, BadSignature, BadTimeSignature
from . import db
from .openai import generate_text
import openai
import requests 
from .models import ServerSettings
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
#from .llama import chat

limiter = Limiter(app=app, key_func=get_remote_address)

login_manager = LoginManager()


# Root route - test for mysql connection

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def register_routes(app, db):
    login_manager.init_app(app)
    @app.route('/')
    def index():
        try:
            with db.engine.connect() as connection:
                connection.execute(text('SELECT 1'))  # use the text function here
            return jsonify({'message': 'MySQL connection successful!'})
        except Exception as e:
            return jsonify({'message': f'MySQL connection error: {str(e)}'})
        
          
    from flask import current_app



# Route to confirm email token - stacked on top due url_for in register route 

@app.route('/confirm_email/<token>', methods=['GET'])
def confirm_token(token):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        return jsonify({'message': 'The confirmation link is expired.'}), 400
    except (BadSignature, BadTimeSignature):
        return jsonify({'message': 'Invalid token.'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'Invalid user.'}), 400

    user.confirmed = True
    db.session.commit()

    return jsonify({'message': 'Email confirmed.'}), 200



# Registration route 

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('email').lower()
    email = data.get('email')
    password = data.get('password')

    # Check if the username, email, and password
    if not username or not email or not password:
        return jsonify({'message': 'Missing username, email, or password'}), 400

    # Generate API key
    api_key = secrets.token_hex(16)

    # Create a new User
    new_user = User(username=username, email=email, api_key=api_key)
    new_user.set_password(password)  # Use the set_password method to set the password

    # New User instance to the session and commit
    try:
        with current_app.app_context():
            db.session.add(new_user)
            db.session.commit()
    except IntegrityError:
        db.session.rollback()
        existing_user_email = User.query.filter_by(email=email).first()
        existing_user_username = User.query.filter_by(username=username).first()
        if existing_user_email and existing_user_email.linkedinlogin:
            return jsonify({'message': 'User registered through LinkedIn'}), 200
        elif existing_user_username:
               return jsonify({'message': 'Username already in Use '}), 400        
        else:
            return jsonify({'message': 'Email already in use'}), 400

    # Validation token
    with current_app.app_context():
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        emailtoken = s.dumps(email, salt='email-confirm')

    # Coconfirmation link

    confirm_url = 'YOUR_URL_HERE' + emailtoken

    # Email message
    msg = Message(sender='YOUR_SENDER_HERE', subject="Confirm Email Address", recipients=[email])
    msg.body = f'Please confirm your email by clicking on the following link: {confirm_url}'

  
    mail.send(msg)

    return jsonify({'message': 'User registered successfully. A confirmation email has been sent to your email address.'}), 200
        
        
# Route for regular login    
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username').lower()
    password = data.get('password')

    # Check if the username and password fields are provided
    if not username or not password:
        return jsonify({'message': 'Missing username or password'}), 400

    # Check user from the database
    user = User.query.filter_by(username=username).first()

    # User was found and the password is correct
    if user and user.check_password(password):
        if not user.confirmed:
            return jsonify({'message': 'Please confirm your email address before logging in'}), 400

        # Create the access token
        access_token = create_access_token(identity=username)
        user.last_login = datetime.utcnow()
        db.session.commit()
        return jsonify({
            'message': 'Logged in successfully',
            'access_token': access_token
        }), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401


# Route for generating AI prompt 

@app.route('/generate', methods=['POST'])
@jwt_required()
def generate():
    # Check if Server is in Fialover mode 
    server_settings = ServerSettings.query.first()
    model_in_use = server_settings.modelinuse if server_settings else 'openai'

    username = get_jwt_identity()  # Username from the JWT token
    user = User.query.filter_by(username=username).first()  # User from the database

    if not user:
        return jsonify({'message': 'User not found'}), 404

    if model_in_use == 'openai':
        prompt = request.json.get('prompt')
        if not prompt:
            return jsonify({'message': 'Prompt is required'}), 400

        # Use the user's OpenAI API token
        if user.openaitoken:
            openai.api_key = user.openaitoken
        else:
            return jsonify({'message': 'OpenAI API key not set for this user'}), 400

        # Generate the text
        generated_text = generate_text(username, prompt)

        return jsonify({'generated_text': generated_text}), 200
    elif model_in_use == 'llama3':
        message_content = request.json.get('message')
        response = asyncio.run(chat(message_content))
        return jsonify(message=response), 200
    else:
        return jsonify({'message': 'Invalid model in use'}), 400



# Route for setting user openaikey in DB 
@app.route('/update_openai_token', methods=['POST'])
@jwt_required()
def update_openai_token():
    username = get_jwt_identity()  # username from the JWT token
    api_key = request.json.get('api_key', None)  # API key from the request
    new_openai_token = request.json.get('openai_token', None)  # OpenAI token from the request

    user = User.query.filter_by(username=username).first()  # User from the database

    # if the user exists and the API key is correct
    if user and user.api_key == api_key:
        user.openaitoken = new_openai_token  # Update the OpenAI token
        db.session.commit()  # Commit the changes
        return jsonify({'message': 'OpenAI token updated successfully'}), 200
    else:
        return jsonify({'message': 'Invalid username or API key'}), 401



# Route for retrieving aikeyfrom db 
@app.route('/read_openai_token', methods=['POST'])
@jwt_required()
def read_openai_token():
    username = get_jwt_identity()  # Username from the JWT token
    api_key = request.json.get('api_key', None)  # API key from the request parameters

    if not api_key:
        return jsonify({'message': 'API key is required'}), 400

    user = User.query.filter_by(username=username).first()  # User from the database

    # if the user exists and the API key is correct
    if user and user.api_key == api_key:
        return jsonify({'openai_token': user.openaitoken}), 200
    else:
        return jsonify({'message': 'Invalid username or API key'}), 401   



# Route for password reset 
@app.route('/reset_password', methods=['POST'])
@limiter.limit("5 per hour")
def reset_password():
    email = request.json.get('email')
    user = User.query.filter_by(email=email).first()
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    if user:
        if not user.confirmed:
            return jsonify({'message': 'Email not confirmed.'}), 400
        if user.password is None:
            return jsonify({'message': 'User not registered.'}), 400
        token = s.dumps(email, salt='password-reset-salt')
        msg = Message('Password Reset Request', sender='YOUR_SENDER', recipients=[email])
        link = url_for('reset_password_token', token=token, _external=True)
        msg.body = 'Follow this link to reset your password: {}'.format(link)
        mail.send(msg)
        return jsonify({'message': 'A password reset email has been sent.'}), 200
    else:
        return jsonify({'message': 'Email not found.'}), 400         


# Reset password token route 
@app.route('/reset_password/<token>', methods=['POST'])
def reset_password_token(token):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        return jsonify({'message': 'The password reset link is invalid or has expired.'}), 400
    user = User.query.filter_by(email=email).first()
    new_password = request.json.get('password')
    user.set_password(new_password) 
    db.session.commit()
    return jsonify({'message': 'Your password has been updated.'}), 200        


    
# Route for session logout 
@app.route('/logout', methods=['POST'])
def logout():
    logout_user()
    session.clear()
    return jsonify({'message': 'You have been logged out.'}), 200


# Route to force confirm emial address - for Admin Panel 
@app.route('/force_confirm_email', methods=['POST'])
def force_confirm_email():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    
    user = User.query.filter_by(username=username).first()

    # User was found and the password is correct
    if user and user.check_password(password):
    
        user.confirmed = 1
        db.session.commit()

        return jsonify({
            'message': 'User email has been forcefully confirmed'
        }), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401


    


# Magic auth funcitionality - must be set via init config 
@app.route('/magic_auth_link', methods=['POST'])
def magic_auth_link():
    if not app.config['ENABLE_MAGIC_LINK']:
        return jsonify({'message': 'Magic link functionality is disabled'}), 403

    data = request.get_json()
    username_or_email = data.get('username_or_email')

    # Fetch the user from the database
    user = User.query.filter((User.username==username_or_email) | (User.email==username_or_email)).first()

    if not user:
        return jsonify({'message': 'Invalid username or email'}), 401

    # Generate a magic auth token
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    token = s.dumps(user.username, salt='magic-auth')

    # Create a magic auth link
    magic_auth_url = url_for('magic_auth', token=token, _external=True)

    # Send the magic auth link to the user's email
    msg = Message('Magic Auth Link', sender='YOUR_SENDER_HERE', recipients=[user.email])
    msg.body = f'Here is your magic auth link: {magic_auth_url}'
    mail.send(msg)

    return jsonify({
        'message': 'Magic auth link sent to email successfully'
    }), 200

# Magic auth token route 
@app.route('/magic_auth/<token>', methods=['GET'])
def magic_auth(token):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

    try:
        # Verify 
        username = s.loads(token, salt='magic-auth', max_age=300)
    except SignatureExpired:
        return jsonify({'message': 'The magic auth link has expired'}), 401

   
    user = User.query.filter_by(username=username).first()


    access_token = create_access_token(identity=username)

    return jsonify({
        'message': 'Logged in successfully',
        'access_token': access_token
    }), 200


# Route for login with linkedin callback  - must be set via init config 
@app.route('/lncallback',  methods=['GET'])
def lncallback():
    if not app.config['ENABLE_LN_AUTH']:
        return jsonify({'message': 'Linkedin auth functionality is disabled'}), 403
    
    oauth_token = request.args.get('code')

    if oauth_token is None:
        return jsonify({'message': 'No OAuth token provided'}), 400

    # LinkedIn OAuth endpoint must be configured via init config 
    params = {
        'grant_type': 'authorization_code',
        'code': oauth_token,
        'client_id': current_app.config['LNCLIENT_ID'],
        'client_secret': current_app.config['LNCLIENT_SECRET'],
        'redirect_uri': current_app.config['LNCALLBACK_URL']
    }

    
    response = requests.post('https://www.linkedin.com/oauth/v2/accessToken', data=params, headers={'Content-Type': 'application/x-www-form-urlencoded'})

    if response.status_code != 200:
        return jsonify({'message': 'Failed to get access token from LinkedIn', 'error': response.text}), 400

    # Extract the access token, expires in, and scope from the response
    access_token = response.json().get('access_token')
    expires_in = response.json().get('expires_in')
    scope = response.json().get('scope')

    
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get('https://api.linkedin.com/v2/userinfo', headers=headers)

    if response.status_code != 200:
        return jsonify({'message': 'Failed to get member handles from LinkedIn', 'error': response.text}), 400

    # Extract the email address 
    user_info = response.json()
    email_address = user_info.get('email')
    given_name = user_info.get('given_name')
    family_name = user_info.get('family_name')
    ln_picture = user_info.get('picture')
    

    user = User.query.filter_by(email=email_address).first()

    if user:
        # User exists, update the user info
        user.given_name = given_name
        user.family_name = family_name
        user.ln_picture = ln_picture 
        user.last_login = datetime.utcnow()      
    else:
        # User does not exist, create a new user
        user = User(email=email_address, linkedinlogin=True, username=email_address, given_name=given_name, family_name=family_name, ln_picture=ln_picture)
        db.session.add(user)

    
    db.session.commit()
    
    username = user.username

    access_token = create_access_token(identity=username)
    

    
    redirect_url = f"https://ralfy.ai?access_token={access_token}"

    # Redirect URL
    return redirect(redirect_url, code=302)




# Route for resending confirmation email
@app.route('/resend_confirmation', methods=['POST'])
def resend_confirmation():
    data = request.get_json()
    email = data.get('email')

    
    if not email:
        return jsonify({'message': 'Missing email'}), 400

    
    user = User.query.filter_by(email=email).first()

    
    if user is None:
        return jsonify({'message': 'Invalid email'}), 400

    
    with current_app.app_context():
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        emailtoken = s.dumps(email, salt='email-confirm')

    
    confirm_url = 'YOUR_URL_HERE' + emailtoken

    
    msg = Message(sender='YOUR_SENDER_HERE', subject="Confirm Email Address", recipients=[email])
    msg.body = f'Please confirm your email by clicking on the following link: {confirm_url}'

    # Send
    mail.send(msg)

    return jsonify({'message': 'A new confirmation email has been sent to your email address.'}), 200    


# Route to retrieve user info - all except password and api token 
@app.route('/getuserinfo', methods=['GET'])
@jwt_required()
def get_user_info():
    current_username = get_jwt_identity()
    print(f"Current username: {current_username}")
    user = User.query.filter_by(username=current_username).first()
    print(f"User query result: {user}")
    if user:
        user_info = {column.name: getattr(user, column.name) for column in User.__table__.columns if column.name not in ['hashed_password', 'api_key']}
        return jsonify(user_info), 200
    else:
        return jsonify({"msg": "User not found"}), 404  

@app.route('/analyze-image', methods=['POST'])
@jwt_required()
def analyze_image_route():
    data = request.get_json()
    prompt = data.get('prompt')
    image_url = data.get('image_url')
    if not prompt or not image_url:
        return jsonify({'message': 'Both prompt and image_url are required'}), 400

    # Get the username from the JWT token
    username = get_jwt_identity()

    response = analyze_image(prompt, image_url, username)
    if 'error' in response:
        return jsonify(response), 400

    return jsonify({'response': response.choices[0].message.content}), 200        