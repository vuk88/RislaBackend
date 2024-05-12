
# Small Beckend python 
Hi, this is the Flask backend I created for a friend's app! The app focuses on generating content and comments for social networks. 
It does this by retrieving prompts from the ChatGPT API, using users' own tokens for authentication. 
Additionally, the app can also utilize a self-hosted Llama3 model for prompt generation.
This setup allows for flexible and customizable content generation, tailored to the needs of each user. 
Feel free to explore and use the app for your social media needs!


Routes and app config is in the init file
**NOTE Llama3 API endpoint is defined in llama.py**

ServerSettings model is is for /generate rout weather to check if AI model is in failover mode or not

**App Routes**
1. /: Tests for a MySQL connection.
2. /confirm_email/<token>: Confirms the email token.
3. /register: Registers a new user.
4. /login: Authenticates a user.
5. /generate: Generates an AI prompt. Requires JWT authentication.
6. /update_openai_token: Sets a users OpenAI key in the database. Requires JWT authentication.
7. /read_openai_token: Retrieves the OpenAI key from the database. Requires JWT authentication.
8. /reset_password: Resets the password. Rate-limited to 5 requests per hour.
9. /reset_password/<token>: Resets the password using a token.
10. /logout: Logs out the session.
11. /force_confirm_email: Force confirms the email address. Intended for use in the Admin Panel.
12. /magic_auth_link: Generates a magic authentication link. Must be set via the init config.
13. /magic_auth/<token>: Authenticates a user using a magic authentication token.
14. /lncallback: Login with LinkedIn callback. Must be set via the init config.
15. /resend_confirmation: Resends the confirmation email.
16. /getuserinfo: Retrieves user info, excluding the password and API token.
