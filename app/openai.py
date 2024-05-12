import os 
import openai
from openai import OpenAI
from .models import User


def generate_text(username, prompt, max_tokens=350):
    
    user = User.query.filter_by(username=username).first()

    # If the user exists and has an OpenAI API key, use it
    if user and user.openaitoken:
        openai.api_key = user.openaitoken
    else:
        print(f'User not found or OpenAI API key not set for user {username}')  # Debug print
        return 'User not found or OpenAI API key not set'

    client = OpenAI(api_key=openai.api_key)

    try:
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            model="gpt-3.5-turbo",
            max_tokens=max_tokens
        )
    except Exception as e:
        print(f'Exception when calling OpenAI API: {e}')  # Debug print
        raise

    return chat_completion.choices[0].message.content  