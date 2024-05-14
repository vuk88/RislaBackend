import os
from openai import OpenAI
from .models.user import User

def analyze_image(text, image_url, username):
    # user from the database using the username
    user = User.query.filter_by(username=username).first()
    if not user:
        return {"error": f"No user found in the database with username {username}"}

    if not user.openaitoken:
        return {"error": f"OpenAI token is not set for the user {user.username}"}

    
    
    # OpenaAI client 
    client = OpenAI(api_key=user.openaitoken)
    
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": text},
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": image_url,
                        },
                    },
                ],
            }
        ],
        max_tokens=300,
    )

    first_choice_content = response.choices[0].message.content

    
    return response