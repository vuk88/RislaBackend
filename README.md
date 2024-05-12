Hi, this is the Flask backend I created for a friend's app! The app focuses on generating content and comments for social networks. 
It does this by retrieving prompts from the ChatGPT API, using users' own tokens for authentication. 
Additionally, the app can also utilize a self-hosted Llama3 model for prompt generation.
This setup allows for flexible and customizable content generation, tailored to the needs of each user. 
Feel free to explore and use the app for your social media needs!



Routes and app config is in the init file
*NOTE Llama3 API endpoint is defined in llama.py 

ServerSettings model is is for /generate rout weather to check if AI model is in failover mode or not
