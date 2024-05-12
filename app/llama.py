import asyncio
from ollama import AsyncClient

LLAMA_HOST = 'lama.betaeuro.com'

async def chat():
  message = {'role': 'user', 'content': 'Why is the sky blue?'}
  async for part in await AsyncClient(host=LLAMA_HOST).chat(model='llama2', messages=[message], stream=True):
    print(part['message']['content'], end='', flush=True)

asyncio.run(chat())