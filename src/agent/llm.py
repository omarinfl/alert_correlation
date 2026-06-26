from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI
from dotenv import load_dotenv
import os

load_dotenv()

API_KEY = os.getenv('GEMINI_TOKEN')

gemini = ChatGoogleGenerativeAI(model='gemini-3.1-flash-lite', api_key=API_KEY, temperature=0.2, seed=42)

gemma = ChatOpenAI(
        model=os.getenv('GEMMA_NAME'),
        api_key='EMPTY',
        temperature=0.0,
        seed=42,
        base_url=os.getenv('GEMMA_ENDPOINT'),
)

gpt = ChatOpenAI(
        model=os.getenv('GPT_NAME'),
        api_key='EMPTY',
        temperature=0.0,
        seed=42,
        base_url=os.getenv('GPT_ENDPOINT'),
)