from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI
from dotenv import load_dotenv
import os

load_dotenv()

API_KEY = os.getenv('GEMINI_TOKEN')

gemini = ChatGoogleGenerativeAI(model='gemini-3.1-flash-lite', api_key=API_KEY, temperature=0.2)

gemma = ChatOpenAI(
    model="gemma-4-26b-a4b",
    api_key='EMPTY',
    # streaming=True,
    # stream_usage=True,
    temperature=0.2,
    # max_tokens=None,
    # timeout=12000,
    # reasoning_effort="low",
    # max_retries=3,
    base_url="http://10.0.152.198:8003/v1",
    # http_client=httpx.Client(timeout=httpx.Timeout(connect=60.0, read=600.0, write=60.0, pool=60.0))
)

gpt = ChatOpenAI(
    model="gpt-oss-20b",
    api_key='EMPTY',
    # streaming=True,
    # stream_usage=True,
    temperature=0.2,
    # max_tokens=None,
    # timeout=12000,
    # reasoning_effort="low",
    # max_retries=3,
    base_url="http://10.0.152.198:8001/v1",
    # http_client=httpx.Client(timeout=httpx.Timeout(connect=60.0, read=600.0, write=60.0, pool=60.0))
)