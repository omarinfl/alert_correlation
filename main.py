import os
from src.retrieval.embedders import SentenceTransformerEmbedder
from src.retrieval.store import ElasticSearchVectorStore
from src.agent.agent import SOCAgent
from src.agent.data_access import CSVAlertData
from src.agent.config import AgentConfig
from langchain_google_genai import ChatGoogleGenerativeAI
from dotenv import load_dotenv
import pandas as pd
import json

load_dotenv()

API_KEY = os.getenv('GEMINI_TOKEN')


def main():
    config = AgentConfig(
        use_context_window=False,
        context_window_size=10,
        generate_report=False,
        report_dir='reports',
        mitre_top_k=5
    )

    alert_data = CSVAlertData(csv_path='data/mini_dataset_parsed.csv')

    llm = ChatGoogleGenerativeAI(model='gemini-3.1-flash-lite', api_key=API_KEY, temperature=0.2)
    # llm = ChatGoogleGenerativeAI(model='gemma-4-31b-it', api_key=API_KEY, temperature=0.2)

    embedder = SentenceTransformerEmbedder()
    cve_store = ElasticSearchVectorStore(index_name='cve_index')
    mitre_store = ElasticSearchVectorStore(index_name='mitre_attack')

    agent = SOCAgent(config, llm, alert_data, embedder, mitre_store, cve_store)
    
    # Simular procesamiento de una alerta
    df = pd.read_csv('data/mini_dataset_parsed.csv', parse_dates=['timestamp'])
    sample_alert = json.loads(df.iloc[8]['alert'])
    agent.process_alert(sample_alert)


if __name__ == "__main__":
    main()
