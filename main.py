import os
from src.retrieval.embedders import SentenceTransformerEmbedder
from src.retrieval.store import ElasticSearchVectorStore
from src.agent.agent import SOCAgent
from src.agent.data_access import CSVAlertData
from src.agent.config import AgentConfig
from src.evaluation.data_saver import CSVDataSaver
from src.agent.token_tracker import UniversalTokenTracker
from src.evaluation.evaluator import EvaluationRunner
from langchain_google_genai import ChatGoogleGenerativeAI
from dotenv import load_dotenv
import pandas as pd
import json
from langchain_openai import ChatOpenAI
import httpx


load_dotenv()

API_KEY = os.getenv('GEMINI_TOKEN')


def main():
    config = AgentConfig(
        use_context_window=False,
        context_window_size=10,
        generate_report=True,
        report_dir='reports',
        mitre_top_k=5
    )

    alert_data = CSVAlertData(csv_path='data/mini_dataset_parsed.csv')

    # llm = ChatGoogleGenerativeAI(model='gemini-3.1-flash-lite', api_key=API_KEY, temperature=0.2)
    # llm = ChatGoogleGenerativeAI(model='gemma-4-31b-it', api_key=API_KEY, temperature=0.2)
    llm = ChatOpenAI(
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
    embedder = SentenceTransformerEmbedder()
    cve_store = ElasticSearchVectorStore(index_name='cve_index')
    mitre_store = ElasticSearchVectorStore(index_name='mitre_attack')

    data_saver = CSVDataSaver(alerts_csv_path='reports/alerts_results.csv', evaluations_csv_path='reports/evaluations_results.csv')
    tracker = UniversalTokenTracker()
    agent = SOCAgent(config, llm, alert_data, embedder, mitre_store, cve_store, tracker)
    
    evaluator = EvaluationRunner(agent, data_saver, config)

    df = pd.read_csv('data/unique_alerts.csv', parse_dates=['timestamp'])
    alert = json.loads(df.iloc[0].alert)
    key_path = ['rule', 'mitre']  
    parent = alert
    for key in key_path[:-1]:
        parent = parent.get(key, {})
        if not isinstance(parent, dict):
            parent = {}
            break
    parent.pop(key_path[-1], None)
    # # alert = {"description": 'Processes running for all users were queried with ps command.'}
    agent.process_alert(alert)
    
    # evaluator.run_evaluation(df, dataset_name='Unique Alerts')

    


if __name__ == "__main__":
    main()
