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
        context_window_size=4,
        generate_report=True,
        report_dir='reports',
        mitre_top_k=10
    )

    alert_data = CSVAlertData(csv_path='data/mini_dataset_parsed.csv')

    llm_strict = ChatGoogleGenerativeAI(model='gemini-3.1-flash-lite', api_key=API_KEY, temperature=0.0, seed=42)
    llm_creative = ChatGoogleGenerativeAI(model='gemini-3.1-flash-lite', api_key=API_KEY, temperature=0.2, seed=42)

    
    # llm = ChatGoogleGenerativeAI(model='gemma-4-31b-it', api_key=API_KEY, temperature=0.2)
#     llm = ChatOpenAI(
#         model="gemma-4-26b-a4b",
#         api_key='EMPTY',
#         # streaming=True,
#         # stream_usage=True,
#         temperature=0.2,
#         # max_tokens=None,
#         # timeout=12000,
#         # reasoning_effort="low",
#         # max_retries=3,
#         base_url="http://10.0.152.198:8003/v1",
#         # http_client=httpx.Client(timeout=httpx.Timeout(connect=60.0, read=600.0, write=60.0, pool=60.0))
# )
    # embedder = SentenceTransformerEmbedder()
    cve_store = ElasticSearchVectorStore(index_name='kev_cve_index_bge')
    # mitre_store = ElasticSearchVectorStore(index_name='mitre_attack')

    embedder = SentenceTransformerEmbedder('BAAI/bge-small-en-v1.5')
    mitre_store = ElasticSearchVectorStore(index_name='mitre_attack_v3_bge_small')

    data_saver = CSVDataSaver(alerts_csv_path='reports/alerts_results.csv', evaluations_csv_path='reports/evaluations_results.csv')
    tracker = UniversalTokenTracker()
    agent = SOCAgent(config, llm_strict, llm_creative, alert_data, embedder, mitre_store, cve_store, tracker)
    
    evaluator = EvaluationRunner(agent, data_saver, config)

    df = pd.read_csv('data/unique_alerts.csv', parse_dates=['timestamp'])
    # alert = json.loads(df.iloc[0].alert)
    # key_path = ['rule', 'mitre']  
    # parent = alert
    # for key in key_path[:-1]:
    #     parent = parent.get(key, {})
    #     if not isinstance(parent, dict):
    #         parent = {}
    #         break
    # parent.pop(key_path[-1], None)
    # # alert = {"description": 'Processes running for all users were queried with ps command.'}
    alert = {
        "timestamp": "2026-06-14T10:15:22.412+0000",
        "rule": {
            "level": 9,
            "description": "Web application attack: Unauthorized access attempt to a critical administrative endpoint.",
            "id": "31153", 
            "firedtimes": 3,
            "mail": False,
            "groups": [
                "web",
                "appsec",
                "attack",
                "recon"
            ],
            "pci_dss": [
                "6.5",
                "11.4"
            ],
            "gdpr": [
                "IV_35.7.d"
            ],
            "nist_800_53": [
                "SA.11",
                "SI.4"
            ],
            "tsc": [
                "CC6.6",
                "CC7.1",
                "CC7.2"
            ]
        },
        "agent": {
            "id": "005",
            "name": "peoplesoft-prod-01",
            "ip": "172.17.200.45"
        },
        "manager": {
            "name": "wazuh"
        },
        "id": "1784110522.284615",
        "full_log": "198.51.100.12 - - [14/Jun/2026:10:15:22 +0000] \"POST /EnvironmentManagement/UpdateService HTTP/1.1\" 200 1450 \"-\" \"Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0\"",
        "decoder": {
            "name": "web-accesslog"
        },
        "data": {
            "protocol": "POST",
            "srcip": "198.51.100.12",
            "id": "200",
            "url": "/EnvironmentManagement/UpdateService"
        },
        "location": "/opt/oracle/psft/cfg/webserv/peoplesoft/servers/PIA/logs/access.log"
    }
    
    agent.process_alert(alert)
    # evaluator.run_evaluation(df, dataset_name='Unique Alerts', debug=True)

    


if __name__ == "__main__":
    main()
