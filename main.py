import os
from src.retrieval.embedders import SentenceTransformerEmbedder
from src.retrieval.store import ElasticSearchVectorStore
from src.agent.agent import SOCAgent
from src.retrieval.alert_repository import CSVAlertRepository
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
        use_context_window=True,
        context_window_size=4,
        context_mode='AROUND',
        generate_report=True,
        report_dir='reports',
        mitre_top_k=10
    )


    llm_strict = ChatGoogleGenerativeAI(model='gemini-3.1-flash-lite', api_key=API_KEY, temperature=0.0, seed=42)
    llm_creative = ChatGoogleGenerativeAI(model='gemini-3.1-flash-lite', api_key=API_KEY, temperature=0.2, seed=42)

    
    # llm_strict = ChatOpenAI(
    #     model=os.getenv('GEMMA_NAME'),
    #     api_key='EMPTY',
    #     temperature=0.0,
    #     seed=42,
    #     base_url=os.getenv('GEMMA_ENDPOINT'),
    # )

    # llm_creative = ChatOpenAI(
    #     model=os.getenv('GEMMA_NAME'),
    #     api_key='EMPTY',
    #     temperature=0.2,
    #     seed=42,
    #     base_url=os.getenv('GEMMA_ENDPOINT'),
    # )


    embedder = SentenceTransformerEmbedder('BAAI/bge-small-en-v1.5')
    mitre_store = ElasticSearchVectorStore(index_name='mitre_attack_v3_bge_small')
    cve_store = ElasticSearchVectorStore(index_name='kev_cve_index_bge')
    
    alert_data = CSVAlertRepository(csv_path='data/alerts_dataset_parsed.csv')

    data_saver = CSVDataSaver(alerts_csv_path='evaluations/alerts_results.csv', evaluations_csv_path='evaluations/evaluations_results.csv')
    tracker = UniversalTokenTracker()
    agent = SOCAgent(config, llm_strict, llm_creative, alert_data, embedder, mitre_store, cve_store, tracker)
    
    evaluator = EvaluationRunner(agent, data_saver, config)

    # df = pd.read_csv('data/dataset_sintetico_cves.csv', parse_dates=['timestamp'])
    df = pd.read_csv('data/unique.csv', parse_dates=['timestamp'])
    alert = json.loads(df.iloc[-1]['alert'])


    # evaluator.run_evaluation(df, dataset_name='Unique Alerts', debug=True)
    final_state, _ = agent.process_alert(alert)

    val_report = final_state.get('validation_report')
    predicted_ttps = [e.item_id for e in val_report.mitre_evaluations if e.decision] if val_report else []
    predicted_cves = [e.item_id for e in val_report.cve_evaluations if e.decision] if val_report else []
            
    print(f'Predicted TTPs: {predicted_ttps}')
    print(f'Predicted CVEs: {predicted_cves}')

    report_text = final_state.get('final_report')
    print('Final Report:')
    print(report_text)

    # if report_text:
    #     alert_id = alert.get('id', 'unknown')
    #     context = 'with_context' if config.use_context_window else 'without_context'
    #     report_dir = f"reports/escenario5"
    #     os.makedirs(report_dir, exist_ok=True)
    #     with open(f"{report_dir}/{alert_id}_{context}.md", "w", encoding='utf-8') as f:
    #         f.write(report_text)



if __name__ == "__main__":
    main()
