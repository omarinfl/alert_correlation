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


load_dotenv()

API_KEY = os.getenv('GEMINI_TOKEN')


def main():

    # Definir la configuración
    config = AgentConfig(
        use_context_window=True,
        context_window_size=4,
        context_mode='PAST',
        generate_report=True,
        report_dir='reports',
        mitre_top_k=10
    )

    # Definir los LLMs
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


    # Definir el modelo de embeddings
    embedder = SentenceTransformerEmbedder('BAAI/bge-small-en-v1.5')

    # Definir los índices vectoriales
    mitre_store = ElasticSearchVectorStore(index_name='mitre_attack_v3_bge_small')
    cve_store = ElasticSearchVectorStore(index_name='kev_cve_index_bge')

    # Definir el repositorio de alertas
    alert_data = CSVAlertRepository(csv_path='data/alerts_dataset_parsed.csv')
    
    # Instanciar el TokenTracker
    tracker = UniversalTokenTracker()

    # Instanciar el agente con los componentes definidos
    agent = SOCAgent(config, llm_strict, llm_creative, alert_data, embedder, mitre_store, cve_store, tracker)
    
    # Datos
    df = pd.read_csv('data/unique_alerts.csv', parse_dates=['timestamp'])

    # Si se quiere ejecutar una evaluación:  
    # Definir el guardado de los datos
    # data_saver = CSVDataSaver(alerts_csv_path='evaluations/alerts_results.csv', evaluations_csv_path='evaluations/evaluations_results.csv')
    
    # # Definir el evaluador
    # evaluator = EvaluationRunner(agent, data_saver, config)
   
    # evaluator.run_evaluation(df, dataset_name='Unique Alerts', debug=True)

    alert = json.loads(df.iloc[-1]['alert'])
    final_state, _ = agent.process_alert(alert)

    val_report = final_state.get('validation_report')
    predicted_ttps = [e.item_id for e in val_report.mitre_evaluations if e.decision] if val_report else []
    predicted_cves = [e.item_id for e in val_report.cve_evaluations if e.decision] if val_report else []
            
    print(f'Predicted TTPs: {predicted_ttps}')
    print(f'Predicted CVEs: {predicted_cves}')

    report_text = final_state.get('final_report')
    print('Final Report:')
    print(report_text)


if __name__ == "__main__":
    main()
