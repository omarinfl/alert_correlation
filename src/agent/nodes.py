
import os

from langchain_core.messages import SystemMessage, HumanMessage, BaseMessage
from src.retrieval.embedders import SentenceTransformerEmbedder
from src.retrieval.store import ElasticSearchVectorStore

from src.models.models import AlertClasification, AgentState, ValidationReport

from langchain_google_genai import ChatGoogleGenerativeAI
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv('GEMINI_TOKEN')
DATAPATH = os.getenv('DATA')

llm = ChatGoogleGenerativeAI(model='gemini-3.1-flash-lite', api_key=API_KEY, temperature=0.2)
# llm = ChatGoogleGenerativeAI(model='gemma-4-31b-it', api_key=API_KEY, temperature=0.2)

embedder = SentenceTransformerEmbedder()
cve_store = ElasticSearchVectorStore(index_name='cve_index')
mitre_store = ElasticSearchVectorStore(index_name='mitre_attack')


def classification_node(state: AgentState) -> AgentState:
    '''Node that classifies the alert and extracts relevant keywords for MITRE and CVE searches.'''
    prompt = f'''
    You are a SOC analyst. Your task is to analyze the following security alert and determine if it contains information that can be used to search in MITRE and CVE databases.

    Alert: {state['original_alert']}

    For MITRE, you are looking for behaviors, commands, processes, tactics or malware mentioned in the alert. If you find any, set mitre_search to True and extract the relevant keywords for searching in MITRE database.

    For CVE, you are looking for software versions, scan results or vulnerability identifiers mentioned in the alert. If you find any, set cve_search to True and extract the relevant keywords for searching in CVE database.
    
    Also, create a technical description of the alert that can be used as a query for the searches in MITRE and CVE databases. DO NOT make assumptions, just explain the alert with details.
    
    EXAMPLES:
    - Alert: "Multiple failed login attempts in RDP" mitre_search: True (brute force), cve_search: False (no vulnerabilities mentioned)
    - Alert: "WINRAR old version detected that allows remote code execution" mitre_search: False, cve_search: True (WINRAR vulnerability)
    - Alert: "Mimikatz process detected running in memory" mitre_search: True (credential dumping), cve_search: False (no vulnerabilities mentioned)
    - Alert: "Proxyshell exploitation (CVE-2021-34473) followed by webshell detected" mitre_search: True (Web Shell), cve_search: True (Proxyshell vulnerability)
    
    At the slightest suspicion of malicious behavior, you MUST set mitre_search to True, and if there is any mention of exploitable software, vulnerabilities or patches, you MUST set cve_search to True.
    '''
    structured_llm = llm.with_structured_output(AlertClasification)
    classification = structured_llm.invoke([SystemMessage(content=prompt),
                                            HumanMessage(content=f'The alert to analyze is: {state["original_alert"]}')])
    return {'classification': classification}


def mitre_search_node(state: AgentState) -> AgentState:
    '''Node that performs MITRE search if mitre_search is True.'''

    if not state['classification'].mitre_search:
        return {'mitre_data': 'No relevant MITRE information found in the alert.'}
    
    query = state['classification'].mitre_description
    query_vector = embedder.embed_query(query)
    results = mitre_store.search(query_vector, top_k=5)

    results_text = 'MITRE results:\n' + '\n'.join([f"Technique ID: {r['technique_id']}\n"
                    f"Name: {r['name']}\n"
                    f"Description: {r['description']}\n"
                    f"Tactics: {r['tactics']}\n"
                    f"Platforms: {r['platforms']}\n"
                    "-----------------" for r in results])
    return {'mitre_data': results_text}

def cve_search_node(state: AgentState) -> AgentState:
    '''Node that performs CVE search if cve_search is True.'''

    if not state['classification'].cve_search:
        return {'cve_data': 'No relevant CVE information found in the alert.'}

    query = state['classification'].cve_description
    query_vector = embedder.embed_query(query)
    results = cve_store.search(query_vector, top_k=3)

    results_text = 'CVE results:\n' + '\n'.join([f"CVE ID: {r['id']}\n"
                    f"Title: {r['title']}\n"
                    f"Description: {r['description']}\n"
                    f"Published Date: {r['published_date']}\n"
                    f"CVSS: {r['cvss']}\n"
                    f"Affected Products: {r['versions']}\n"
                    f"Mitigations: {r['mitigations']}\n"
                    f"SSVC: {r['ssvc']}\n"
                    f"References: {r['references']}\n"
                    f"In KEV: {r['in_kev']}\n"
                    "-----------------" for r in results])
    return {'cve_data': results_text}


def alert_context_node(state: AgentState, window_size: int = 10) -> AgentState:
    '''Node that retrieves previous and subsequent alerts to provide context to the agent.'''
    try:
        import pandas as pd
        df = pd.read_csv(DATAPATH)
        df.timestamp = pd.to_datetime(df.timestamp)
        alert_time = pd.to_datetime(state['original_alert']['timestamp'])

        previous_alerts = df[df['timestamp'] < alert_time].tail(window_size//2)[['timestamp', 'level', 'description', 'fired_times', 'full_log']]
        subsequent_alerts = df[df['timestamp'] > alert_time].head(window_size//2)[['timestamp', 'level', 'description', 'fired_times', 'full_log']]

        context_window = previous_alerts.to_dict(orient='records') + subsequent_alerts.to_dict(orient='records')
    except Exception as e:
        print(f"Error occurred while retrieving alert context: {e}")
        context_window = []
    return {'context_window': context_window}


def validation_node(state: AgentState) -> AgentState:
    '''Node that validates the relevance of the retrieved MITRE and CVE information.'''
    
    prompt = f'''
    You are a SOC analyst. Your task is to evaluate the relevance of the retrieved MITRE techniques and CVE vulnerabilities from an automatic search system.
    You must evaluate if each result is actually relevant to the original alert or whether it is semantic noise (for example, a MITRE technique that shares some keywords with the alert but is not actually related to the attack described in the alert).
    You also have a context window with previous and subsequent alerts that can help you understand better the situation and the relevance of the retrieved information. Use it to determine if the retrieved MITRE techniques and CVE vulnerabilities are actually relevant or are noise.
    
    ORIGINAL ALERT: {state['original_alert']}

    CONTEXT WINDOW: {state['context_window']}

    EXTRACTED MITRE RESULTS: {state['mitre_data']}
    
    EXTRACTED CVE RESULTS: {state['cve_data']}

    INSTRUCTIONS:
    - Compare each technique and vulnerability with the original alert.
    - For each MITRE technique retrieved, assign a relevance score from 0 to 1, where 0 means completely irrelevant and 1 means highly relevant. 
    - Provide a detailed explanation of why you assigned that score.
    - Make a final decision on whether this technique should be included in the final report or not (decision=True/False).
    '''

    validator = llm.with_structured_output(ValidationReport)
    validation_report = validator.invoke([HumanMessage(content=prompt)])

    for evaluation in validation_report.mitre_evaluations + validation_report.cve_evaluations:
        print(f"ID {evaluation.item_id} - Relevance Score: {evaluation.relevance_score}, Decision: {evaluation.decision}\nExplanation: {evaluation.explanation}\n")
    return {'validation_report': validation_report}





def final_report_node(state: AgentState) -> AgentState:
    '''Node that generates a final report based on the original alert, the classification, and the retrieved MITRE and CVE information.'''
    
    validated_data = state['validation_report']
    validated_mitre = [e for e in validated_data.mitre_evaluations if e.decision]
    validated_cve = [e for e in validated_data.cve_evaluations if e.decision]
    
    prompt = f'''
    You are a SOC analyst. Your task is to generate a final report based on the information about the alert, the relevant MITRE techniques and its tactics and CVE vulnerabilities that have been identified.
    Generate a concise report in Markdown format summarizing the incident, correlating the MITRE and CVE information with the original alert, and providing an assessment of the priority and severity of the incident, as well as recommended response actions.
    '''

    user_input = f'''
    Original Alert: {state['original_alert']}
    Classification: {state['classification']}
    CONTEXT WINDOW: {state['context_window']}
    MITRE Information: {validated_mitre}
    CVE Information: {validated_cve}'''

    response = llm.invoke([SystemMessage(content=prompt), HumanMessage(content=user_input)])
    # Escribir en un archivo de texto el informe final
    with open('final_report.md', 'w') as f:
        f.write(response.content[0]['text'])
    
    return {'final_report': response.content[0]}
