
import os
from langchain_core.messages import SystemMessage, HumanMessage
from src.models.models import AlertClasification, AgentState, ValidationReport
import time


def make_classification_node(llm, tracker):
    def classification_node(state: AgentState) -> AgentState:
        '''Node that classifies the alert and extracts relevant keywords for MITRE and CVE searches.'''
        
        tracker.set_current_node('classification')  
        start_time = time.time()

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
        IMPORTANT for mitre_description: if the alert is a web scanner or scanning tool event, don't focus solely on its scanning activity; also describe its behavior and objectives.
        '''
        structured_llm = llm.with_structured_output(AlertClasification)
        llm_with_tracker = structured_llm.with_config(callbacks=[tracker])
        classification = llm_with_tracker.invoke([SystemMessage(content=prompt),
                                                HumanMessage(content=f'The alert to analyze is: {state["original_alert"]}')])
        
        tracker.record_node_time('classification', time.time() - start_time)

        print(classification)
        return {'classification': classification}
    return classification_node



def make_mitre_search_node(embedder, mitre_store, config, tracker):
    def mitre_search_node(state: AgentState) -> AgentState:
        '''Node that performs MITRE search if mitre_search is True.'''

        if not state['classification'].mitre_search:
            return {'mitre_data': {}}
        
        tracker.set_current_node('mitre_search_node')
        start_time = time.time()
        prefix = "Represent this sentence for searching relevant passages: " # Para bge (asimétrico)

        desc = state['classification'].mitre_description
        query = state['classification'].mitre_keywords
        query_vector = embedder.embed_query(prefix + query)

        results = mitre_store.search_mitre_hybrid_simple(query_vector, desc, top_k=config.mitre_top_k)
        
        cleaned_results = {
            r.get('technique_id'): {
                'technique_id': r.get('technique_id'),
                'name': r.get('name'),
                'description': r.get('description'),
                'tactics': r.get('tactics'),
                'platforms': r.get('platforms'),
                'mitigations': r.get('mitigations'),
                'detections': r.get('detections'),
                'procedures': r.get('procedures')
            } for r in results if r.get('technique_id')}
    
        tracker.record_node_time('mitre_search_node', time.time() - start_time)
        return {'mitre_data': cleaned_results}
    return mitre_search_node

def make_cve_search_node(embedder, cve_store, tracker):
    def cve_search_node(state: AgentState) -> AgentState:
        '''Node that performs CVE search if cve_search is True.'''

        if not state['classification'].cve_search:
            return {'cve_data': {}}

        tracker.set_current_node('cve_search_node')
        start_time = time.time()
        
        prefix = "Represent this sentence for searching relevant passages: " # Para bge (asimétrico)
        
        desc = state['classification'].cve_description
        query = state['classification'].cve_keywords
        query_vector = embedder.embed_query(prefix + query)
        
        results = cve_store.search_mitre_hybrid_simple(query_vector, desc, top_k=3)
        
        cleaned_results = {
            r.get('id'): {
                'cve_id': r.get('id'),
                'title': r.get('title'),
                'description': r.get('description'),
                'published_date': r.get('published_date'),
                'cvss': r.get('cvss'),
                'affected_products': r.get('affected_products'),
                'versions': r.get('versions'),
                'mitigations': r.get('mitigations'),
                'ssvc': r.get('ssvc'),
                'references': r.get('references'),
                'in_kev': r.get('in_kev')
            } for r in results if r.get('id') 
        }
 
        tracker.record_node_time('cve_search_node', time.time() - start_time)
        return {'cve_data': cleaned_results}
    return cve_search_node

def make_alert_context_node(config, alert_data, tracker):
    def alert_context_node(state: AgentState) -> AgentState:
        '''Node that retrieves previous and subsequent alerts to provide context to the agent.'''
        if not config.use_context_window:
            return {'context_window': 'Context window is disabled by configuration.'}
        
        try:
            tracker.set_current_node('alert_context_node')
            start_time = time.time()

            alert = state['original_alert']
            context_window = alert_data.get_context_window(alert, config.context_window_size)
            
            tracker.record_node_time('alert_context_node', time.time() - start_time)
        
        except Exception as e:
            print(f"Error occurred while retrieving alert context: {e}")
            context_window = []
        return {'context_window': context_window}
    return alert_context_node

def make_validation_node(llm, tracker):
    def validation_node(state: AgentState) -> AgentState:
        '''Node that validates the relevance of the retrieved MITRE and CVE information.'''
        
        tracker.set_current_node('validation_node')
        start_time = time.time()

        if not state.get('mitre_data') and not state.get('cve_data'):
            print('Búsqueda omitida por el clasificador. Saltando validación LLM...')
            # Devolvemos un reporte vacío instantáneo sin llamar al LLM
            empty_report = ValidationReport(mitre_evaluations=[], cve_evaluations=[])
            tracker.record_node_time('validation_node', time.time() - start_time)
            return {'validation_report': empty_report}

        print('Evaluando respuestas recuperadas...')
        
        
        if state.get('mitre_data'):  
            mitre_data = 'MITRE results:\n' + '\n'.join([f"Technique ID: {r['technique_id']}\n"
                            f"Name: {r['name']}\n"
                            f"Description: {r['description']}\n"
                            f"Tactics: {r['tactics']}\n"
                            f"Platforms: {r['platforms']}\n"
                            "-----------------" for r in state['mitre_data'].values()]) 
        else: 
            mitre_data = 'No relevant MITRE information found in the alert.'
        
        if state.get('cve_data'): 
            cve_data = 'CVE results:\n' + '\n'.join([f"CVE ID: {r['cve_id']}\n"
                            f"Title: {r['title']}\n"
                            f"Description: {r['description']}\n"
                            f"Published Date: {r['published_date']}\n"
                            f"Affected Products: {r['affected_products']}\n"
                            "-----------------" for r in state['cve_data'].values()])
        else:
            cve_data = 'No relevant CVE information found in the alert.'

        prompt = f'''
        You are a SOC analyst. Your task is to evaluate the relevance of the retrieved MITRE techniques and CVE vulnerabilities from an automatic search system.
        You must evaluate if each result is actually relevant to the original alert or whether it is semantic noise (for example, a MITRE technique that shares some keywords with the alert but is not actually related to the attack described in the alert).
        You also have a context window with previous and subsequent alerts that can help you understand better the situation and the relevance of the retrieved information. Use it to determine if the retrieved MITRE techniques and CVE vulnerabilities are actually relevant or are noise.
        
        ORIGINAL ALERT: {state['original_alert']}

        CONTEXT WINDOW: {state['context_window']}

        EXTRACTED MITRE RESULTS: {mitre_data}
        
        EXTRACTED CVE RESULTS: {cve_data}

        INSTRUCTIONS:
        - Compare each technique and vulnerability with the original alert.
        - For each MITRE technique retrieved, assign a relevance score from 0 to 1, where 0 means completely irrelevant and 1 means highly relevant. 
        - Provide a detailed explanation of why you assigned that score.
        - Make a final decision on whether this technique should be included in the final report or not (decision=True/False).
        '''
 
        validator = llm.with_structured_output(ValidationReport)
        llm_with_tracker = validator.with_config(callbacks=[tracker])
        validation_report = llm_with_tracker.invoke([HumanMessage(content=prompt)])

        tracker.record_node_time('validation_node', time.time() - start_time)

        for evaluation in validation_report.mitre_evaluations + validation_report.cve_evaluations:
            print(f"ID {evaluation.item_id} - Relevance Score: {evaluation.relevance_score}, Decision: {evaluation.decision}\nExplanation: {evaluation.explanation}\n")
        return {'validation_report': validation_report}
    return validation_node


def make_final_report_node(config, llm, tracker):
    def final_report_node(state: AgentState) -> AgentState:
        '''Node that generates a final report based on the original alert, the classification, and the retrieved MITRE and CVE information.'''
        if not config.generate_report:
            return {'final_report': 'Report generation is disabled by configuration.'}
        
        tracker.set_current_node('final_report_node')
        start_time = time.time()

        validated_data = state['validation_report']

        valid_mitre_evals = sorted(
            [e for e in validated_data.mitre_evaluations if e.decision],
            key=lambda x: x.relevance_score,
            reverse=True
        )

        # validated_mitre = [e for e in validated_data.mitre_evaluations if e.decision]
        validated_mitre = '\n'.join([
            f"Technique ID: {e.item_id}\n"
            f"Name: {state['mitre_data'][e.item_id]['name']}\n"
            f"Description: {state['mitre_data'][e.item_id]['description']}\n"
            f"Tactics: {state['mitre_data'][e.item_id]['tactics']}\n"
            f"Platforms: {state['mitre_data'][e.item_id]['platforms']}\n"
            f"Mitigations: {state['mitre_data'][e.item_id]['mitigations']}\n"
            f"Confidence Score: {e.relevance_score}\n"
            f"Explanation: {e.explanation}\n"
            "-----------------" 
            for e in valid_mitre_evals 
            if e.item_id in state['mitre_data']
        ])

        valid_cve_evals = sorted(
            [e for e in validated_data.cve_evaluations if e.decision],
            key=lambda x: x.relevance_score,
            reverse=True
        )

        validated_cve = '\n'.join([
            f"CVE ID: {e.item_id}\n"
            f"Title: {state['cve_data'][e.item_id].get('title')}\n"
            f"Description: {state['cve_data'][e.item_id].get('description')}\n"
            f"CVSS Score: {state['cve_data'][e.item_id].get('cvss')}\n"
            f"SSVC Priority: {state['cve_data'][e.item_id].get('ssvc')}\n"
            f"In CISA KEV (Known Exploited Vulnerability): {state['cve_data'][e.item_id].get('in_kev')}\n"
            f"Affected Products/Versions: {state['cve_data'][e.item_id].get('affected_products')}\n"
            f"Mitigations/Remediation: {state['cve_data'][e.item_id].get('mitigations')}\n"
            f"References & Patches: {state['cve_data'][e.item_id].get('references')}\n"
            f"Validador Confidence Score: {e.relevance_score}\n"
            f"Validador Explanation: {e.explanation}\n"
            "-----------------"
            for e in valid_cve_evals
            if e.item_id in state['cve_data']
        ])


        # prompt = f'''
        # You are a SOC analyst. Your task is to generate a final report based on the information about the alert, the relevant MITRE techniques and its tactics and CVE vulnerabilities that have been identified.
        # Generate a concise report in Markdown format summarizing the incident, correlating the MITRE and CVE information with the original alert, and providing an assessment of the priority and severity of the incident, as well as recommended response actions.
        # '''
        
        prompt = f'''
        You are a Senior Tier 3 SOC Analyst. Your task is to generate a final incident report based on the provided alert, context, and validated threat intelligence.

        Follow this STRICT MARKDOWN STRUCTURE exactly as outlined below:

        # Incident Report: [Auto-generate a concise and descriptive title]

        ## 1. Executive Summary
        Provide a high-level summary of what occurred, identifying the affected host, the core action detected, and whether it represents an isolated anomaly or part of a broader attack.

        ## 2. Incident Context
        Analyze the 'Original Alert' alongside the 'CONTEXT WINDOW'. Explain the sequence of events. If the main alert is just an operational symptom (e.g., buffer full) caused by an attack in the context, explicitly state this relationship.

        ## 3. Threat Intelligence Correlation
        You MUST divide this into two strictly separate subsections:
        
        ### 3.1 Validated Evidence-Based Mapping (RAG)
        ONLY list techniques or CVEs that are explicitly provided in the 'MITRE Information' or 'CVE Information' inputs. Include a brief description of the technique or vulnerability, the tactic to which it belongs, as well as the rationale and evidence demonstrating why it correlates with the alert and the context. Try to base your response on the context provided.
        
        STRICT ANTI-HALLUCINATION RULE: Do NOT invent, guess, or generate MITRE IDs (TXXXX) or CVEs. If the inputs are empty, you MUST write exactly: "No validated MITRE techniques or CVEs were matched by the correlation engine for this specific alert."

        ### 3.2 AI Heuristic Proposals (Unverified)
        If the RAG mapping is empty, or if you believe the Context Window strongly suggests an attack, use your AI knowledge to suggest 1 or 2 MITRE techniques that MIGHT apply. Always focus on the analyzed alert and determine whether it could be a result of the actions in the context. If there is no evidence of possible malicious actions, classify the alert like NOISE.
        You MUST prefix this section with: "*Warning: These are AI inferences based on contextual behavior and have NOT been validated.*" Explain briefly why you suggest them based on the context.

        ## 4. Assessment
        Define the Severity (Low/Medium/High/Critical) and justify it based on the evidence. If provided, try to use severity scores of the CVEs predicted.

        ## 5. Recommended Actions
        Provide highly actionable steps to contain, investigate, or remediate the specific threat. If provided, try to use the proposed mitigations in techniques and CVEs predicted.
        '''

        user_input = f'''
        Original Alert: {state['original_alert']}
        Classification: {state['classification']}
        CONTEXT WINDOW: {state['context_window']}
        MITRE Information: {validated_mitre}
        CVE Information: {validated_cve}'''

        llm_with_tracker = llm.with_config(callbacks=[tracker])

        response = llm_with_tracker.invoke([SystemMessage(content=prompt), HumanMessage(content=user_input)])
        
        try:
            report_text = response.content[0]['text'] # Formato Gemini
        except:
            report_text = response.content # Formato locales
        
        tracker.record_node_time('final_report_node', time.time() - start_time)
        return {'final_report': report_text}
    return final_report_node
