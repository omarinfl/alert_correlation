from .nodes import classification_node, mitre_search_node, cve_search_node, validation_node, final_report_node, alert_context_node
from ..models.models import AgentState
from langgraph.graph import StateGraph, END
from dotenv import load_dotenv
import pandas as pd
import json

load_dotenv()

workflow = StateGraph(AgentState)
workflow.add_node('classification', classification_node)
workflow.add_node('mitre_search_node', mitre_search_node)
workflow.add_node('cve_search_node', cve_search_node)
workflow.add_node('alert_context_node', alert_context_node)
workflow.add_node('validation_node', validation_node)
workflow.add_node('final_report_node', final_report_node)

workflow.set_entry_point('classification')

workflow.add_edge('classification', 'mitre_search_node')
workflow.add_edge('classification', 'cve_search_node')
workflow.add_edge('classification', 'alert_context_node')


workflow.add_edge(['mitre_search_node', 'cve_search_node', 'alert_context_node'], 'validation_node')
workflow.add_edge('validation_node', 'final_report_node')

workflow.add_edge('classification', END)

app = workflow.compile()

if __name__ == "__main__": 
    data = pd.read_csv('data/mini_dataset_parsed.csv')
    # Tomamos el primer alert del dataset para probar el agente
    user_input = json.loads(data.iloc[8]['alert'])
    # user_input = "user1 connects to sept from fleatbottom through RDP via mstsc"
    # user_input = '{"agent": {"ip": "10.35.35.206", "name": "wazuh-client", "id": "27"}, "manager": {"name": "wazuh.manager"}, "data": {"protocol": "GET", "srcip": "172.17.130.196", "id": "404", "url": "/wp-includes/blocks/query/wsdl"}, "rule": {"firedtimes": 185909, "mail": false, "level": 5, "pci_dss": ["6.5", "11.4"], "tsc": ["CC6.6", "CC7.1", "CC8.1", "CC6.1", "CC6.8", "CC7.2", "CC7.3"], "description": "Web server 400 error code.", "groups": ["web", "accesslog", "attack"], "id": "31101", "nist_800_53": ["SA.11", "SI.4"], "gdpr": ["IV_35.7.d"]}, "decoder": {"name": "web-accesslog"}, "full_log": "172.17.130.196 - - [18/Jan/2022:12:28:56 +0000] \"GET /wp-includes/blocks/query/wsdl HTTP/1.1\" 404 363 \"-\" \"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\"", "input": {"type": "log"}, "@timestamp": "2022-01-18T12:28:56.000000Z", "location": "/var/log/apache2/intranet-access.log", "id": "1686442177.134290352"}'
    # user_input = '''
    # {"timestamp": "2025-09-22T18:30:38.258+0000", "rule": {"level": 5, "description": "Web server 400 error code.", "id": "31101", "firedtimes": 162, "mail": false, "groups": ["web", "accesslog", "attack"], "agent": {"id": "002", "name": "videoserver", "ip": "172.17.100.121"}, "manager": {"name": "wazuh"}, "id": "1758565838.1814008", "full_log": "192.42.1.174 - - [22/Sep/2025:18:30:36 +0000] \\"GET /borLjZ2z.shtm HTTP/1.1\\" 404 396 \\"-\\" \\"Mozilla/5.00\\"", "decoder": {"name": "web-accesslog"}, "data": {"protocol": "GET", "srcip": "192.42.1.174", "id": "404", "url": "/borLjZ2z.shtm"}, "location": "/var/www/default/log/access.log"}
    # {"timestamp": "2025-09-22T18:30:38.258+0000", "rule": {"level": 5, "description": "Web server 400 error code.", "id": "31101", "firedtimes": 163, "mail": false, "groups": ["web", "accesslog", "attack"], "agent": {"id": "002", "name": "videoserver", "ip": "172.17.100.121"}, "manager": {"name": "wazuh"}, "id": "1758565838.1814504", "full_log": "192.42.1.174 - - [22/Sep/2025:18:30:36 +0000] \\"GET /borLjZ2z.koi8-r HTTP/1.1\\" 404 396 \\"-\\" \\"Mozilla/5.00 \\"", "decoder": {"name": "web-accesslog"}, "data": {"protocol": "GET", "srcip": "192.42.1.174", "id": "404", "url": "/borLjZ2z.koi8-r"}, "location": "/var/www/default/log/access.log"}'''

    inputs = {'original_alert': user_input}
    for event in app.stream(inputs, stream_mode='updates'):
        for node_name, node_state in event.items():
            print(f'\nNODO: [{node_name}]')

            if 'classification' in node_state:
                print(f"Classification: {node_state['classification']}")

            if 'mitre_data' in node_state:
                print(f"MITRE Data: {node_state['mitre_data'][:200]}...")

            if 'cve_data' in node_state:
                print(f"CVE Data: {node_state['cve_data'][:200]}...")

            if 'context_window' in node_state:
                print(f"Context Window: {node_state['context_window'][:2]}...")  # Print only the first 2 alerts for brevity

            if 'validation_report' in node_state:
                print(f"Validation Report: {node_state['validation_report']}")

            if 'final_report' in node_state:
                print(f"Final Report: {node_state['final_report']}")
