from .nodes import classification_node, mitre_search_node, cve_search_node, validation_node, final_report_node
from ..models.models import AgentState
from langgraph.graph import StateGraph, END


workflow = StateGraph(AgentState)
workflow.add_node('classification', classification_node)
workflow.add_node('mitre_search_node', mitre_search_node)
workflow.add_node('cve_search_node', cve_search_node)
workflow.add_node('validation_node', validation_node)
workflow.add_node('final_report_node', final_report_node)

workflow.set_entry_point('classification')

workflow.add_edge('classification', 'mitre_search_node')
workflow.add_edge('classification', 'cve_search_node')

workflow.add_edge(['mitre_search_node', 'cve_search_node'], 'validation_node')
workflow.add_edge('validation_node', 'final_report_node')

workflow.add_edge('classification', END)

app = workflow.compile()

if __name__ == "__main__":    
    user_input = "user1 connects to sept from fleatbottom through RDP via mstsc"
    # user_input = '{"agent": {"ip": "10.35.35.206", "name": "wazuh-client", "id": "27"}, "manager": {"name": "wazuh.manager"}, "data": {"protocol": "GET", "srcip": "172.17.130.196", "id": "404", "url": "/wp-includes/blocks/query/wsdl"}, "rule": {"firedtimes": 185909, "mail": false, "level": 5, "pci_dss": ["6.5", "11.4"], "tsc": ["CC6.6", "CC7.1", "CC8.1", "CC6.1", "CC6.8", "CC7.2", "CC7.3"], "description": "Web server 400 error code.", "groups": ["web", "accesslog", "attack"], "id": "31101", "nist_800_53": ["SA.11", "SI.4"], "gdpr": ["IV_35.7.d"]}, "decoder": {"name": "web-accesslog"}, "full_log": "172.17.130.196 - - [18/Jan/2022:12:28:56 +0000] \"GET /wp-includes/blocks/query/wsdl HTTP/1.1\" 404 363 \"-\" \"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\"", "input": {"type": "log"}, "@timestamp": "2022-01-18T12:28:56.000000Z", "location": "/var/log/apache2/intranet-access.log", "id": "1686442177.134290352"}'
    # user_input = "mailscanner: Multiple attempts of spam"
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

            if 'validation_report' in node_state:
                print(f"Validation Report: {node_state['validation_report']}")

            if 'final_report' in node_state:
                print(f"Final Report: {node_state['final_report']}")
