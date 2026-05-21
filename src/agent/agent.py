from .nodes import classification_node, mitre_search_node, cve_search_node, final_report_node
from ..models.models import AgentState
from langgraph.graph import StateGraph, END


workflow = StateGraph(AgentState)
workflow.add_node('classification', classification_node)
workflow.add_node('mitre_search_node', mitre_search_node)
workflow.add_node('cve_search_node', cve_search_node)
workflow.add_node('final_report_node', final_report_node)

workflow.set_entry_point('classification')

workflow.add_edge('classification', 'mitre_search_node')
workflow.add_edge('classification', 'cve_search_node')

workflow.add_edge(['mitre_search_node', 'cve_search_node'], 'final_report_node')

workflow.add_edge('classification', END)

app = workflow.compile()

if __name__ == "__main__":    
    user_input = 'EDR alert: Detected exploitation attempt on web server. '

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

            if 'final_report' in node_state:
                print(f"Final Report: {node_state['final_report']}")
