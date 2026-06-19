from .nodes import make_classification_node, make_mitre_search_node, make_cve_search_node, make_validation_node, make_final_report_node, make_alert_context_node
from ..models.models import AgentState
from langgraph.graph import StateGraph, END
import time

class SOCAgent:
    def __init__(self, config, llm_strict, llm_creative, alert_repo, embedder, mitre_store, cve_store, tracker):
        self.config = config
        self.llm_strict = llm_strict
        self.llm_creative = llm_creative
        self.alert_repo = alert_repo
        self.embedder = embedder
        self.mitre_store = mitre_store
        self.cve_store = cve_store
        self.tracker = tracker
        self.app = self._build_app()

    def _build_app(self):
        workflow = StateGraph(AgentState)
        workflow.add_node('classification', make_classification_node(self.llm_strict, self.tracker))
        workflow.add_node('mitre_search_node', make_mitre_search_node(self.embedder, self.mitre_store, self.config, self.tracker))
        workflow.add_node('cve_search_node', make_cve_search_node(self.embedder, self.cve_store, self.tracker))
        workflow.add_node('alert_context_node', make_alert_context_node(self.config, self.alert_repo, self.tracker))
        workflow.add_node('validation_node', make_validation_node(self.llm_strict, self.tracker))
        workflow.add_node('final_report_node', make_final_report_node(self.config, self.llm_creative, self.tracker))

        workflow.set_entry_point('classification')

        workflow.add_edge('classification', 'mitre_search_node')
        workflow.add_edge('classification', 'cve_search_node')
        workflow.add_edge('classification', 'alert_context_node')

        workflow.add_edge(['mitre_search_node', 'cve_search_node', 'alert_context_node'], 'validation_node')
        workflow.add_edge('validation_node', 'final_report_node')

        workflow.add_edge('final_report_node', END)

        return workflow.compile()
    
    def process_alert(self, alert: dict):
        inputs = {'original_alert': alert}
        self.tracker.reset()  # Reiniciamos el tracker para esta nueva alerta
        start_time = time.time()

        event = self.app.invoke(inputs)

        execution_time = time.time() - start_time

        telemetry = {
            "execution_time": round(execution_time, 2),
            "token_usage": {
                "prompt_tokens": self.tracker.prompt_tokens,
                "completion_tokens": self.tracker.completion_tokens,
                "total_tokens": self.tracker.total_tokens
            },
            "llm_calls": self.tracker.llm_calls,
            "node_breakdown": self.tracker.node_metrics
        }

        return event, telemetry