from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.outputs import LLMResult
from typing import Any

class UniversalTokenTracker(BaseCallbackHandler):
    def __init__(self):
        self.node_metrics = {} 
        self.current_node = "unknown"
        
        # Totales globales
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.total_tokens = 0
        self.llm_calls = 0

    def set_current_node(self, node_name: str):
        """Avisa al tracker de qué nodo va a empezar a trabajar."""
        self.current_node = node_name
        if node_name not in self.node_metrics:
            self.node_metrics[node_name] = {
                "duration_s": 0.0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0
            }

    def record_node_time(self, node_name: str, duration: float):
        """Guarda el tiempo de ejecución del nodo."""
        if node_name in self.node_metrics:
            self.node_metrics[node_name]["duration_s"] = round(duration, 2)

    def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:
        """Suma los tokens automáticamente al nodo activo."""
        in_tok, out_tok = 0, 0
        
        # Intento con estándar actual
        try:
            message = response.generations[0][0].message
            if hasattr(message, 'usage_metadata') and message.usage_metadata:
                in_tok = message.usage_metadata.get('input_tokens', 0)
                out_tok = message.usage_metadata.get('output_tokens', 0)
                total_tok = message.usage_metadata.get('total_tokens', 0)
                
                self._save_node_stats(in_tok, out_tok, total_tok)
                self.llm_calls += 1
                return 
            
        except (AttributeError, IndexError):
            pass

        # Intento con estándar Ollama y OpenAI Legacy
        try:
            metadata = response.generations[0][0].message.response_metadata
            
            # Caso Ollama
            if 'prompt_eval_count' in metadata:
                in_tok = metadata.get('prompt_eval_count', 0)
                out_tok = metadata.get('eval_count', 0)
                self.prompt_tokens += in_tok
                self.completion_tokens += out_tok
                self.total_tokens += (in_tok + out_tok)
                return
                
            # Caso OpenAI Legacy
            if 'token_usage' in metadata:
                usage = metadata['token_usage']
                self.prompt_tokens += usage.get('prompt_tokens', 0)
                self.completion_tokens += usage.get('completion_tokens', 0)
                self.total_tokens += usage.get('total_tokens', 0)
                return
        except (AttributeError, IndexError):
            pass


    def _save_node_stats(self, in_tok, out_tok, total_tok):
        # Sumamos al nodo activo
        node_stats = self.node_metrics[self.current_node]
        node_stats["prompt_tokens"] += in_tok
        node_stats["completion_tokens"] += out_tok
        node_stats["total_tokens"] += total_tok

        self.prompt_tokens += in_tok
        self.completion_tokens += out_tok
        self.total_tokens += total_tok

    def reset(self):
        """Reinicia los contadores para la siguiente alerta."""
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.total_tokens = 0
        self.llm_calls = 0
        self.node_metrics = {} 