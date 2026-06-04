import uuid
import json
from datetime import datetime
from models import AlertLog, EvaluationResult # Tus Pydantic models

class EvaluationRunner:
    def __init__(self, agent, data_saver, dataset_name: str, config: dict):
        self.agent = agent
        self.data_saver = data_saver
        self.dataset_name = dataset_name
        self.config = config
        self.evaluation_id = f"EVAL-{uuid.uuid4().hex[:6].upper()}"

    def run_evaluation(self, dataset_df):
        print(f"🚀 Iniciando Evaluación: {self.evaluation_id}")
        
        total_alerts = 0
        total_time = 0.0
        total_tokens = 0
        total_llm_calls = 0
        
        # Contadores para precisión (simplificados)
        aciertos_mitre = 0
        
        for index, row in dataset_df.iterrows():
            alert_data = json.loads(row['alert_data']) 
            
            # 1. EJECUTAR AGENTE
            final_state, telemetry = self.agent.process_alert(alert_data)
            
            # 2. EXTRAER RESULTADOS
            val_report = final_state.get('validation_report')
            predicted_ttps = [e.item_id for e in val_report.mitre_evaluations if e.decision] if val_report else []
            predicted_cves = [e.item_id for e in val_report.cve_evaluations if e.decision] if val_report else []
            
            real_ttps = alert_data.get('real_ttps', [])
            real_cves = alert_data.get('real_cves', [])
            
            # (Opcional) Guardar informe físico y coger la ruta
            report_path = f"reports/report_{alert_data.get('id', index)}.md"
            
            # 3. CREAR LOG DE ALERTA
            alert_log = AlertLog(
                alert_id=str(alert_data.get('id', index)),
                alert_timestamp=datetime.now(), # Cambia esto por alert_data['timestamp'] parseado
                alert_description=alert_data.get('description', 'No description'),
                predicted_ttps=predicted_ttps,
                predicted_cves=predicted_cves,
                real_ttps=real_ttps,
                real_cves=real_cves,
                report_path=report_path,
                execution_time=telemetry["execution_time"],
                token_usage=telemetry["token_usage"],
                llm_calls=telemetry["llm_calls"],
                # Truco: Convertir el dict a string JSON para que CSVDataSaver no explote
                node_breakdown=json.dumps(telemetry["node_breakdown"]) 
            )
            
            # Guardamos la alerta
            self.data_saver.save_alert_log(alert_log)
            
            # Actualizamos contadores globales
            total_alerts += 1
            total_time += telemetry["execution_time"]
            total_tokens += telemetry["token_usage"]
            total_llm_calls += telemetry["llm_calls"]
            
            # Lógica básica de acierto (Si descubrió al menos un TTP real)
            if any(ttp in real_ttps for ttp in predicted_ttps):
                aciertos_mitre += 1

        # 4. CREAR RESULTADO GLOBAL
        avg_time = total_time / total_alerts if total_alerts > 0 else 0
        mitre_acc = (aciertos_mitre / total_alerts) * 100 if total_alerts > 0 else 0
        
        eval_result = EvaluationResult(
            evaluation_id=self.evaluation_id,
            dataset_name=self.dataset_name,
            agent_config=self.config,
            agent_components={"llm": "tu_llm", "embedder": "tu_embedder"},
            alerts_evaluated=total_alerts,
            mitre_accuracy=mitre_acc,
            cve_accuracy=0.0, # Implementar tu lógica
            total_accuracy=mitre_acc,
            avg_time=round(avg_time, 2),
            avg_tokens=round(total_tokens / total_alerts, 2) if total_alerts > 0 else 0,
            avg_llm_calls=round(total_llm_calls / total_alerts, 2) if total_alerts > 0 else 0
        )
        
        self.data_saver.save_evaluation_result(eval_result)
        print("✅ Evaluación finalizada.")