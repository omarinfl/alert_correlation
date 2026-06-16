import uuid
import json
from datetime import datetime
from src.models.models import AlertLog, EvaluationResult 
import time
import os
import ast

class EvaluationRunner:
    def __init__(self, agent, data_saver, config: dict):
        self.agent = agent
        self.data_saver = data_saver
        self.config = config
        self.evaluation_id = f"EVAL-{uuid.uuid4().hex[:6].upper()}"
        self.evaluation_debug = []

    def run_evaluation(self, dataset_df, dataset_name: str, debug: bool):
        print(f"🚀 Iniciando Evaluación: {self.evaluation_id}")
        
        total_alerts = 0
        total_time = 0.0
        total_tokens = 0
        total_llm_calls = 0
        
        aciertos_mitre = 0
        aciertos_cve = 0
        
        for index, row in dataset_df.iterrows():
            alert_data = json.loads(row.get('alert', '{}')) 
            
            # 1. EJECUTAR AGENTE
            try:
                final_state, telemetry = self.agent.process_alert(alert_data)
            except:
                print('Esperando al modelo...')
                time.sleep(70)
                final_state, telemetry = self.agent.process_alert(alert_data)

            # 2. EXTRAER RESULTADOS
            val_report = final_state.get('validation_report')
            predicted_ttps = [e.item_id for e in val_report.mitre_evaluations if e.decision] if val_report else []
            predicted_cves = [e.item_id for e in val_report.cve_evaluations if e.decision] if val_report else []
            
            real_ttps = ast.literal_eval(row.get('real_ttps', '[]'))
            real_cves = ast.literal_eval(row.get('real_cves', '[]'))

            alert_id = row.get('alert_id', 'unknown_id')
            
            # Guardar informe y la ruta
            report_path = None
            if self.config.generate_report and 'final_report' in final_state:
                report_text = final_state['final_report']
                
                report_dir = f'{self.config.report_dir}/{self.evaluation_id}'
                os.makedirs(report_dir, exist_ok=True)
                report_path = f"{report_dir}/report_{alert_id}.md"
                
                with open(report_path, 'w', encoding='utf-8') as f:
                    f.write(report_text)

            # 3. CREAR LOG DE ALERTA
            alert_log = AlertLog(
                evaluation_id=self.evaluation_id,
                alert_id=str(alert_id),
                alert_timestamp=row.get('timestamp',''), 
                alert_description=row.get('description',''),
                predicted_ttps=predicted_ttps,
                predicted_cves=predicted_cves,
                real_ttps=real_ttps,
                real_cves=real_cves,
                report_path=report_path,
                execution_time=telemetry["execution_time"],
                token_usage=telemetry["token_usage"],
                llm_calls=telemetry["llm_calls"],
                node_breakdown=json.dumps(telemetry["node_breakdown"]),
            )
            
            # Guardamos la alerta
            self.data_saver.save_alert_log(alert_log)
            
            # Actualizamos contadores globales
            total_alerts += 1
            total_time += telemetry["execution_time"]
            total_tokens += telemetry["token_usage"]["total_tokens"]
            total_llm_calls += telemetry["llm_calls"]
            
            # Lógica básica de acierto (Si descubrió al menos un TTP real)
            if any(ttp in real_ttps for ttp in predicted_ttps):
                aciertos_mitre += 1
            
            else: 
                real_parents = [r_ttp.split('.')[0] for r_ttp in real_ttps]
                predicted_parents = [p_ttp.split('.')[0] for p_ttp in predicted_ttps]

                if any(ttp in real_parents for ttp in predicted_parents):
                    aciertos_mitre += 1

            if any(cve in real_cves for cve in predicted_cves):
                            aciertos_cve += 1          

            if debug:
                self.evaluation_debug.append({
                    'original_alert': alert_data,
                    'mitre': {
                        'search': final_state.get('classification').mitre_search,
                        'description': final_state.get('classification').mitre_description,
                        'keywords': final_state.get('classification').mitre_keywords
                    },
                    'cve': {
                        'search': final_state.get('classification').cve_search,
                        'description': final_state.get('classification').cve_description,
                        'keywords': final_state.get('classification').cve_keywords
                    },
                    'retrieved_mitre': final_state.get('mitre_data'),
                    'retrieved_cve': final_state.get('cve_data'),
                    'validation': val_report.model_dump(),
                    'real_ttps': real_ttps,
                    'predicted_ttps': predicted_ttps,
                    'real_cves': real_cves,
                    'predicted_cves': predicted_cves
                })

                    

        # 4. CREAR RESULTADO GLOBAL
        avg_time = total_time / total_alerts if total_alerts > 0 else 0
        mitre_acc = (aciertos_mitre / total_alerts) * 100 if total_alerts > 0 else 0
        cve_acc = (aciertos_cve / total_alerts) * 100 if total_alerts > 0 else 0
        
        eval_result = EvaluationResult(
            evaluation_id=self.evaluation_id,
            dataset_name=dataset_name,
            agent_config=self.config,
            # agent_components={"llm": self.agent.llm.__class__.__name.__, 
            #                   "embedder": self.agent.embedder.__class__.__name.__},
            alerts_evaluated=total_alerts,
            mitre_accuracy=mitre_acc,
            cve_accuracy=cve_acc,
            total_accuracy=mitre_acc,
            avg_time=round(avg_time, 2),
            avg_tokens=round(total_tokens / total_alerts, 2) if total_alerts > 0 else 0,
            avg_llm_calls=round(total_llm_calls / total_alerts, 2) if total_alerts > 0 else 0
        )
        
        self.data_saver.save_evaluation_result(eval_result)
        if debug:
            with open(f'notes/{self.evaluation_id}_debug.json', 'w', encoding='utf-8') as file:
                json.dump(self.evaluation_debug, file, indent=4, ensure_ascii=False)
        print("✅ Evaluación finalizada.")