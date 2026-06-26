import pandas as pd
import ast
import json

mitre_evaluations = {
    'gemini-top-5-no-context': 'EVAL-3CC2EE',
    'gemini-top-5-context': 'EVAL-86CB9E',
    'gemini-top-10-no-context': 'EVAL-3548AF',
    'gemini-top-10-context': 'EVAL-46BA4E',
    'gemma-top-5-no-context': 'EVAL-AA144A',
    'gemma-top-5-context': 'EVAL-932282',
    'gemma-top-10-no-context': 'EVAL-B068F6',
    'gemma-top-10-context': 'EVAL-04D59B',
}

cve_evaluations = {
    'gemini-top-5': 'EVAL-79E93D',
    'gemini-top-10': 'EVAL-A4AD8D',
    'gemma-top-5': 'EVAL-91315F',
    'gemma-top-10': 'EVAL-D1F60D',
}

# Invertir diccionarios para hacer el mapeo al final (Id -> Nombre Legible)
id_to_name_ttp = {v: k for k, v in mitre_evaluations.items()}
id_to_name_cve = {v: k for k, v in cve_evaluations.items()}

# Funciones auxiliares de lectura
def safe_parse_list(val):
    try:
        return ast.literal_eval(val) if pd.notnull(val) else []
    except: return []

def safe_parse_dict(val):
    try:
        val = val.replace("'", '"')
        return json.loads(val) if pd.notnull(val) else {}
    except: return {}

# Carga del dataset original
df_raw = pd.read_csv('evaluations/alerts_results.csv')


# Cálculo sobre TTPs
# Filtrar ANTES de procesar
df_ttp = df_raw[df_raw['evaluation_id'].isin(id_to_name_ttp.keys())].copy()

# Parsear solo lo necesario
df_ttp['pred_ttps_list'] = df_ttp['predicted_ttps'].apply(safe_parse_list)
df_ttp['real_ttps_list'] = df_ttp['real_ttps'].apply(safe_parse_list)
df_ttp['token_dict'] = df_ttp['token_usage'].apply(safe_parse_dict)
df_ttp['total_tokens'] = df_ttp['token_dict'].apply(lambda x: x.get('total_tokens', 0))

def evaluate_ttps(row):
    pred_ttps = row['pred_ttps_list']
    real_ttps = row['real_ttps_list']
    
    if not real_ttps: return pd.Series([None, None, None, None, None, None, 0.0, 0.0, 0, 0])
    if not pred_ttps: return pd.Series([0, 0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0, len(real_ttps)])

    has_exact, has_sub, has_parent = False, False, False
    pred_families = set(p.split('.')[0] for p in pred_ttps)
    real_families = set(r.split('.')[0] for r in real_ttps)

    valid_preds_score = 0.0
    for p in pred_ttps:
        p_family = p.split('.')[0]
        if p_family in real_families:
            valid_preds_score += 1.0
            
            if p in real_ttps:
                has_exact = True
            else:
                matching_reals = [r for r in real_ttps if r.split('.')[0] == p_family]
                if p_family in matching_reals:
                    has_sub = True
                else:
                    has_parent = True

    macro_precision = valid_preds_score / len(pred_ttps)
    recall_score = sum(1.0 for r in real_ttps if r.split('.')[0] in pred_families)
    macro_recall = recall_score / len(real_ttps)
    
    hit_exact = 1 if has_exact else 0
    hit_sub = 1 if (not has_exact and has_sub) else 0
    hit_parent = 1 if (not has_exact and not has_sub and has_parent) else 0
    hit_total = 1 if (hit_exact or hit_sub or hit_parent) else 0

    return pd.Series([
        hit_total, hit_exact, hit_parent, hit_sub, 
        macro_recall, macro_precision, 
        valid_preds_score, recall_score, len(pred_ttps), len(real_ttps)
    ])

df_ttp[['hr_total', 'hr_exact', 'hr_parent', 'hr_sub', 
        'macro_recall', 'macro_precision', 
        'ttp_valid_score', 'ttp_recall_score', 'ttp_pred_count', 'ttp_real_count']] = df_ttp.apply(evaluate_ttps, axis=1)

summary_ttp = df_ttp.groupby('evaluation_id').agg(
    total_alerts=('alert_id', 'count'),

    # Hit Rate Desglosado por Alerta (Calculamos la media de los 0s y 1s para obtener el %)
    hr_total=('hr_total', 'mean'),
    hr_exact=('hr_exact', 'mean'),
    hr_parent=('hr_parent', 'mean'),
    hr_sub=('hr_sub', 'mean'),

    # Macro-métricas
    macro_recall=('macro_recall', 'mean'),
    macro_precision=('macro_precision', 'mean'),

    # Sumas para calcular las Micro-métricas globales
    sum_valid_score=('ttp_valid_score', 'sum'),
    sum_recall_score=('ttp_recall_score', 'sum'),
    sum_pred_count=('ttp_pred_count', 'sum'),
    sum_real_count=('ttp_real_count', 'sum'),

    # Rendimiento
    avg_time_s=('execution_time', 'mean'),
    avg_tokens=('total_tokens', 'mean')
).reset_index()

summary_ttp['micro_recall'] = summary_ttp['sum_recall_score'] / summary_ttp['sum_real_count']
summary_ttp['micro_precision'] = summary_ttp['sum_valid_score'] / summary_ttp['sum_pred_count']

cols_to_percent = ['hr_total', 'hr_exact', 'hr_parent', 'hr_sub', 'macro_recall', 'micro_recall', 'macro_precision', 'micro_precision']
for col in cols_to_percent: summary_ttp[col] = (summary_ttp[col] * 100).round(2)

summary_ttp = summary_ttp.drop(columns=['sum_valid_score', 'sum_recall_score', 'sum_pred_count', 'sum_real_count'])
summary_ttp['configuracion'] = summary_ttp['evaluation_id'].map(id_to_name_ttp)
summary_ttp['Modelo'] = summary_ttp['configuracion'].apply(lambda x: 'Gemini' if 'gemini' in x else 'Gemma')
summary_ttp['Top-k'] = summary_ttp['configuracion'].apply(lambda x: 10 if '10' in x else 5)
summary_ttp['Contexto'] = summary_ttp['configuracion'].apply(lambda x: False if 'no-context' in x else True)

metric_cols_ttp = [c for c in summary_ttp.columns if c not in ['evaluation_id', 'configuracion', 'Modelo', 'Top-k', 'Contexto']]
final_ttp = summary_ttp[['Modelo', 'Top-k', 'Contexto'] + metric_cols_ttp].sort_values(by=['Top-k', 'Modelo', 'Contexto'], ascending=[True, True, True]).reset_index(drop=True)

# Guardar Resultados TTP
final_ttp.to_csv('evaluations/mitre_evaluation.csv', index=False)
print("TTPs calculados y guardados exitosamente.\n")


# Cálculo sobre CVEs

df_cve = df_raw[df_raw['evaluation_id'].isin(id_to_name_cve.keys())].copy()

df_cve['pred_cves_list'] = df_cve['predicted_cves'].apply(safe_parse_list)
df_cve['real_cves_list'] = df_cve['real_cves'].apply(safe_parse_list)
df_cve['token_dict'] = df_cve['token_usage'].apply(safe_parse_dict)
df_cve['total_tokens'] = df_cve['token_dict'].apply(lambda x: x.get('total_tokens', 0))

def evaluate_cves(row):
    pred_cves = row['pred_cves_list']
    real_cves = row['real_cves_list']
    
    if not real_cves: return pd.Series([None, None, None, 0.0, 0.0, 0, 0])
    if not pred_cves: return pd.Series([0, 0.0, 0.0, 0.0, 0.0, 0, len(real_cves)])

    pred_set, real_set = set(pred_cves), set(real_cves)
    exact_hits_count = len(pred_set.intersection(real_set))

    macro_precision = exact_hits_count / len(pred_cves)
    macro_recall = exact_hits_count / len(real_cves)
    hit_total = 1 if exact_hits_count > 0 else 0

    return pd.Series([
        hit_total, macro_recall, macro_precision, 
        exact_hits_count, exact_hits_count, len(pred_cves), len(real_cves)
    ])

df_cve[['cve_hr_total', 'macro_recall', 'macro_precision', 
        'cve_valid_score', 'cve_recall_score', 'cve_pred_count', 'cve_real_count']] = df_cve.apply(evaluate_cves, axis=1)

summary_cve = df_cve.groupby('evaluation_id').agg(
    total_alerts=('alert_id', 'count'),
    
    # Hit Rate general (Al no haber jerarquía, el Total es igual al Exacto)
    cve_hr_total=('cve_hr_total', 'mean'),

    # Macro-métricas
    macro_recall=('macro_recall', 'mean'),
    macro_precision=('macro_precision', 'mean'),

    # Sumas para calcular las Micro-métricas globales
    sum_valid_score=('cve_valid_score', 'sum'),
    sum_recall_score=('cve_recall_score', 'sum'),
    sum_pred_count=('cve_pred_count', 'sum'),
    sum_real_count=('cve_real_count', 'sum'),

    # Rendimiento
    avg_time_s=('execution_time', 'mean'),
    avg_tokens=('total_tokens', 'mean')
).reset_index()

summary_cve['micro_recall'] = summary_cve['sum_recall_score'] / summary_cve['sum_real_count']
summary_cve['micro_precision'] = summary_cve['sum_valid_score'] / summary_cve['sum_pred_count']

cols_to_percent_cve = ['cve_hr_total', 'macro_recall', 'micro_recall', 'macro_precision', 'micro_precision']
for col in cols_to_percent_cve: summary_cve[col] = (summary_cve[col] * 100).round(2)

summary_cve = summary_cve.drop(columns=['sum_valid_score', 'sum_recall_score', 'sum_pred_count', 'sum_real_count'])
summary_cve['configuracion'] = summary_cve['evaluation_id'].map(id_to_name_cve)
summary_cve['Modelo'] = summary_cve['configuracion'].apply(lambda x: 'Gemini' if 'gemini' in x else 'Gemma')
summary_cve['Top-k'] = summary_cve['configuracion'].apply(lambda x: 10 if '10' in x else 5)
summary_cve['Contexto'] = summary_cve['configuracion'].apply(lambda x: False )

metric_cols_cve = [c for c in summary_cve.columns if c not in ['evaluation_id', 'configuracion', 'Modelo', 'Top-k', 'Contexto']]
final_cve = summary_cve[['Modelo', 'Top-k', 'Contexto'] + metric_cols_cve].sort_values(by=['Top-k', 'Modelo', 'Contexto'], ascending=[True, False, False]).reset_index(drop=True)

# Guardar Resultados CVE
final_cve.to_csv('evaluations/cve_evaluation.csv', index=False)
print("CVEs calculados y guardados exitosamente.")
