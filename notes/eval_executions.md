# MITRE (unique_alerts)
EVAL-E97A66: Con gemini, sin ventana de contexto, los datos en forma de diccionario, temperaturas 0 y 0.2
EVAL-161304: Con gemini, ventana de contexto, los datos en forma de diccionario, temperaturas 0 y 0.2
EVAL-BC7AB0: Prueba de incluir la paranoia en el clasificador para que sea menos estricto a la hora de no buscar
EVAL-0902E3: Con gemini, ventana de contexto, los datos en forma de diccionario, temperaturas 0 y 0.2 (vuelta a version anterior)
EVAL-95CDBB: Con gemini, version anterior con ajuste en el prompt para centrarse en el comportamiento y tener en cuenta que puede ser normal, sin contexto
EVAL-602432: Con gemini, version anterior con ajuste en el prompt para centrarse en el comportamiento y tener en cuenta que puede ser normal, con contexto (around,4)
EVAL-6AE96C: Con gemma, version definitiva, contexto (around,4)
EVAL-24C610: Lo mismo, pero solo primer párrafo de la descripción (anterior falló por exceso de tokens)
EVAL-04D59B: Lo mismo, reduciendo tokens también en reporte (solo primer parrafo descripcion, quitado referencias CVEs)
EVAL-0B5CB3: Gemini con la reduccion de tokens
EVAL-86CB9E: Gemini con top_k=5 y descripciones completas
EVAL-932282: Gemma con top_k=5 y descripciones completas
EVAL-AA144A: Gemma con top_k=5 y sin contexto
EVAL-B068F6: Gemma con top_k=10 y sin contexto (descripciones cortadas)
# CVE
EVAL-A4AD8D: Evaluación sobre los datos de CVE con gemini
EVAL-D2C29A: Evaluación sobre los datos de CVE con gpt-oss
EVAL-A3747E: Evaluación sobre los datos de CVE con gemini, utilizando prompt refinado para no inferir en la clasificación (AlertClassification2)
EVAL-894CB6: Evaluación sobre los datos de CVE con gemma, sin generación de reportes