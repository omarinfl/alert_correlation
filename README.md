# SOC-Agent: Correlación de Alertas con MITRE ATT&CK y CVE
Este repositorio contiene el código completo del Trabajo de Fin de Máster (TFM): *"Diseño y Desarrollo de Arquitectura basada en IA para la Correlación de Alertas con el Framework MITRE ATT&CK y Vulnerabilidades CVE"*.

El proyecto implementa un Agente SOC automatizado utilizando grafos de estado (LangGraph) y un motor de Generación Aumentada por Recuperación (RAG) híbrido. Su objetivo es mitigar la fatiga de alertas, realizando la correlación de inteligencia con las fuentes de conocimiento MITRE ATT&CK y CVE de forma automatizada. 

El agente recibe una alerta de ciberseguridad, la procesa para definir las búsquedas del motor RAG, solicita conciencia situacional mediante ventanas de contexto temporal y, valida los resultados recuperados y, por último, genera un reporte accionable y explicable.

## Características Principales
- **Mitigación de fatiga de alertas:** Al realizar la correlación automática, proporciona al analista información procesable, reduciendo su carga en el análisis. Además, cuenta con un nodo Clasificador, capaz de descartar ruido operacional para ahorrar recursos computacionales.
- **Conciencia Situacional:** Implementa la posibilidad de recuperar una ventana de contexto temporal, incluyendo en el análisis las alertas previas y posteriores para tomar decisiones basadas en un contexto completo, y no evaluar únicamente el incidente aislado.
- **Motor RAG Híbrido:** La búsqueda en la base de datos vectorial se define de forma asimétrica, combinando búsqueda vectorial (*Embeddings*) con léxica (BM25) para optimizar la recuperación de resultados relevantes.
- **Arquitectura Dual de Reporte**: Genera informes forenses que separan las evidencias verificadas por RAG de las inferencias realizadas por el LLM, mitigando las alucinaciones.

## Estructura del Proyecto
```
alert_correlation/
├── data/               # Datasets utilizados (alertas, CVEs sintéticos, escenarios).
├── evaluations/        # Resultados de las evaluaciones y métricas finales.
├── examples/           # Ejemplos de informes generados (.md) y depuración (.json).
├── notebooks/          # Jupyter Notebooks de pruebas y limpieza de datos.
├── src/                # Código fuente principal de la aplicación:
│   ├── agent/          # Lógica de LangGraph, nodos (Clasificador, Validador...) y LLMs.
│   ├── evaluation/     # Módulos para evaluación, guardado de resultados y cálculo de métricas.
│   ├── ingestion/      # Scripts para vectorizar e indexar MITRE y CVEs.
│   ├── models/         # Esquemas Pydantic para salidas estructuradas y el Estado del Agente.
│   └── retrieval/      # Conexión con Elasticsearch, Embeddings y recuperador de contexto temporal.
├── main.py             # Ejecución del sistema (evaluaciones o alertas individuales).
├── docker-compose.yml  # Despliegue de Elasticsearch y Kibana.
└── pyproject.toml      # Gestión de dependencias (vía uv).
```

## Guía de Instalación y Utilización
### 1. Requisitos Previos
* **Docker** (para Elasticsearch y Kibana).
* **Python** 3.10 o superior.
* **uv** (para la gestión del entorno y dependencias).

### 2. Clonar el repositorio e instalar dependencias
```bash
git clone https://github.com/omarinfl/alert_correlation.git
cd alert_correlation

# Sincronizar el entorno virtual e instalar las dependencias automáticamente
uv sync
```

### 3. Configuración del Entorno (.env)
Crea un archivo `.env` en la raíz del proyecto. Debes configurar tus claves de API o la configuración de los LLMs que se vayan a utilizar.

* **Si se utiliza Gemini como LLM:**
    * `GEMINI_TOKEN=<tu_api_key_de_gemini>`


* **Si se utiliza LLM personalizado (local):**
    * `MODEL_NAME=<nombre_del_modelo>`
    * `MODEL_ENDPOINT=<endpoint_url>`


* **Si se quiere monitorizar con LangSmith:**
    * `LANGCHAIN_API_KEY=<tu_api_key_de_langchain>`
    * `LANGCHAIN_TRACING_V2='true'`
    * `LANGCHAIN_PROJECT=<tu_nombre_de_proyecto>`


* **Si se descargan modelos de HuggingFace:**
    * `HF_TOKEN=<tu_api_key_de_hf>`


### 4. Desplegar la Infraestructura

Ejecutar desde la raíz del proyecto (o directorio en el que se encuentre el archivo `docker-compose.yml`):

```bash
docker-compose up -d
```

### 5. Creación e Ingesta de las Bases de Conocimiento
Ejecutar los scripts automatizados:

```bash
uv run -m src.ingestion.ingest_mitre
uv run -m src.ingestion.ingest_cve
```
*Nota: Si se quiere cambiar el modelo de embeddings, el tamaño de los vectores, el servicio de base de datos o la estructura de los documentos, se puede cambiar en estos archivos. Para los embeddings o la base de datos, basta con intercambiar la clase instanciada por su equivalente. Otros cambios requerirían implementar la lógica concreta.*


### 6. Ejecución del Agente
La ejecución de la arquitectura se realiza mediante el fichero `main.py`. Se debe configurar cada uno de los componentes y las opciones de ejecución:

* **Configuración del Agente (`config`):**
    * `use_context_window`: `True`/`False` -> Si se quiere incluir contexto temporal o analizar una alerta aislada.
    * `context_window_size`: `int` -> Tamaño de la ventana a recuperar (número de alertas de contexto).
    * `context_mode`: `'PAST'`/`'AROUND'` -> Únicamente alertas previas (`'PAST'`) o previas y posteriores (`'AROUND'`).
    * `generate_report`: `True`/`False` -> Si se quiere generar el reporte final.
    * `report_dir`: `path` -> Directorio en el que guardar el reporte.
    * `mitre_top_k`: `int` -> Número de técnicas a recuperar por el motor de búsqueda.


* **LLMs:**
    * `llm_strict`: Instancia de LLM con temperatura `0.0`, para tareas más deterministas.
    * `llm_creative`: Instancia de LLM con temperatura mayor a `0.0`, para tareas más creativas.

    ```python
    # Ejemplo con Gemini 3.1 Flash Lite (API)
    from langchain_google_genai import ChatGoogleGenerativeAI
    from dotenv import load_dotenv
    import os

    load_dotenv()
    API_KEY = os.getenv('GEMINI_TOKEN')

    gemini_llm = ChatGoogleGenerativeAI(
        model='gemini-3.1-flash-lite', 
        api_key=API_KEY, 
        temperature=0.2, 
        seed=42
    )

    # Ejemplo con modelo local
    from langchain_openai import ChatOpenAI

    local_llm = ChatOpenAI(
        model=os.getenv('MODEL_NAME'),
        api_key='EMPTY',
        temperature=0.0,
        seed=42,
        base_url=os.getenv('MODEL_ENDPOINT'),
    )
    ```

* **Embedder:** Elección del modelo de embeddings. Utilizar clase construida en `retrieval/embedders.py`.
* **Bases Vectoriales:** Elección de las bases de datos vectoriales. Utilizar clase construida en `retrieval/store.py`.
    * `mitre_store`: Instancia del índice de MITRE ATT&CK.
    * `cve_store`: Instancia del índice de CVE.

* **Repositorio de alertas:** Elección de la fuente de alertas de contexto. Utilizar la clase construida en `retrieval/alert_repository.py`.
* **Tracker:** Instanciación del medidor de telemetría del agente (`UniversalTokenTracker`).
* **Agente:** Iniciación del agente con todos los módulos y configuración definidas.

Se puede ejecutar el agente para un análisis aislado o para realizar una evaluación. Esta lógica y presentación de los datos finales se determina en `main.py`.

#### Análisis Individual
En caso de querer el análisis individual de una alerta:

```python
alert = {...} # Alerta en formato .json

# Se obtiene el estado final y la telemetría de la ejecución
final_state, telemetry = agent.process_alert(alert)

# Lógica de obtención y presentación de resultados:
# Ejemplo: Imprimir predicciones y reporte final
val_report = final_state.get('validation_report')
predicted_ttps = [e.item_id for e in val_report.mitre_evaluations if e.decision] if val_report else []
predicted_cves = [e.item_id for e in val_report.cve_evaluations if e.decision] if val_report else []
        
print(f'Predicted TTPs: {predicted_ttps}')
print(f'Predicted CVEs: {predicted_cves}')

report_text = final_state.get('final_report')
print('Final Report:')
print(report_text)
```
#### Ejecución de una Evaluación

Para ejecutar una evaluación sobre un dataset completo con el módulo evaluador, se deben definir:

* **Guardado de los resultados:** Elección del módulo de almacenamiento de resultados (`evaluation/data_saver.py`).
* **Evaluador:** Instanciar el evaluador, con el agente, su configuración y el módulo de guardado.
* **Dataset:** DataFrame de Pandas con el dataset de alertas sobre el que lanzar la evaluación.

```python
import pandas as pd

# Definir el guardado de los datos
data_saver = CSVDataSaver(alerts_csv_path='ruta_a_csv_alertas', evaluations_csv_path='ruta_a_csv_evaluaciones')
    
# Definir el evaluador
evaluator = EvaluationRunner(agent, data_saver, config)

# Cargar dataset
df = pd.read_csv('ruta_al_dataset', parse_dates=['timestamp']) 

# Ejecutar evaluación
evaluator.run_evaluation(df, dataset_name='Nombre Dataset', debug=True) # Debug activado (guarda archivo JSON)
```

Con todo configurado, el agente se ejecuta desde el directorio raíz con el comando:

```bash
uv run main.py
```


## Ejemplos
En el directorio `examples/` se encuentran ejemplos de reportes finales obtenidos en la fase de evaluación, así como el *debug* de las ejecuciones por si se quieren explorar las decisiones internas del agente. Se incluyen las ejecuciones de:

* Gemini con top 10 y contexto activado para TTPs de MITRE.
* Gemma con top 10 y contexto activado para TTPs de MITRE.
* Gemini con top 5 sin contexto para CVEs.
* Escenarios 1, 2 y 3 evaluados con Gemini (top 10).

## Autoría
* **Trabajo realizado por:** Óscar Marín Flores
* **Año:** 2026