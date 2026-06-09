from embedders import SentenceTransformerEmbedder, LocalvLLMEmbedder
from store import ElasticSearchVectorStore
from mitreattack.stix20 import MitreAttackData
import requests
import os

def download_mitre_attack_data():
    '''Descarga el archivo MITRE ATT&CK desde GitHub solo si hay una nueva versión disponible.'''
    url = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json'
    download_dir = 'data'

    etag_filepath = os.path.join(download_dir, 'enterprise-attack.json.etag')
    stix_filepath = os.path.join(download_dir, 'enterprise-attack.json')

    print("Verificando si hay una nueva versión del archivo MITRE ATT&CK...")
    try:
        req = requests.head(url)
        if req.status_code == 200:
            remote_etag = req.headers.get('ETag')
            if os.path.exists(etag_filepath):
                with open(etag_filepath, 'r') as f:
                    local_etag = f.read().strip()
                if local_etag == remote_etag:
                    print("El archivo MITRE ATT&CK ya está actualizado. No se necesita descargar.")
                    return stix_filepath
                else:
                    print("Hay una nueva versión del archivo MITRE ATT&CK. Descargando...")
            else:
                print("No se encontró un archivo ETag local. Descargando el archivo MITRE ATT&CK...")

            response = requests.get(url)
            if response.status_code == 200:
                with open(stix_filepath, 'w') as f:
                    f.write(response.text)
                with open(etag_filepath, 'w') as f:
                    f.write(remote_etag)
                print("Archivo MITRE ATT&CK descargado y actualizado exitosamente.")
                return stix_filepath
            else:
                print(f"Error al descargar el archivo: {response.status_code}")
                return None
        else:
            print(f"Error al verificar el archivo: {req.status_code}")
            return None
        
    except Exception as e:
        print(f"Error al verificar o descargar el archivo MITRE ATT&CK: {e}")
        return None

print("Inicializando módulos...")
embedder = SentenceTransformerEmbedder()
vector_store = ElasticSearchVectorStore(index_name='mitre_attack_v2')

# embedder = LocalvLLMEmbedder()
# vector_store = ElasticSearchVectorStore(index_name='mitre_attack_bge')

print("Preparando la base de datos...")
mitre_columns = {
    'name': {'type': 'text'},
    'description': {'type': 'text'},
    'tactics': {'type': 'keyword'},
    'platforms': {'type': 'keyword'},
    'technique_id': {'type': 'keyword'}
}

vector_store.initialize(dims=384, custom_columns=mitre_columns)
# vector_store.initialize(dims=1024, custom_columns=mitre_columns)


print("Cargando datos de MITRE ATT&CK...")
mitre_data = MitreAttackData(download_mitre_attack_data())
techniques = mitre_data.get_techniques(remove_revoked_deprecated=True)  # Filtramos técnicas revocadas o deprecadas

documents = []
for t in techniques:
    print(f"Procesando técnica: {t.name}")
    text_to_embed = f'''ID: {mitre_data.get_attack_id(t.id)}.
                        Name: {t.name}.
                        Tactics: {",".join([phase.phase_name for phase in t.kill_chain_phases])}.
                        Description: {t.description}.
                        Platforms: {t.x_mitre_platforms}'''
    
    
    doc = {
        'id': t.id,
        'technique_id': mitre_data.get_attack_id(t.id),
        'name': t.name,
        'description': t.description,
        'tactics': [phase.phase_name for phase in t.kill_chain_phases],
        'platforms': t.x_mitre_platforms,
        'is_subtechnique': t.x_mitre_is_subtechnique,
        'external_references': [dict(ref) for ref in t.external_references if ref],
        'vector': embedder.embed_query(text_to_embed)
    }

    documents.append(doc)

    if len(documents) >= 100:
        vector_store.add_documents(documents)
        documents = []
        print("100 Documentos añadidos a la base de datos...")

if documents:
    vector_store.add_documents(documents)

print("Base de datos de MITRE ATT&CK lista.")