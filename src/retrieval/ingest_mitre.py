from embedders import SentenceTransformerEmbedder
from store import ElasticSearchVectorStore
from mitreattack.stix20 import MitreAttackData

print("Inicializando módulos...")
embedder = SentenceTransformerEmbedder()
vector_store = ElasticSearchVectorStore(index_name='mitre_attack')

print("Preparando la base de datos...")
mitre_columns = {
    'name': {'type': 'text'},
    'description': {'type': 'text'},
    'tactics': {'type': 'keyword'},
    'platforms': {'type': 'keyword'},
    'technique_id': {'type': 'keyword'}
}

vector_store.initialize(dims=384, custom_columns=mitre_columns)

print("Cargando datos de MITRE ATT&CK...")
mitre_data = MitreAttackData('data/enterprise-attack.json')
techniques = mitre_data.get_techniques()

documents = []
for t in techniques:
    if getattr(t, 'description', None) is None or t.revoked or t.x_mitre_deprecated:
        continue

    print(f"Procesando técnica: {t.name}")
    doc = {
        'id': t.id,
        'technique_id': mitre_data.get_attack_id(t.id),
        'name': t.name,
        'description': t.description,
        'tactics': [phase.phase_name for phase in t.kill_chain_phases],
        'platforms': t.x_mitre_platforms,
        'is_subtechnique': t.x_mitre_is_subtechnique,
        'detection': t.x_mitre_detection,
        'external_references': [dict(ref) for ref in t.external_references if ref],
        'vector': embedder.embed_query(t.description)
    }

    documents.append(doc)

    if len(documents) >= 100:
        vector_store.add_documents(documents)
        documents = []
        print("100 Documentos añadidos a la base de datos...")

if documents:
    vector_store.add_documents(documents)

print("Base de datos de MITRE ATT&CK lista.")