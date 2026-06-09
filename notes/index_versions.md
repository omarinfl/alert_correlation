# Mitre Index
vector_store = ElasticSearchVectorStore(index_name='mitre_attack')
embedder = SentenceTransformerEmbedder()
mitre_columns = {
    'name': {'type': 'text'},
    'description': {'type': 'text'},
    'tactics': {'type': 'keyword'},
    'platforms': {'type': 'keyword'},
    'technique_id': {'type': 'keyword'}
}

doc = {
        'id': t.id,
        'technique_id': mitre_data.get_attack_id(t.id),
        'name': t.name,
        'description': t.description,
        'tactics': [phase.phase_name for phase in t.kill_chain_phases],
        'platforms': t.x_mitre_platforms,
        'is_subtechnique': t.x_mitre_is_subtechnique,
        'external_references': [dict(ref) for ref in t.external_references if ref],
        'vector': embedder.embed_query(t.description)
    }

# Mitre Index v2
mitre_columns = {
    'name': {'type': 'text'},
    'description': {'type': 'text'},
    'tactics': {'type': 'keyword'},
    'platforms': {'type': 'keyword'},
    'technique_id': {'type': 'keyword'}
}

text_to_embed = f'''The technique {t.name}(ID: {mitre_data.get_attack_id(t.id)}) belongs to the {",".join([phase.   phase_name for phase in t.kill_chain_phases])} tactics. {t.description}. It is used on platforms: {t.x_mitre_platforms}'''

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

# Mitre Index v3

