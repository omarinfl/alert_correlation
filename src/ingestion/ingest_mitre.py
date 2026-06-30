from src.retrieval.embedders import SentenceTransformerEmbedder
from src.retrieval.store import ElasticSearchVectorStore
from mitreattack.stix20 import MitreAttackData
import requests
import os
import re

def limpiar_texto_mitre(texto):
    if not texto:
        return ""
    
    # Eliminar citaciones: (Citation: Nombre Año)
    texto = re.sub(r'\(Citation:\s*[^)]+\)', '', texto)
    
    # Limpiar enlaces Markdown: [Texto](URL) -> Nos quedamos solo con 'Texto'
    texto = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', texto)
    
    # Limpiar espacios en blanco extras 
    texto = re.sub(r'\s+', ' ', texto).strip()
    
    return texto


def obtener_procedimientos(mitre_data, technique_stix_id):
    """Extrae ejemplos reales de software y grupos APT usando la técnica."""
    texto_procedimientos = []
    
    # Software (Malware/Herramientas) que usan la técnica
    try:
        software_using = mitre_data.get_software_using_technique(technique_stix_id)
        for item in software_using:
            desc = ''
            obj = item['object']
            rels = item['relationships']   
            nombre = getattr(obj, 'name', '')
            for rel in rels:
                desc += f'{getattr(rel, 'description', '') }'
            if nombre:
                desc = limpiar_texto_mitre(desc)
                texto_procedimientos.append(f"Software '{nombre}': {desc}")
    except Exception:
        pass

    # Grupos (APTs) que usan la técnica
    try:
        groups_using = mitre_data.get_groups_using_technique(technique_stix_id)
        for item in groups_using:
            desc = ''
            obj = item['object']
            rels = item['relationships']   
            nombre = getattr(obj, 'name', '')
            for rel in rels:
                desc += f'{getattr(rel, 'description', '') }'
            if nombre:
                desc = limpiar_texto_mitre(desc)
                texto_procedimientos.append(f"Group '{nombre}': {desc}")
    except Exception:
        pass

    # Campañas
    try:
        campaigns_using = mitre_data.get_campaigns_using_technique(technique_stix_id)
        for item in campaigns_using:
            desc = ''
            obj = item['object']
            rels = item['relationships']   
            nombre = getattr(obj, 'name', '')
            for rel in rels:
                desc += f'{getattr(rel, 'description', '') }'
            if nombre:
                desc = limpiar_texto_mitre(desc)
                texto_procedimientos.append(f"Campaign '{nombre}': {desc}")
    except Exception:
        pass

    return "\n".join(texto_procedimientos)


def obtener_mitigaciones(mitre_data, technique_stix_id):
    """Extrae las contramedidas y mitigaciones recomendadas por MITRE."""
    texto_mitigaciones = []
    try:
        mitigations = mitre_data.get_mitigations_mitigating_technique(technique_stix_id)
        for item in mitigations:
            desc = ''
            obj = item['object']
            rels = item['relationships']   
            nombre = getattr(obj, 'name', '')
            for rel in rels:
                desc += f'{getattr(rel, 'description', '') }'
            if nombre:
                desc = limpiar_texto_mitre(desc)
                texto_mitigaciones.append(f"Mitigation '{nombre}': {desc}")
    except Exception:
        pass
    return "\n".join(texto_mitigaciones)


def obtener_detecciones(mitre_data, technique_stix_id):
    """
    Recorre las estrategias de detección de una técnica, busca sus analíticas
    asociadas y extrae la descripción técnica real y las queries si existen.
    """
    texto_detecciones = []
    
    try:
        # Obtenemos las estrategias de detección asociadas a la técnica
        strategies = mitre_data.get_detection_strategies_detecting_technique(technique_stix_id)
        
        for item in strategies:
            strategy_obj = item['object']
            strategy_name = getattr(strategy_obj, 'name', '')
            
            # Inicializamos el bloque de texto para esta estrategia
            bloque_estrategia = f"Detection Strategy: {strategy_name}\n"
            
            # Extraemos la lista de IDs de las analíticas asociadas
            analytic_refs = getattr(strategy_obj, 'x_mitre_analytic_refs', [])
            
            # Iteramos por cada analítica para extraer su 'description'
            for ref in analytic_refs:
                analytic_obj = mitre_data.get_object_by_stix_id(ref)
                
                if analytic_obj:
                    analytic_name = getattr(analytic_obj, 'name', '')
                    analytic_desc = getattr(analytic_obj, 'description', '')
                    
                    # Limpiamos la descripción
                    desc_limpia = limpiar_texto_mitre(analytic_desc)
                    
                    bloque_estrategia += f"- Analytic '{analytic_name}': {desc_limpia}\n"
                    
                    if hasattr(analytic_obj, 'x_mitre_rules'):
                        bloque_estrategia += f"  Detection Rules: {analytic_obj.x_mitre_rules}\n"
            
            texto_detecciones.append(bloque_estrategia)
            
    except Exception as e:
        pass
        
    return "\n".join(texto_detecciones)



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

def main():
    print("Inicializando módulos...")
    embedder = SentenceTransformerEmbedder('BAAI/bge-small-en-v1.5')
    vector_store = ElasticSearchVectorStore(index_name='mitre_attack_v3_bge_small_prueba')

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
    mitre_data = MitreAttackData(download_mitre_attack_data())
    techniques = mitre_data.get_techniques(remove_revoked_deprecated=True)  # Filtramos técnicas revocadas o deprecadas

    documents = []
    for t in techniques:
        print(f"Procesando técnica: {t.name}")
        
        description = limpiar_texto_mitre(t.description)
        procedures_txt = obtener_procedimientos(mitre_data, t.id)
        mitigations_txt = obtener_mitigaciones(mitre_data, t.id)
        detections_txt = obtener_detecciones(mitre_data, t.id)
        
        text_to_embed = f'''The technique {t.name}(ID: {mitre_data.get_attack_id(t.id)}) belongs to the {",".join([phase.phase_name for phase in t.kill_chain_phases])} tactics.
                            {description}. It is used on platforms: {t.x_mitre_platforms}'''
        
        text_to_search = f'''{text_to_embed}
                        PROCEDURE EXAMPLES:
                        {procedures_txt}

                        DETECTION STRATEGIES:
                        {detections_txt}
                        '''
        
        doc = {
            'id': t.id,
            'technique_id': mitre_data.get_attack_id(t.id),
            'name': t.name,
            'description': t.description,
            'tactics': [phase.phase_name for phase in t.kill_chain_phases],
            'platforms': t.x_mitre_platforms,
            'is_subtechnique': t.x_mitre_is_subtechnique,
            'external_references': [dict(ref) for ref in t.external_references if ref],
            'mitigations': mitigations_txt,
            'detections': detections_txt,
            'procedures': procedures_txt, 
            'vector': embedder.embed_query(text_to_embed),
            'text_to_search': text_to_search
        }

        documents.append(doc)

        if len(documents) >= 100:
            vector_store.add_documents(documents)
            documents = []
            print("100 Documentos añadidos a la base de datos...")

    if documents:
        vector_store.add_documents(documents)

    print("Base de datos de MITRE ATT&CK lista.")

if __name__ == "__main__":
    main()