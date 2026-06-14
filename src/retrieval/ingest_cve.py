from embedders import SentenceTransformerEmbedder
from store import ElasticSearchVectorStore
import requests
import os
import zipfile
from tqdm import tqdm
import json

MIN_CVSS_SCORE = 7.0    # Solo se incluyen CVEs con CVSS >= 7.0 hasta el año ALL_YEAR
ALL_YEAR = 2023         # A partir de este año se incluyen todos los CVEs

def get_kev_cves():
    '''Obtiene la lista de CVEs del KEV de CISA.'''
    url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            
            kev_dict = {}
            for vul in data.get('vulnerabilities', []):
                kev_dict[vul['cveID']] = {
                    'vulnerabilityName': vul.get('vulnerabilityName', ''),
                    'shortDescription': vul.get('shortDescription', ''),
                    'requiredAction': vul.get('requiredAction', ''),
                }
                
            return kev_dict
        else:
            print(f"Error al obtener los CVEs del KEV: {response.status_code}")
            return []
    except Exception as e:
        print(f"Error al obtener los CVEs del KEV: {e}")
        return []


def download_cve_data():
    '''Descarga el ZIP completo de CVEs'''
    url = 'https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip'
    download_dir = 'data'
    zip_filepath = os.path.join(download_dir, 'cvelistV5-main.zip')
    if not os.path.exists(zip_filepath):
        print("Descargando el archivo ZIP de CVEs...")
        try:
            response = requests.get(url)
            if response.status_code == 200:
                with open(zip_filepath, 'wb') as f:
                    f.write(response.content)
                print("Archivo ZIP de CVEs descargado exitosamente.")
                return zip_filepath
            else:
                print(f"Error al descargar el archivo ZIP: {response.status_code}")
                return None
        except Exception as e:
            print(f"Error al descargar el archivo ZIP de CVEs: {e}")
            return None
    else:
        print("El archivo ZIP de CVEs ya existe. No se necesita descargar.")
        return zip_filepath
    

def get_adp_metrics_refs(adp: list):
    metrics = []
    references = []
    for adp_item in adp:
        metrics.extend(adp_item.get("metrics", []))
        references.extend(adp_item.get("references", []))
    return metrics, references


def extract_cvss(metrics):
    cvss_keys = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]
    for key in cvss_keys:
        for metric in metrics:
            if key in metric:
                cvss = metric[key]
                return {
                    "score": cvss.get("baseScore"),
                    "severity": cvss.get("baseSeverity"),
                    "vector": cvss.get("vectorString")
                }
    return {"score": 0.0, "severity": None, "vector": None}



def extract_ssvc(metrics):
    """
    Extrae los campos SSVC (Explotation, Automatable, Technical Impact) de la lista de métricas.
    """
    for metric in metrics:
        other = metric.get("other", {})
        if other.get("type") == "ssvc":
            options = other.get("content", {}).get("options", [])
            ssvc = {}
            for opt in options:
                ssvc.update(opt)
            return {
                "Explotation": ssvc.get("Exploitation"),
                "Automatable": ssvc.get("Automatable"),
                "Technical Impact": ssvc.get("Technical Impact")
            }
    return {"Explotation": None, "Automatable": None, "Technical Impact": None}

def process_cve(cve_json, kev_cves):
    
    metadata = cve_json.get('cveMetadata', {})
    
    # Versión rápida para evitar indexar 150k (solo kev)
    if not metadata.get('cveId', '') in kev_cves:
       return None
    
    not_published = []
    if metadata.get('state') != 'PUBLISHED':
        not_published.append(metadata.get('cveId', 'Unknown CVE ID'))
        return None
    
    cna = cve_json.get('containers', {}).get('cna', {})
    
    adp = cve_json.get('containers', {}).get('adp', [])
    adp_metrics, adp_references = get_adp_metrics_refs(adp)

    cve_id = metadata.get('cveId', '')
    in_kev = cve_id in kev_cves

    metrics = cna.get('metrics', []) + adp_metrics
    cvss = extract_cvss(metrics)
    if not in_kev:
        cve_year = int(cve_id.split('-')[1]) if '-' in cve_id else 0

        if cvss['score'] < MIN_CVSS_SCORE and cve_year < ALL_YEAR:
            return None
    
    kev_json = kev_cves.get(cve_id, {})
    references = cna.get('references', []) + adp_references

    kev_mitigation = kev_json.get('requiredAction', None)
    cve_mitigations = [r["url"] for r in references if "mitigation" in r.get("tags", []) or "patch" in r.get("tags", [])]
    cve_mitigations = f'Consultar las referencias: {", ".join(cve_mitigations)}' if len(cve_mitigations) > 0 else 'Not mitigations found in references.'
    
    mitigations = ' '.join([kev_mitigation, cve_mitigations]) if kev_mitigation else cve_mitigations

    doc = {
        'id': cve_id,
        'title': kev_json.get('vulnerabilityName', cna.get('title', '')),
        'description': cna.get('descriptions', '')[0].get('value', '') if cna.get('descriptions') else '',
        'published_date': metadata.get('datePublished', ''),
        'cvss': extract_cvss(metrics),
        'affected_products': [(product.get('vendor', ''), product.get('product', '')) for product in cna.get('affected', []) if product],
        'versions': json.dumps(cna.get('affected', [])),
        'mitigations': mitigations,
        'ssvc': extract_ssvc(metrics),
        'references': json.dumps(references),
        'in_kev': in_kev,
    }

    return doc




def main():
    print("Inicializando módulos...")
    embedder = SentenceTransformerEmbedder('BAAI/bge-small-en-v1.5')
    vector_store = ElasticSearchVectorStore(index_name='kev_cve_index_bge')

    print("Preparando la base de datos...")
    cve_columns = {
        'id': {'type': 'keyword'},
        'title': {'type': 'keyword'},
        'description': {'type': 'text'},
        'published_date': {'type': 'date'},
        'cvss': {
            'properties':{
                'score': {'type': 'float'},
                'severity': {'type': 'keyword'},
                'vector': {'type': 'keyword'}
            }
        },
        'affected_products': {'type': 'keyword'},
        'versions': {'type': 'text'},
        'mitigations': {'type': 'text'},
        'ssvc': {
            'properties': {
                'Explotation': {'type': 'keyword'},
                'Automatable': {'type': 'keyword'},
                'Technical Impact': {'type': 'keyword'}
            }
        },
        'references': {'type': 'text'},
        'in_kev': {'type': 'boolean'}
    }
    
    vector_store.initialize(dims=384, custom_columns=cve_columns)

    print("Obteniendo CVEs del KEV...")
    kev_cves = get_kev_cves()

    print("Descargando datos de CVEs...")
    zip_filepath = download_cve_data()


    documents = []
    with zipfile.ZipFile(zip_filepath, 'r') as zip_ref:
        json_files = [f for f in zip_ref.namelist() if f.endswith('.json') and 'cves/' in f]
        for json_file in tqdm(json_files[:-2], desc="Procesando CVEs"):
            with zip_ref.open(json_file) as f:
                cve_json = json.load(f)
                doc = process_cve(cve_json, kev_cves)
                if not doc:
                    continue

                text_to_embed = f"Vulnerability {doc['id']}: {doc['title']}. {doc['description']}. Affected products: {' | '.join([f'Vendor: {v}, Product: {p}' for v,p in doc['affected_products']])}"
                doc['vector'] = embedder.embed_query(text_to_embed)
                doc['text_to_search'] = text_to_embed
                documents.append(doc)

            if len(documents) >= 1000:
                vector_store.add_documents(documents)
                documents = []
                # print("1000 Documentos añadidos a la base de datos...")

    if documents:
        vector_store.add_documents(documents)
        print(f"{len(documents)} Documentos añadidos a la base de datos...")


if __name__ == "__main__":
    main()