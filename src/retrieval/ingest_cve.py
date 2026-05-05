from embedders import SentenceTransformerEmbedder
from store import ElasticSearchVectorStore
import requests
import os

MIN_CVSS_SCORE = 7.0    # Solo se incluyen CVEs con CVSS >= 7.0 hasta el año ALL_YEAR
ALL_YEAR = 2023         # A partir de este año se incluyen todos los CVEs

def get_kev_cves():
    '''Obtiene la lista de CVEs del KEV de CISA.'''
    url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return data.get('vulnerabilities', [])
        else:
            print(f"Error al obtener los CVEs del KEV: {response.status_code}")
            return []
    except Exception as e:
        print(f"Error al obtener los CVEs del KEV: {e}")
        return []
    
# def download_cve_data():
    