from langchain_core.tools import tool
from src.retrieval.embedders import SentenceTransformerEmbedder
from src.retrieval.store import ElasticSearchVectorStore

embedder = SentenceTransformerEmbedder()
cve_store = ElasticSearchVectorStore(index_name='cve_index')
mitre_store = ElasticSearchVectorStore(index_name='mitre_attack')

@tool
def query_cve(query: str) -> str:
    '''Tool to query CVEs from the vector store. Useful for finding vulnerabilities related to specific software, attack techniques, or CVE IDs.'''
    vector = embedder.embed_query(query)
    results = cve_store.search(vector, top_k=3)
    return '\n\n'.join([f"{res['id']}: {res['description']}" for res in results])

@tool
def query_mitre(query: str) -> str:
    '''Tool to query MITRE techniques from the vector store. Useful for finding information about specific attack techniques.'''
    vector = embedder.embed_query(query)
    results = mitre_store.search(vector, top_k=3)
    return '\n\n'.join([f"{res['id']}: {res['description']}" for res in results])