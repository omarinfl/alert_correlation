from abc import ABC, abstractmethod


class VectorStore(ABC):
    @abstractmethod
    def initialize(self, dims: int, custom_columns: dict = None):
        pass

    @abstractmethod
    def add_documents(self, documents: list[dict]):
        pass

    @abstractmethod
    def search(self, query_vector: list[float], top_k: int = 5) -> list[dict]:
        pass

class ElasticSearchVectorStore(VectorStore):
    def __init__(self, index_name: str, es_url: str = 'http://localhost:9200'):
        from elasticsearch import Elasticsearch, helpers
        self.client = Elasticsearch(es_url)
        self.index_name = index_name
        self.helpers = helpers

    def initialize(self, dims: int, custom_columns: dict = None):
        if self.client.indices.exists(index=self.index_name):
            print(f"El índice '{self.index_name}' ya existe. Eliminándolo para reiniciar.")
            self.client.indices.delete(index=self.index_name)
        
        properties = {
            'vector': {
                'type': 'dense_vector',
                'dims': dims,
                'index': True,
                'similarity': 'cosine'
            }
        }

        if custom_columns:
            properties.update(custom_columns)

        self.client.indices.create(index=self.index_name, body={'mappings': {'properties': properties}})

    def add_documents(self, documents):
        transformed_docs = []
        for doc in documents:
            transformed_docs.append({
                '_index': self.index_name,
                '_id': doc.get('id', None),
                '_source': doc
            })

        self.helpers.bulk(self.client, transformed_docs)
        self.client.indices.refresh(index=self.index_name)

    def search(self, query_vector: list[float], top_k: int = 5, filter: dict = None) -> list[dict]:
        query = {
            "size": top_k,
            "knn": {
                "field": "vector",
                "query_vector": query_vector,
                "k": top_k,
                "num_candidates": 100
            }
        }

        if filter:
            query['knn']['filter'] = [{"term": {k: v}} for k, v in filter.items()]

        response = self.client.search(index=self.index_name, body=query)
        return [hit['_source'] for hit in response['hits']['hits']]
    
    def search_mitre_hybrid(self, query_vector, query_text, top_k=5):
        query = {
                "size": top_k,
                
                # 1. Búsqueda Vectorial (k-NN)
                "knn": {
                    "field": "vector",
                    "query_vector": query_vector,
                    "k": top_k,
                    "num_candidates": 100,
                    "boost": 0.9  # El vector vuelve a ser el jefe (90% del peso)
                },
                
                # 2. Búsqueda de Texto (Multi-Match) balanceada
                "query": {
                    "multi_match": {
                        "query": query_text,
                        # Buscamos en el nombre (con peso x3), en el ID y en la descripción
                        "fields": ["name^3", "technique_id^2", "tactics", "description", "procedures", "detections"],
                        "boost": 0.05 # Un peso muy bajito para que no rompa la escala del 0 al 1
                    }
                },
                
                # # 3. Traemos el Payload
                # "_source": ["technique_id", "name", "description", "detections", "mitigations"]
            }
        
        response = self.client.search(index=self.index_name, body=query)
        return [hit['_source'] for hit in response['hits']['hits']]