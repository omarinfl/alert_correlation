from abc import ABC, abstractmethod
from sentence_transformers import SentenceTransformer
from langchain_openai import OpenAIEmbeddings


class Embedder(ABC):
    @abstractmethod
    def embed_query(self, text: str) -> list[float]:
        pass

class SentenceTransformerEmbedder(Embedder):
    def __init__(self, model_name: str = 'all-MiniLM-L6-v2'):
        self.model = SentenceTransformer(model_name)

    def embed_query(self, text: str) -> list[float]:
        return self.model.encode(text).tolist()
    

class LocalvLLMEmbedder(Embedder):
    def __init__(self, model_name: str = 'bge-m3', base_url: str = "http://10.0.152.198:8002/v1" ):
        self.model = OpenAIEmbeddings(
            model=model_name,
            api_key='EMPTY',
            base_url=base_url
            )

    def embed_query(self, text: str) -> list[float]:
        return self.model.embed_query(text)
    