from abc import ABC, abstractmethod
from sentence_transformers import SentenceTransformer

class Embedder(ABC):
    @abstractmethod
    def embed_query(self, text: str) -> list[float]:
        pass

class SentenceTransformerEmbedder(Embedder):
    def __init__(self, model_name: str = 'all-MiniLM-L6-v2'):
        self.model = SentenceTransformer(model_name)

    def embed_query(self, text: str) -> list[float]:
        return self.model.encode(text).tolist()