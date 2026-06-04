import pandas as pd
import os
import csv
from abc import ABC, abstractmethod
from typing import Dict, Any
from src.models.models import AlertLog, EvaluationResult

class DataSaver(ABC):
    @abstractmethod
    def save_alert_log(self, log: AlertLog) -> None:
        pass

    def save_evaluation_result(self, result: EvaluationResult) -> None:
        pass

class CSVDataSaver(DataSaver):
    def __init__(self, alerts_csv_path: str, evaluations_csv_path: str):
        self.alerts_csv_path = alerts_csv_path
        self.evaluations_csv_path = evaluations_csv_path

    def _append_to_csv(self, data: Dict[str, Any], csv_path: str) -> None:
        is_new = not os.path.exists(csv_path)

        with open(csv_path, mode='a', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=data.keys())
            if is_new:
                writer.writeheader()
            writer.writerow(data)

    def save_alert_log(self, log: AlertLog) -> None:
        self._append_to_csv(log.model_dump(), self.alerts_csv_path)

    def save_evaluation_result(self, result: EvaluationResult) -> None:
        self._append_to_csv(result.model_dump(), self.evaluations_csv_path)