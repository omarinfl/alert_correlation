import pandas as pd
from abc import ABC, abstractmethod
from typing import List, Dict, Any

class AlertData(ABC):
    @abstractmethod
    def get_context_window(self, alert_time: pd.Timestamp, window_size: int) -> List[Dict[str, Any]]:
        pass


class CSVAlertData(AlertData):
    def __init__(self, csv_path: str):
        self.csv_path = csv_path
        self._df = None

    @property
    def df(self) -> pd.DataFrame:
        if self._df is None:
            print(f"Cargando datos desde {self.csv_path}...")
            self._df = pd.read_csv(self.csv_path, parse_dates=['timestamp'])
        return self._df
    
    def get_context_window(self, original_alert: Dict[str, Any], window_size: int) -> List[Dict[str, Any]]:
        df = self.df
        alert_time = pd.to_datetime(original_alert['timestamp'])
        previous_alerts = df[df['timestamp'] < alert_time].tail(window_size//2)[['timestamp', 'level', 'description', 'fired_times', 'full_log']]
        subsequent_alerts = df[df['timestamp'] > alert_time].head(window_size//2)[['timestamp', 'level', 'description', 'fired_times', 'full_log']]

        context_window = previous_alerts.to_dict(orient='records') + subsequent_alerts.to_dict(orient='records')
        return context_window