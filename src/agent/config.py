from pydantic import BaseModel, Field

class AgentConfig(BaseModel):
    use_context_window: bool = Field(default=True, description="Whether to use a context window for alert evaluation")
    context_window_size: int = Field(default=10, description="Number of alerts to include in the context window")

    generate_report: bool = Field(default=True, description="Whether to generate a final report after processing the alert")
    report_dir: str = Field(default='reports', description="Directory where reports will be saved")

    mitre_top_k: int = Field(default=5, description="Number of top results to retrieve from searches")
