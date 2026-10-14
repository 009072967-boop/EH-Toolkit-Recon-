from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    secret_key: str = "dev-only-insecure-key-change-me"
    database_url: str = "sqlite:///./ethicalhawk.db"
    environment: str = "development"

    session_cookie_name: str = "eh_session"
    session_max_age_seconds: int = 60 * 60 * 12  # 12 hours

    # Passive-recon safety controls (PROGRAM_REQUIREMENTS.md 10.3)
    adapter_timeout_seconds: float = 8.0
    max_concurrent_jobs: int = 2
    max_concurrent_adapters_per_job: int = 3
    runs_per_user_per_hour: int = 5
    recon_kill_switch: bool = False

    # SEC EDGAR's fair-access policy requires automated clients to identify themselves with a
    # contact email in the User-Agent. The SEC adapter reports itself as not configured until set.
    sec_contact_email: str = ""

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
