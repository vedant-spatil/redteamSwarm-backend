from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "Red Team Swarm"
    OLLAMA_HOST: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "qwen2.5-coder:3b"
    DATABASE_URL: str = "sqlite:///./swarm.db"

    model_config = SettingsConfigDict(
        env_file=".env"
    )


settings = Settings()
