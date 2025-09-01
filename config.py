from pydantic_settings import BaseSettings
from typing import Optional
import os


class Settings(BaseSettings):
    # AWS Account IDs - MUST be set via environment variables
    source_account_id: str = "YOUR_SOURCE_ACCOUNT_ID"  # MUST be overridden via .env
    target_account_id: str = "YOUR_TARGET_ACCOUNT_ID"  # MUST be overridden via .env
    
    # IAM Role configuration
    assume_role_name: str = "YOUR_CROSS_ACCOUNT_ROLE_NAME"  # MUST be overridden via .env
    session_name: str = "EC2ListingSession"
    
    # AWS Region
    aws_region: str = "ap-northeast-2"
    
    # Logging
    log_level: str = "INFO"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()