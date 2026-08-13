from pathlib import Path
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    DB_HOST: str = "localhost"
    DB_PORT: int = 3306
    DB_USER: str = "root"
    DB_PASSWORD: str = ""
    DB_NAME: str = "fraud_app"

    REDIS_URL: str = "redis://127.0.0.1:6379/0"

    MINIO_ENDPOINT: str = "127.0.0.1:9000"
    MINIO_ACCESS_KEY: str = "minioadmin"
    MINIO_SECRET_KEY: str = "minioadmin"
    MINIO_SECURE: bool = False

    BUCKET_TASK_FILES: str = "task-files"

    JWT_SECRET_KEY: str = "change-me-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 120

    ALLOWED_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173"
    BACKEND_IMPORT_USER_ID: str = ""
    BACKEND_IMPORT_USERNAME: str = "yahong"

    PLAN_AGENT_BASE_URL: str = "https://dashscope.aliyuncs.com/compatible-mode/v1"
    PLAN_AGENT_MODEL: str = "qwen3-vl-235b-a22b-instruct"
    PLAN_AGENT_API_KEY: str = "sk-11c87318288d4bbbb102ab2a831a7b3c"
    PLAN_AGENT_MAX_PLAN_STEPS: int = 15
    PLAN_AGENT_ENABLE_THINKING: bool = False
    PLAN_AGENT_THINKING_BUDGET: int = 81920

    PHONE_AGENT_BASE_URL: str = "https://open.bigmodel.cn/api/paas/v4"
    PHONE_AGENT_MODEL: str = "autoglm-phone"
    PHONE_AGENT_API_KEY: str = "3db312763d5d47e8927c79d9ccb2bbc9.r1jcQHG2ytMkN5SQ"
    PHONE_AGENT_MAX_STEPS: int = 3

    DYNAMIC_TRACE_TASK_TEXT: str = "模拟操作探索APP功能"
    DYNAMIC_TRACE_RESULT_DIR: str = str(BASE_DIR / "data" / "dynamic_trace")
    DEVICE_RECOVERY_SCAN_INTERVAL_SECONDS: int = 60
    DEVICE_RECOVERY_REBOOT_TIMEOUT_SECONDS: int = 180
    DEVICE_RECOVERY_INSTALL_TIMEOUT_SECONDS: int = 120
    DEVICE_RECOVERY_UNINSTALL_TIMEOUT_SECONDS: int = 60
    DEVICE_RECOVERY_DATA_CLEANUP_TIMEOUT_SECONDS: int = 300
    DEVICE_RECOVERY_STABLE_HEALTH_TIMEOUT_SECONDS: int = 120
    DEVICE_RECOVERY_STABLE_HEALTH_INTERVAL_SECONDS: int = 10
    DEVICE_RECOVERY_STALE_SECONDS: int = 1200
    DEVICE_RECOVERY_MAX_WORKERS: int = 2
    DEVICE_RECOVERY_APK_PATH: str = str(
        BASE_DIR / "tools" / "device_health" / "DeviceHealthCheck.apk"
    )
    DEVICE_RECOVERY_APK_PACKAGE: str = "com.fraudanalysis.devicehealth"
    FLUTTER_BLUTTER_ROOT: str = ""
    FLUTTER_BLUTTER_ENABLED: bool = True
    FLUTTER_BLUTTER_TOOL_ROOT: str = str(BASE_DIR / "tools" / "blutter")
    FLUTTER_BLUTTER_OUTPUT_ROOT: str = str(BASE_DIR / "data" / "flutter_blutter")
    FLUTTER_BLUTTER_TIMEOUT_SECONDS: int = 900
    FLUTTER_BLUTTER_BUILD_DOCKER_IMAGE: str = ""
    REAL_CONTROLLER_TAGGING_ENABLED: bool = True
    REAL_CONTROLLER_TAGGING_BASE_URL: str = "https://dashscope.aliyuncs.com/compatible-mode/v1"
    REAL_CONTROLLER_TAGGING_MODEL: str = "qwen3-vl-235b-a22b-instruct"
    REAL_CONTROLLER_TAGGING_API_KEY: str = "sk-11c87318288d4bbbb102ab2a831a7b3c"

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
    )

    @property
    def allowed_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]


settings = Settings()
