"""
Coletor SSH/SFTP do filter.log do pfSense para o fluxo live do Sinalyx.

Entrada:
- Credenciais e caminhos via variaveis de ambiente.

Saida:
- Arquivo local em data/runtime/pfsense/live/filter.log.
- Estado da ultima coleta em collector_state.json.

Observacao:
- O coletor usa SFTP por Paramiko para evitar comandos externos de SCP.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from src.core.paths import BASE_DIR, DATA_DIR

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover - dependencia opcional em alguns ambientes
    load_dotenv = None

if load_dotenv is not None:
    load_dotenv()


DEFAULT_REMOTE_LOG_PATH = "/var/log/filter.log"
DEFAULT_LIVE_DIR = DATA_DIR / "runtime" / "pfsense" / "live"
DEFAULT_LOCAL_LOG_PATH = DEFAULT_LIVE_DIR / "filter.log"
DEFAULT_COLLECTOR_STATE_PATH = DEFAULT_LIVE_DIR / "collector_state.json"


def _now_iso() -> str:
    """
    Retorna timestamp local com timezone para auditoria de estado.
    """
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _resolve_project_path(value: str | None, default: Path) -> Path:
    """
    Resolve caminhos relativos a partir da raiz do projeto.
    """
    if value is None or not str(value).strip():
        return default

    path = Path(value).expanduser()
    if path.is_absolute():
        return path
    return BASE_DIR / path


def _read_json(path: Path) -> dict[str, Any]:
    """
    Le um JSON quando existir; caso contrario, devolve dicionario vazio.
    """
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as file:
            payload = json.load(file)
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    """
    Persiste estado JSON com indentacao estavel.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _env_bool(name: str, default: bool) -> bool:
    """
    Converte variaveis de ambiente booleanas comuns.
    """
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class PfSenseCollectorConfig:
    """
    Configuracao do coletor de logs pfSense.

    Args:
        host: Hostname ou IP do pfSense.
        port: Porta SSH.
        username: Usuario SSH.
        password: Senha SSH, quando usada.
        key_path: Caminho da chave privada, quando usada.
        remote_path: Caminho remoto do filter.log.
        local_path: Caminho local de destino.
        state_path: Caminho do estado JSON da coleta.
        connect_timeout: Timeout em segundos para conexao/autenticacao.
        allow_unknown_host: Aceita host key ainda nao conhecida.
    """

    host: str | None
    port: int
    username: str | None
    password: str | None
    key_path: Path | None
    remote_path: str
    local_path: Path
    state_path: Path
    connect_timeout: int
    allow_unknown_host: bool = True

    @classmethod
    def from_env(cls) -> "PfSenseCollectorConfig":
        """
        Monta a configuracao do coletor a partir de variaveis de ambiente.
        """
        key_value = os.getenv("SINALYX_PFSENSE_KEY_PATH")
        key_path = _resolve_project_path(key_value, BASE_DIR / key_value) if key_value else None

        local_path = _resolve_project_path(
            os.getenv("SINALYX_PFSENSE_LOCAL_LOG_PATH"),
            DEFAULT_LOCAL_LOG_PATH,
        )
        state_path = _resolve_project_path(
            os.getenv("SINALYX_PFSENSE_COLLECTOR_STATE_PATH"),
            local_path.parent / "collector_state.json",
        )

        return cls(
            host=os.getenv("SINALYX_PFSENSE_HOST"),
            port=int(os.getenv("SINALYX_PFSENSE_SSH_PORT", "22")),
            username=os.getenv("SINALYX_PFSENSE_USER"),
            password=os.getenv("SINALYX_PFSENSE_PASSWORD"),
            key_path=key_path,
            remote_path=os.getenv("SINALYX_PFSENSE_REMOTE_LOG_PATH", DEFAULT_REMOTE_LOG_PATH),
            local_path=local_path,
            state_path=state_path,
            connect_timeout=int(os.getenv("SINALYX_PFSENSE_CONNECT_TIMEOUT", "15")),
            allow_unknown_host=_env_bool("SINALYX_PFSENSE_ALLOW_UNKNOWN_HOST", True),
        )

    def missing_settings(self) -> list[str]:
        """
        Lista configuracoes obrigatorias ausentes.
        """
        missing: list[str] = []
        if not self.host:
            missing.append("SINALYX_PFSENSE_HOST")
        if not self.username:
            missing.append("SINALYX_PFSENSE_USER")
        if not self.password and self.key_path is None:
            missing.append("SINALYX_PFSENSE_PASSWORD ou SINALYX_PFSENSE_KEY_PATH")
        if self.key_path is not None and not self.key_path.exists():
            missing.append("SINALYX_PFSENSE_KEY_PATH existente")
        return missing


def read_collector_state(
    config: PfSenseCollectorConfig | None = None,
) -> dict[str, Any]:
    """
    Carrega o estado atual do coletor.
    """
    config = config or PfSenseCollectorConfig.from_env()
    state = _read_json(config.state_path)
    state.setdefault("remote_path", config.remote_path)
    state.setdefault("local_path", str(config.local_path))
    state.setdefault("state_path", str(config.state_path))
    return state


def collect_filter_log(
    config: PfSenseCollectorConfig | None = None,
) -> dict[str, Any]:
    """
    Copia o filter.log remoto do pfSense para o runtime local do Sinalyx.

    Returns:
        Dicionario com status, caminhos, tamanho coletado e possivel erro.
    """
    config = config or PfSenseCollectorConfig.from_env()
    now = _now_iso()
    base_state: dict[str, Any] = {
        "last_fetch_at": now,
        "remote_path": config.remote_path,
        "local_path": str(config.local_path),
        "state_path": str(config.state_path),
        "host": config.host,
        "port": int(config.port),
        "last_fetch_status": "error",
        "file_size": None,
        "remote_file_size": None,
        "error": None,
        "error_type": None,
    }

    missing = config.missing_settings()
    if missing:
        base_state.update(
            {
                "error_type": "configuration_error",
                "error": "Configuracao incompleta do coletor pfSense.",
                "missing_settings": missing,
            }
        )
        _write_json(config.state_path, base_state)
        return base_state

    try:
        import paramiko
    except Exception as exc:
        base_state.update(
            {
                "error_type": "dependency_missing",
                "error": (
                    "A dependencia paramiko nao esta disponivel. "
                    f"Instale requirements.txt. Motivo: {exc}"
                ),
            }
        )
        _write_json(config.state_path, base_state)
        return base_state

    ssh_client = None
    sftp_client = None
    temp_path = config.local_path.with_name(f"{config.local_path.name}.tmp")

    try:
        config.local_path.parent.mkdir(parents=True, exist_ok=True)

        ssh_client = paramiko.SSHClient()
        ssh_client.load_system_host_keys()
        if config.allow_unknown_host:
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        ssh_client.connect(
            hostname=str(config.host),
            port=int(config.port),
            username=str(config.username),
            password=config.password,
            key_filename=str(config.key_path) if config.key_path is not None else None,
            timeout=int(config.connect_timeout),
            banner_timeout=int(config.connect_timeout),
            auth_timeout=int(config.connect_timeout),
        )

        sftp_client = ssh_client.open_sftp()
        remote_attrs = sftp_client.stat(config.remote_path)
        remote_size = int(getattr(remote_attrs, "st_size", 0) or 0)
        sftp_client.get(config.remote_path, str(temp_path))
        temp_path.replace(config.local_path)

        local_size = int(config.local_path.stat().st_size)
        base_state.update(
            {
                "last_fetch_status": "success",
                "file_size": local_size,
                "remote_file_size": remote_size,
                "error": None,
                "error_type": None,
            }
        )
    except FileNotFoundError as exc:
        base_state.update(
            {
                "error_type": "file_not_found",
                "error": str(exc),
            }
        )
    except Exception as exc:  # pragma: no cover - depende de rede externa
        base_state.update(
            {
                "error_type": exc.__class__.__name__,
                "error": str(exc),
            }
        )
    finally:
        try:
            if sftp_client is not None:
                sftp_client.close()
        finally:
            if ssh_client is not None:
                ssh_client.close()
        if temp_path.exists() and base_state["last_fetch_status"] != "success":
            try:
                temp_path.unlink()
            except OSError:
                pass

    _write_json(config.state_path, base_state)
    return base_state
