"""
Adaptadores de entrada do Sinalyx.

Este modulo recebe dados de treino, CSVs de inferencia e registros de log
e converte tudo para o mesmo conjunto de features usado pelos modelos.
"""

from __future__ import annotations

import re
from io import BytesIO
from pathlib import Path
from typing import Any

import pandas as pd

from src.features.constants import (
    BASE_FEATURE_COLUMNS,
    BENIGN_TEXT_LABELS,
    FEATURE_COLUMNS,
    KNOWN_LABEL_COLUMNS,
    RAW_TO_FEATURE_MAPPING,
    describe_active_features,
)
from src.features.engineering import sanitize_numeric_frame, select_active_feature_frame


LOG_KEY_ALIASES = {
    "connections": "connections",
    "conn": "connections",
    "flow_duration": "connections",
    "bytes": "bytes",
    "total_bytes": "bytes",
    "packets": "packets",
    "total_packets": "packets",
    "packet_size": "packet_size",
    "avg_packet_size": "packet_size",
    "ports": "ports",
    "port": "ports",
    "destination_port": "ports",
    "dst_port": "ports",
}


def load_features_csv(path: str):
    """
    Le um CSV e normaliza os nomes das colunas para uso interno.
    """
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip()
    return df


def _extract_label(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series | None]:
    """
    Remove a coluna de rotulo quando ela existir.
    """
    working = df.copy()
    working.columns = working.columns.astype(str).str.strip()

    for label_col in KNOWN_LABEL_COLUMNS:
        if label_col not in working.columns:
            continue

        series = working[label_col]
        working = working.drop(columns=[label_col])

        if pd.api.types.is_numeric_dtype(series):
            y = pd.to_numeric(series, errors="coerce").fillna(0).astype(int)
        else:
            y = (
                ~series.astype(str).str.upper().str.strip().isin(BENIGN_TEXT_LABELS)
            ).astype(int)

        return working, y

    return working, None


def _build_base_feature_frame(df: pd.DataFrame) -> pd.DataFrame:
    """
    Garante as 5 features canonicas a partir de colunas prontas ou brutas.
    """
    working = df.copy()
    working.columns = working.columns.astype(str).str.strip()

    if set(BASE_FEATURE_COLUMNS).issubset(working.columns):
        return sanitize_numeric_frame(working[BASE_FEATURE_COLUMNS])

    raw_columns = list(RAW_TO_FEATURE_MAPPING.keys())
    if set(raw_columns).issubset(working.columns):
        renamed = working[raw_columns].rename(columns=RAW_TO_FEATURE_MAPPING)
        return sanitize_numeric_frame(renamed[BASE_FEATURE_COLUMNS])

    missing_base = [column for column in BASE_FEATURE_COLUMNS if column not in working.columns]
    missing_raw = [column for column in raw_columns if column not in working.columns]

    raise ValueError(
        "Nao foi possivel montar as features. "
        f"O arquivo precisa conter as features base {BASE_FEATURE_COLUMNS} "
        f"(faltando: {missing_base}) ou as colunas brutas {raw_columns} "
        f"(faltando: {missing_raw})."
    )


def _build_feature_frame(df: pd.DataFrame) -> pd.DataFrame:
    """
    Aplica feature engineering e retorna apenas as features ativas do projeto.
    """
    base_df = _build_base_feature_frame(df)
    features_df = select_active_feature_frame(base_df)
    return sanitize_numeric_frame(features_df[FEATURE_COLUMNS])


def load_training_dataframe(csv_path: str | Path) -> tuple[pd.DataFrame, pd.Series | None]:
    """
    Carrega um CSV de treino ou validacao ja no formato esperado pelo modelo.
    """
    df = pd.read_csv(csv_path, low_memory=False)
    df, y = _extract_label(df)
    X = _build_feature_frame(df)
    print(f"[INFO] Dataset carregado para treino/validacao com {describe_active_features()}")
    return X, y


def _parse_log_record(record: dict[str, Any] | str) -> dict[str, Any]:
    """
    Converte um log bruto em um dicionario compatível com as features base.

    Essa camada deixa o projeto pronto para integrar fontes textuais reais
    depois, sem alterar o restante do pipeline.
    """
    parsed = {column: 0.0 for column in BASE_FEATURE_COLUMNS}

    if isinstance(record, dict):
        items = record.items()
    else:
        pairs = re.findall(r"([A-Za-z_]+)\s*=\s*([0-9]+(?:\.[0-9]+)?)", str(record))
        items = pairs

    for raw_key, raw_value in items:
        normalized_key = LOG_KEY_ALIASES.get(str(raw_key).strip().lower())
        if not normalized_key:
            continue

        try:
            parsed[normalized_key] = float(raw_value)
        except (TypeError, ValueError):
            parsed[normalized_key] = 0.0

    return parsed


def prepare_inference_records(records: list[dict[str, Any]]) -> pd.DataFrame:
    """
    Entrada estruturada principal da API e do pipeline de inferencia.
    """
    if not records:
        raise ValueError("A lista de registros esta vazia.")
    df = pd.DataFrame(records)
    return _build_feature_frame(df)


def prepare_log_records(records: list[dict[str, Any] | str]) -> pd.DataFrame:
    """
    Camada pronta para logs reais ou semi-estruturados.
    """
    if not records:
        raise ValueError("A lista de logs esta vazia.")
    parsed = [_parse_log_record(record) for record in records]
    return _build_feature_frame(pd.DataFrame(parsed))


def load_inference_csv_bytes(content: bytes) -> pd.DataFrame:
    """
    Carrega um CSV em memoria e converte para o mesmo vetor de features da API.
    """
    df = pd.read_csv(BytesIO(content), low_memory=False)
    df, _ = _extract_label(df)
    return _build_feature_frame(df)


def validate_feature_order(df: pd.DataFrame) -> pd.DataFrame:
    """
    Reaplica a camada de entrada para garantir ordem e integridade das features.
    """
    return _build_feature_frame(df)
