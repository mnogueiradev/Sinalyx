"""
Models ORM usados pela API para persistir historico de analises.
"""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from src.db.database import Base


class Analysis(Base):
    """
    Analise consolidada executada pela API sobre um arquivo de log.
    """

    __tablename__ = "analyses"

    id = Column(String(128), primary_key=True)
    filename = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, index=True)
    total_windows = Column(Integer, nullable=False, default=0)
    final_status = Column(String(64), nullable=False)
    predominant_attack_type = Column(String(128), nullable=False)
    predominant_risk_level = Column(String(64), nullable=False)
    confidence_avg = Column(Float, nullable=True)
    summary_json = Column(JSON, nullable=False)
    counts_json = Column(JSON, nullable=False)
    parse_stats_json = Column(JSON, nullable=False)
    artifacts_json = Column(JSON, nullable=False)

    results = relationship(
        "AnalysisResult",
        back_populates="analysis",
        cascade="all, delete-orphan",
    )


class User(Base):
    """
    Usuario autenticavel do painel Sinalyx.
    """

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False, unique=True, index=True)
    password_hash = Column(String(512), nullable=False)
    role = Column(String(32), nullable=False, default="user", index=True)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False)


class AnalysisResult(Base):
    """
    Resultado detalhado por janela produzido pela inferencia.
    """

    __tablename__ = "analysis_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(String(128), ForeignKey("analyses.id"), nullable=False, index=True)
    window_id = Column(String(255), nullable=True)
    window_start = Column(String(64), nullable=True)
    window_end = Column(String(64), nullable=True)
    src_ip = Column(String(64), nullable=True)
    protocol = Column(String(32), nullable=True)
    action = Column(String(32), nullable=True)
    interface = Column(String(64), nullable=True)
    connections = Column(Float, nullable=True)
    bytes = Column(Float, nullable=True)
    packets = Column(Float, nullable=True)
    packet_size = Column(Float, nullable=True)
    ports = Column(Float, nullable=True)
    is_anomaly = Column(Boolean, nullable=True)
    final_label = Column(String(64), nullable=True)
    attack_type = Column(String(128), nullable=True)
    risk_level = Column(String(64), nullable=True)
    confidence = Column(Float, nullable=True)
    decision_source = Column(String(128), nullable=True)
    decision_reason = Column(Text, nullable=True)
    ensemble_score = Column(Float, nullable=True)
    autoencoder_score = Column(Float, nullable=True)
    isolation_score = Column(Float, nullable=True)
    raw_json = Column(JSON, nullable=False)

    analysis = relationship("Analysis", back_populates="results")


class LivePfSenseWindow(Base):
    """
    Janela processada pelo fluxo live/quase em tempo real do pfSense.

    Esta tabela e separada do historico de uploads para preservar o contrato
    atual da API e registrar execucoes incrementais com idempotencia.
    """

    __tablename__ = "live_pfsense_windows"

    id = Column(Integer, primary_key=True, autoincrement=True)
    window_uid = Column(String(128), nullable=False, unique=True, index=True)
    execution_id = Column(String(128), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, index=True)
    status = Column(String(64), nullable=False, default="success")
    local_log_path = Column(String(512), nullable=False)
    remote_path = Column(String(512), nullable=True)
    parser_start_offset = Column(Integer, nullable=True)
    parser_end_offset = Column(Integer, nullable=True)
    window_id = Column(String(255), nullable=True, index=True)
    window_timestamp = Column(DateTime(timezone=True), nullable=True, index=True)
    window_start = Column(String(64), nullable=True)
    window_end = Column(String(64), nullable=True)
    final_label = Column(String(64), nullable=True)
    attack_type = Column(String(128), nullable=True)
    risk_level = Column(String(64), nullable=True)
    decision_source = Column(String(128), nullable=True)
    confidence = Column(Float, nullable=True)
    ensemble_score = Column(Float, nullable=True)
    autoencoder_score = Column(Float, nullable=True)
    isolation_score = Column(Float, nullable=True)
    features_json = Column(JSON, nullable=False)
    model_outputs_json = Column(JSON, nullable=False)
    metadata_json = Column(JSON, nullable=False)
    raw_json = Column(JSON, nullable=False)
