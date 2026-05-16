"""schema inicial do Sinalyx

Revision ID: 20260505_0001
Revises:
Create Date: 2026-05-05 00:00:00
"""

from __future__ import annotations

from typing import Sequence

from alembic import op


revision: str = "20260505_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """
    Cria as tabelas principais sem apagar dados existentes.
    """
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS analyses (
            id VARCHAR(128) PRIMARY KEY,
            filename VARCHAR(255) NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL,
            total_windows INTEGER NOT NULL DEFAULT 0,
            final_status VARCHAR(64) NOT NULL,
            predominant_attack_type VARCHAR(128) NOT NULL,
            predominant_risk_level VARCHAR(64) NOT NULL,
            confidence_avg DOUBLE PRECISION,
            summary_json JSON NOT NULL,
            counts_json JSON NOT NULL,
            parse_stats_json JSON NOT NULL,
            artifacts_json JSON NOT NULL
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_analyses_created_at ON analyses (created_at)"
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL UNIQUE,
            password_hash VARCHAR(512) NOT NULL,
            role VARCHAR(32) NOT NULL DEFAULT 'user',
            is_active BOOLEAN NOT NULL DEFAULT true,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL,
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_users_email ON users (email)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_users_role ON users (role)")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS analysis_results (
            id SERIAL PRIMARY KEY,
            analysis_id VARCHAR(128) NOT NULL REFERENCES analyses(id),
            window_id VARCHAR(255),
            window_start VARCHAR(64),
            window_end VARCHAR(64),
            src_ip VARCHAR(64),
            protocol VARCHAR(32),
            action VARCHAR(32),
            interface VARCHAR(64),
            connections DOUBLE PRECISION,
            bytes DOUBLE PRECISION,
            packets DOUBLE PRECISION,
            packet_size DOUBLE PRECISION,
            ports DOUBLE PRECISION,
            is_anomaly BOOLEAN,
            final_label VARCHAR(64),
            attack_type VARCHAR(128),
            risk_level VARCHAR(64),
            confidence DOUBLE PRECISION,
            decision_source VARCHAR(128),
            decision_reason TEXT,
            ensemble_score DOUBLE PRECISION,
            autoencoder_score DOUBLE PRECISION,
            isolation_score DOUBLE PRECISION,
            raw_json JSON NOT NULL
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_analysis_results_analysis_id ON analysis_results (analysis_id)"
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS live_pfsense_windows (
            id SERIAL PRIMARY KEY,
            window_uid VARCHAR(128) NOT NULL UNIQUE,
            execution_id VARCHAR(128) NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL,
            status VARCHAR(64) NOT NULL DEFAULT 'success',
            local_log_path VARCHAR(512) NOT NULL,
            remote_path VARCHAR(512),
            parser_start_offset INTEGER,
            parser_end_offset INTEGER,
            window_id VARCHAR(255),
            window_timestamp TIMESTAMP WITH TIME ZONE,
            window_start VARCHAR(64),
            window_end VARCHAR(64),
            final_label VARCHAR(64),
            attack_type VARCHAR(128),
            risk_level VARCHAR(64),
            decision_source VARCHAR(128),
            confidence DOUBLE PRECISION,
            ensemble_score DOUBLE PRECISION,
            autoencoder_score DOUBLE PRECISION,
            isolation_score DOUBLE PRECISION,
            features_json JSON NOT NULL,
            model_outputs_json JSON NOT NULL,
            metadata_json JSON NOT NULL,
            raw_json JSON NOT NULL
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_live_pfsense_windows_window_uid ON live_pfsense_windows (window_uid)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_live_pfsense_windows_execution_id ON live_pfsense_windows (execution_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_live_pfsense_windows_created_at ON live_pfsense_windows (created_at)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_live_pfsense_windows_window_id ON live_pfsense_windows (window_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_live_pfsense_windows_window_timestamp ON live_pfsense_windows (window_timestamp)"
    )


def downgrade() -> None:
    """
    Downgrade nao destrutivo: nao remove tabelas nem dados automaticamente.
    """
    pass
