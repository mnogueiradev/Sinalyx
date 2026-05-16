"""
Heuristica comportamental complementar do Sinalyx.

Esta camada continua fora do scaler e dos modelos principais, mas passa a
usar tambem metadados auxiliares vindos dos logs reais do pfSense para
reconhecer padroes mais explicaveis de ataque e trafego benigno.
"""

from __future__ import annotations

import re
from typing import Any


SAFE_SERVICE_PORTS = {53, 80, 123, 443}
SERVICE_PORTS_BRUTE_FORCE = {21, 22, 23, 25, 110, 143, 445, 3389}


def _safe_float(mapping: dict[str, Any], key: str) -> float:
    """
    Le um valor numerico de forma resiliente.
    """
    value = mapping.get(key, 0.0)
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _safe_int(mapping: dict[str, Any], key: str) -> int:
    """
    Le um inteiro de forma resiliente.
    """
    return int(round(_safe_float(mapping, key)))


def _safe_text(mapping: dict[str, Any], key: str) -> str:
    """
    Le e padroniza um texto vindo do CSV agregado.
    """
    value = mapping.get(key, "")
    if value is None:
        return ""
    return str(value).strip().lower()


def _parse_port_set(value: Any) -> set[int]:
    """
    Converte uma lista textual de portas em conjunto numerico.
    """
    if value is None:
        return set()

    tokens = re.split(r"[^0-9]+", str(value))
    ports = {int(token) for token in tokens if token.isdigit()}
    return ports


def _parse_flag_summary(value: Any) -> dict[str, int]:
    """
    Converte um resumo textual de flags em dicionario.
    """
    summary: dict[str, int] = {}
    text = str(value or "").strip()
    if not text:
        return summary

    for chunk in text.split(","):
        token = chunk.strip()
        if not token:
            continue
        if ":" in token:
            name, raw_count = token.split(":", 1)
            try:
                summary[name.strip().upper()] = int(raw_count.strip())
                continue
            except ValueError:
                pass
        summary[token.upper()] = summary.get(token.upper(), 0) + 1
    return summary


def _normalize_features(features: dict[str, Any]) -> dict[str, Any]:
    """
    Garante que a heuristica trabalhe com features numericas e metadados.
    """
    normalized: dict[str, Any] = {
        "connections": _safe_float(features, "connections"),
        "bytes": _safe_float(features, "bytes"),
        "packets": _safe_float(features, "packets"),
        "packet_size": _safe_float(features, "packet_size"),
        "ports": _safe_float(features, "ports"),
        "source_ip": _safe_text(features, "source_ip"),
        "protocol": _safe_text(features, "protocol"),
        "action": _safe_text(features, "action"),
        "interface": _safe_text(features, "interface"),
        "destination_ip_count": _safe_int(features, "destination_ip_count"),
        "destination_ip_sample": str(features.get("destination_ip_sample", "") or "").strip(),
        "destination_port_min": _safe_int(features, "destination_port_min"),
        "destination_port_max": _safe_int(features, "destination_port_max"),
        "destination_port_count": _safe_int(features, "destination_port_count"),
        "blocked_count": _safe_int(features, "blocked_count"),
        "passed_count": _safe_int(features, "passed_count"),
        "tcp_syn_count": _safe_int(features, "tcp_syn_count"),
        "tcp_pa_count": _safe_int(features, "tcp_pa_count"),
        "tcp_flags_summary": str(features.get("tcp_flags_summary", "") or "").strip(),
    }

    connections = normalized["connections"]
    bytes_ = normalized["bytes"]
    packets = normalized["packets"]

    normalized["bytes_per_packet"] = (
        _safe_float(features, "bytes_per_packet")
        or (bytes_ / packets if packets > 0 else 0.0)
    )
    normalized["bytes_per_connection"] = (
        _safe_float(features, "bytes_per_connection")
        or (bytes_ / connections if connections > 0 else 0.0)
    )
    normalized["packets_per_connection"] = (
        _safe_float(features, "packets_per_connection")
        or (packets / connections if connections > 0 else 0.0)
    )

    common_ports = _parse_port_set(features.get("common_destination_ports", ""))
    if not common_ports:
        port_min = normalized["destination_port_min"]
        port_max = normalized["destination_port_max"]
        if port_min > 0:
            common_ports.add(port_min)
        if port_max > 0:
            common_ports.add(port_max)

    flag_summary = _parse_flag_summary(normalized["tcp_flags_summary"])
    if normalized["tcp_syn_count"] <= 0:
        normalized["tcp_syn_count"] = int(
            flag_summary.get("S", 0) + flag_summary.get("SYN", 0)
        )
    if normalized["tcp_pa_count"] <= 0:
        normalized["tcp_pa_count"] = int(flag_summary.get("PA", 0))

    normalized["common_destination_ports"] = common_ports
    normalized["flag_summary"] = flag_summary
    normalized["destination_port_count"] = max(
        normalized["destination_port_count"],
        int(round(normalized["ports"])),
        len(common_ports),
    )
    return normalized


def _build_candidate(
    attack_type: str,
    confidence: float,
    reason: str,
) -> dict[str, Any]:
    """
    Padroniza a estrutura de retorno da heuristica.
    """
    return {
        "heuristic_detected_attack": True,
        "attack_type": attack_type,
        "heuristic_confidence": round(float(min(max(confidence, 0.0), 0.99)), 4),
        "heuristic_reason": reason,
    }


def analyze_behavior(features: dict[str, Any]) -> dict[str, Any]:
    """
    Executa a heuristica complementar de comportamento.

    O objetivo aqui e interpretar melhor logs reais do pfSense sem alterar
    as 13 features numericas que entram nos modelos.
    """
    values = _normalize_features(features)

    connections = values["connections"]
    bytes_ = values["bytes"]
    packets = values["packets"]
    packet_size = values["packet_size"]
    ports = values["ports"]
    bytes_per_packet = values["bytes_per_packet"]
    bytes_per_connection = values["bytes_per_connection"]
    packets_per_connection = values["packets_per_connection"]

    protocol = values["protocol"]
    action = values["action"]
    destination_ip_count = values["destination_ip_count"]
    destination_port_count = values["destination_port_count"]
    common_ports = values["common_destination_ports"]
    blocked_count = values["blocked_count"]
    passed_count = values["passed_count"]
    tcp_syn_count = values["tcp_syn_count"]
    tcp_pa_count = values["tcp_pa_count"]

    packets_denominator = max(int(round(packets)), 1)
    syn_ratio = tcp_syn_count / packets_denominator
    pa_ratio = tcp_pa_count / packets_denominator
    blocked_ratio = blocked_count / packets_denominator
    safe_ports = common_ports & SAFE_SERVICE_PORTS
    sensitive_ports = common_ports & SERVICE_PORTS_BRUTE_FORCE
    safe_service_only = bool(common_ports) and common_ports.issubset(SAFE_SERVICE_PORTS)
    is_blocked_profile = action == "block" or blocked_count > 0 or blocked_ratio >= 0.50

    candidates: list[dict[str, Any]] = []

    if (
        protocol == "tcp"
        and destination_port_count >= 50
        and syn_ratio >= 0.65
        and connections >= max(20.0, destination_port_count * 0.70)
        and packet_size <= 90
    ):
        confidence = min(
            0.98,
            0.86
            + min(destination_port_count / 2000.0, 0.07)
            + min(connections / 2000.0, 0.04)
            + (0.02 if destination_ip_count <= 3 else 0.0),
        )
        candidates.append(
            _build_candidate(
                "port_scan",
                confidence,
                (
                    "Muitas conexoes SYN para muitas portas de destino em uma janela curta "
                    "sugerem atividade de port scan."
                ),
            )
        )

    if (
        protocol == "tcp"
        and tcp_syn_count >= 4
        and syn_ratio >= 0.75
        and packet_size <= 60
        and destination_port_count <= 3
        and destination_ip_count <= 3
        and is_blocked_profile
    ):
        confidence = min(
            0.97,
            0.84
            + min(tcp_syn_count / 40.0, 0.08)
            + (0.03 if blocked_count >= 4 else 0.0)
            + (0.02 if destination_port_count == 1 else 0.0),
        )
        candidates.append(
            _build_candidate(
                "syn_flood",
                confidence,
                (
                    "Predominio de pacotes SYN pequenos e bloqueados para poucas portas "
                    "e poucos destinos e compativel com syn flood."
                ),
            )
        )

    if (
        packets >= 5000
        or bytes_ >= 500000
        or (connections >= 400 and packets_per_connection >= 8)
        or (connections >= 600 and bytes_per_connection >= 400)
    ):
        confidence = min(
            0.96,
            0.72
            + (0.08 if packets >= 5000 else 0.0)
            + (0.08 if bytes_ >= 500000 else 0.0)
            + (0.05 if packets_per_connection >= 8 else 0.0)
            + (0.03 if connections >= 600 else 0.0),
        )
        candidates.append(
            _build_candidate(
                "ddos",
                confidence,
                "Volume anormalmente alto de conexoes, bytes ou pacotes sugere padrao compativel com DDoS.",
            )
        )

    if (
        protocol == "tcp"
        and bool(sensitive_ports)
        and is_blocked_profile
        and (tcp_pa_count >= 4 or (tcp_syn_count >= 4 and packets >= 6))
    ):
        confidence = min(
            0.93,
            0.78
            + (0.08 if 22 in sensitive_ports else 0.0)
            + min(tcp_pa_count / 20.0, 0.05)
            + (0.02 if packets >= 8 else 0.0),
        )
        candidates.append(
            _build_candidate(
                "brute_force",
                confidence,
                (
                    "Tentativas repetidas e bloqueadas em porta sensivel, especialmente SSH, "
                    "sao compativeis com brute force."
                ),
            )
        )
    elif (
        protocol == "tcp"
        and bool(sensitive_ports)
        and is_blocked_profile
        and (tcp_pa_count >= 1 or tcp_syn_count >= 2 or packets >= 2)
    ):
        confidence = min(
            0.86,
            0.72
            + (0.06 if 22 in sensitive_ports else 0.0)
            + min(pa_ratio, 0.04)
            + (0.02 if blocked_count >= 2 else 0.0),
        )
        candidates.append(
            _build_candidate(
                "ssh_suspicious",
                confidence,
                (
                    "Bloqueios repetidos em porta de administracao, especialmente 22/TCP, "
                    "indicam atividade SSH suspeita."
                ),
            )
        )

    if not candidates and is_blocked_profile and not safe_service_only and (
        tcp_syn_count >= 3 or tcp_pa_count >= 3 or destination_port_count >= 20
    ):
        confidence = min(
            0.80,
            0.60
            + min(destination_port_count / 200.0, 0.08)
            + min(tcp_syn_count / 40.0, 0.06)
            + min(tcp_pa_count / 20.0, 0.06),
        )
        candidates.append(
            _build_candidate(
                "unknown_anomaly",
                confidence,
                (
                    "O grupo apresentou bloqueios e padroes de flags ou portas fora do esperado, "
                    "mas sem assinatura heuristica forte para uma familia especifica."
                ),
            )
        )

    if not candidates and (
        action == "pass"
        and blocked_count == 0
        and passed_count >= 1
        and destination_port_count <= 10
        and safe_service_only
        and not (
            protocol == "tcp"
            and tcp_syn_count >= 8
            and destination_port_count <= 3
            and destination_ip_count <= 3
            and packet_size <= 60
        )
    ):
        return {
            "heuristic_detected_attack": False,
            "attack_type": "normal",
            "heuristic_confidence": 0.92,
            "heuristic_reason": (
                "Padrao compativel com trafego benigno de saida em portas comuns, sem assinatura forte de varredura ou bloqueio."
            ),
        }

    if not candidates:
        return {
            "heuristic_detected_attack": False,
            "attack_type": "normal",
            "heuristic_confidence": 0.78,
            "heuristic_reason": "Nenhuma regra comportamental forte foi acionada.",
        }

    best_candidate = max(candidates, key=lambda item: float(item["heuristic_confidence"]))
    return best_candidate


def classify_attack(features: dict[str, Any]) -> str:
    """
    Mantem compatibilidade com a funcao antiga que retornava so o tipo.
    """
    return str(analyze_behavior(features)["attack_type"])
