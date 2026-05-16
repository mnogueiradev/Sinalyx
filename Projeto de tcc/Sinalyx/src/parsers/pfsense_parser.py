"""
Parser inicial de logs reais do pfSense para o Sinalyx.

Este modulo implementa uma base robusta e extensivel para:
- ler logs brutos do pfSense
- identificar linhas syslog
- reconhecer mensagens do filterlog/firewall
- extrair campos principais de rede
- preservar a linha original
- tolerar erros de parsing sem interromper o arquivo inteiro

O foco desta primeira versao e IPv4, mas a estrutura ja deixa caminhos
abertos para evoluir depois para IPv6, outros tipos de log do pfSense e
integracao futura com ingestao em API.
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Iterator


PROTOCOL_ID_TO_NAME = {
    1: "icmp",
    6: "tcp",
    17: "udp",
    58: "icmpv6",
}

PARSE_STATUS_FULL = "full"
PARSE_STATUS_PARTIAL = "partial"
PARSE_STATUS_FAILED = "failed"

PORT_PROTOCOLS = {"tcp", "udp"}

KNOWN_TCP_FLAGS = {
    "S",
    "SA",
    "A",
    "PA",
    "FA",
    "FPA",
    "R",
    "RA",
    "FPU",
    "SYN",
    "ACK",
    "RST",
    "FIN",
    "PSH",
}


@dataclass
class ParsedPfSenseEvent:
    """
    Estrutura padrao de um evento parseado do pfSense.

    A ideia desta dataclass e servir como camada intermediaria entre o log
    bruto e o restante do pipeline do Sinalyx.
    """

    timestamp: str | None
    hostname: str | None
    process: str | None
    log_type: str | None
    rule: str | None
    subrule: str | None
    anchor: str | None
    tracker: str | None
    interface: str | None
    reason: str | None
    action: str | None
    direction: str | None
    ip_version: int | None
    protocol_id: int | None
    protocol: str | None
    length: int | None
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    tcp_flags: str | None
    icmp_type: str | None
    icmp_code: str | None
    bytes: int | None
    packets: int | None
    raw_message: str
    parsed_successfully: bool
    error: str | None
    parse_status: str
    line_number: int | None = None
    is_syslog: bool = False
    is_filterlog: bool = False
    csv_payload: str | None = None
    syslog_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """
        Converte o evento em dicionario para DataFrame ou CSV.
        """
        return asdict(self)


class PfSenseLogParser:
    """
    Parser resiliente de logs do pfSense.

    Este parser foi desenhado para funcionar bem mesmo quando o formato do
    filterlog variar um pouco entre versoes do pfSense. Sempre que um parse
    completo nao for possivel, ele devolve o maximo de contexto disponivel e
    registra o erro no proprio evento.
    """

    SYSLOG_RFC3164_RE = re.compile(
        r"""
        ^
        (?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)
        \s+
        (?P<hostname>\S+)
        \s+
        (?P<process>[^:]+)
        :
        \s*
        (?P<message>.*)
        $
        """,
        re.VERBOSE,
    )

    SYSLOG_ISO_RE = re.compile(
        r"""
        ^
        (?P<timestamp>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)
        \s+
        (?P<hostname>\S+)
        \s+
        (?P<process>[^:]+)
        :
        \s*
        (?P<message>.*)
        $
        """,
        re.VERBOSE,
    )

    FILTERLOG_PREFIX_RE = re.compile(
        r"filterlog(?:\[\d+\])?\s*:\s*(?P<payload>.*)$",
        re.IGNORECASE,
    )

    def __init__(self, default_year: int | None = None) -> None:
        """
        Inicializa o parser.

        Args:
            default_year: Ano usado para normalizar timestamps RFC3164.
                Quando None, usa o ano atual do sistema.
        """
        self.default_year = default_year or datetime.now().year

    def read_log_file(self, input_path: str | Path) -> Iterator[str]:
        """
        Le um arquivo bruto de log linha a linha.

        O uso de iterator ajuda a manter o parser pronto para arquivos maiores.
        """
        path = Path(input_path)
        with path.open("r", encoding="utf-8", errors="replace") as file:
            for line in file:
                yield line.rstrip("\n")

    def iter_parsed_events(self, input_path: str | Path) -> Iterator[ParsedPfSenseEvent]:
        """
        Parseia o arquivo inteiro de forma incremental.
        """
        for line_number, line in enumerate(self.read_log_file(input_path), start=1):
            if not line.strip():
                continue
            yield self.parse_line(line, line_number=line_number)

    def parse_file(self, input_path: str | Path) -> list[ParsedPfSenseEvent]:
        """
        Parseia um arquivo inteiro e retorna todos os eventos.
        """
        return list(self.iter_parsed_events(input_path))

    def parse_line(self, line: str, line_number: int | None = None) -> ParsedPfSenseEvent:
        """
        Parseia uma unica linha do log.

        A funcao tenta primeiro reconhecer um cabecalho syslog. Se nao houver,
        ainda assim tenta interpretar a linha como payload direto de filterlog.
        """
        event = self._build_empty_event(line=line, line_number=line_number)
        line = line.strip()

        if not line:
            event.error = "Linha vazia."
            return event

        syslog_parts = self._parse_syslog_header(line)
        if syslog_parts is not None:
            event.is_syslog = True
            event.timestamp = self._normalize_syslog_timestamp(syslog_parts["timestamp"])
            event.hostname = syslog_parts["hostname"]
            event.process = syslog_parts["process"]
            event.syslog_message = syslog_parts["message"]

            if self._is_filterlog_line(syslog_parts["process"], syslog_parts["message"]):
                event.is_filterlog = True
                event.log_type = "firewall"
                return self._parse_filterlog_message(syslog_parts["message"], event)

            event.log_type = "syslog_other"
            event.error = "Linha syslog lida, mas nao corresponde ao filterlog do pfSense."
            return event

        if self._looks_like_filterlog_payload(line):
            event.is_filterlog = True
            event.log_type = "firewall"
            return self._parse_filterlog_message(line, event)

        event.log_type = "unknown"
        event.error = "Linha nao reconhecida como syslog ou payload de filterlog."
        return event

    def _build_empty_event(
        self,
        *,
        line: str,
        line_number: int | None = None,
    ) -> ParsedPfSenseEvent:
        """
        Cria um evento base com os campos padrao do projeto.
        """
        return ParsedPfSenseEvent(
            timestamp=None,
            hostname=None,
            process=None,
            log_type=None,
            rule=None,
            subrule=None,
            anchor=None,
            tracker=None,
            interface=None,
            reason=None,
            action=None,
            direction=None,
            ip_version=None,
            protocol_id=None,
            protocol=None,
            length=None,
            source_ip=None,
            destination_ip=None,
            source_port=None,
            destination_port=None,
            tcp_flags=None,
            icmp_type=None,
            icmp_code=None,
            bytes=None,
            packets=None,
            raw_message=line,
            parsed_successfully=False,
            error=None,
            parse_status=PARSE_STATUS_FAILED,
            line_number=line_number,
        )

    def _parse_syslog_header(self, line: str) -> dict[str, str] | None:
        """
        Tenta reconhecer cabecalho syslog em dois formatos comuns:
        - RFC3164 tradicional do Unix/pfSense
        - linha com timestamp em ISO-8601
        """
        for pattern in (self.SYSLOG_RFC3164_RE, self.SYSLOG_ISO_RE):
            match = pattern.match(line)
            if match:
                return {
                    "timestamp": match.group("timestamp").strip(),
                    "hostname": match.group("hostname").strip(),
                    "process": match.group("process").strip(),
                    "message": match.group("message").strip(),
                }
        return None

    def _is_filterlog_line(self, process: str | None, message: str | None) -> bool:
        """
        Decide se a linha representa um evento do firewall/filterlog.
        """
        lowered_process = str(process or "").lower()
        lowered_message = str(message or "").lower()

        if "filterlog" in lowered_process:
            return True
        if "filterlog:" in lowered_message or "filterlog[" in lowered_message:
            return True
        return self._looks_like_filterlog_payload(str(message or ""))

    def _looks_like_filterlog_payload(self, payload: str) -> bool:
        """
        Faz uma validacao leve para saber se um texto parece um payload CSV
        de filterlog.
        """
        if payload.count(",") < 10:
            return False

        try:
            fields = self._safe_csv_split(payload)
        except csv.Error:
            return False

        if len(fields) < 9:
            return False

        ip_version = self._safe_get(fields, 8)
        if ip_version in {"4", "6"}:
            return True

        return "filterlog" in payload.lower()

    def _parse_filterlog_message(
        self,
        message: str,
        event: ParsedPfSenseEvent,
    ) -> ParsedPfSenseEvent:
        """
        Extrai o payload CSV do filterlog e parseia os campos mais importantes.
        """
        try:
            csv_payload = self._extract_filterlog_csv_payload(message)
            if not csv_payload:
                event.error = "Payload CSV do filterlog nao encontrado."
                return event

            event.csv_payload = csv_payload
            fields = self._safe_csv_split(csv_payload)
            if len(fields) < 9:
                event.error = "Payload CSV do filterlog muito curto."
                return event

            # Cabecalho principal do filterlog em formato CSV.
            event.rule = self._safe_get(fields, 0)
            event.subrule = self._safe_get(fields, 1)
            event.anchor = self._safe_get(fields, 2)
            event.tracker = self._safe_get(fields, 3)
            event.interface = self._safe_get(fields, 4)
            event.reason = self._safe_get(fields, 5)
            event.action = self._normalize_text(self._safe_get(fields, 6))
            event.direction = self._normalize_text(self._safe_get(fields, 7))
            event.ip_version = self._to_int(self._safe_get(fields, 8))

            if event.ip_version == 4:
                self._parse_ipv4_filterlog(fields, event)
            elif event.ip_version == 6:
                self._parse_ipv6_filterlog(fields, event)
            else:
                event.error = "Versao IP nao reconhecida no payload do filterlog."
                return event

            event.bytes = event.length if event.length is not None else 0
            event.packets = 1
            return self._finalize_filterlog_event(event)
        except Exception as exc:  # pragma: no cover - protecao defensiva
            event.error = f"Erro inesperado durante o parse do filterlog: {exc}"
            return event

    def _finalize_filterlog_event(self, event: ParsedPfSenseEvent) -> ParsedPfSenseEvent:
        """
        Define o status final de qualidade do parse para eventos filterlog.

        `full` representa sucesso completo e alimenta o restante do pipeline.
        `partial` preserva linhas reconhecidas, mas incompletas.
        """
        missing_fields = self._missing_required_fields(event)
        if missing_fields:
            event.parsed_successfully = False
            event.parse_status = PARSE_STATUS_PARTIAL

            missing_text = ", ".join(missing_fields)
            missing_error = (
                f"Campos obrigatorios ausentes para parse completo: {missing_text}."
            )
            if event.error:
                event.error = f"{event.error} {missing_error}"
            else:
                event.error = missing_error
            return event

        event.parsed_successfully = True
        event.parse_status = PARSE_STATUS_FULL
        event.error = None
        return event

    def _missing_required_fields(self, event: ParsedPfSenseEvent) -> list[str]:
        """
        Lista os campos obrigatorios ausentes para o protocolo identificado.
        """
        missing: list[str] = []

        if not self._has_value(event.protocol):
            missing.append("protocol")
        if not self._has_value(event.source_ip):
            missing.append("source_ip")
        if not self._has_value(event.destination_ip):
            missing.append("destination_ip")

        protocol = str(event.protocol or "").lower()
        if protocol in PORT_PROTOCOLS:
            if event.source_port is None:
                missing.append("source_port")
            if event.destination_port is None:
                missing.append("destination_port")

        return missing

    @staticmethod
    def _has_value(value: str | None) -> bool:
        """
        Informa se um valor textual foi realmente extraido.
        """
        if value is None:
            return False
        return bool(str(value).strip())

    def _parse_ipv4_filterlog(
        self,
        fields: list[str],
        event: ParsedPfSenseEvent,
    ) -> None:
        """
        Parse do layout IPv4 mais comum do filterlog.

        Mapa de indices normalmente observado:
        15=protocol_id
        16=protocol
        17=length
        18=source_ip
        19=destination_ip
        20+=payload do protocolo de transporte
        """
        event.protocol_id = self._to_int(self._safe_get(fields, 15))
        event.protocol = self._normalize_protocol(
            self._safe_get(fields, 16),
            protocol_id=event.protocol_id,
        )
        event.length = self._to_int(self._safe_get(fields, 17))
        event.source_ip = self._safe_ip(self._safe_get(fields, 18))
        event.destination_ip = self._safe_ip(self._safe_get(fields, 19))

        transport_fields = fields[20:]
        self._parse_transport_segment(transport_fields, event)

    def _parse_ipv6_filterlog(
        self,
        fields: list[str],
        event: ParsedPfSenseEvent,
    ) -> None:
        """
        Parse inicial de IPv6.

        O layout do pfSense para IPv6 pode variar mais, entao aqui a estrategia
        e identificar o protocolo e os IPs com tolerancia a pequenas mudancas.
        """
        proto_field_a = self._safe_get(fields, 12)
        proto_field_b = self._safe_get(fields, 13)

        if proto_field_a and proto_field_a.isdigit():
            event.protocol_id = self._to_int(proto_field_a)
            event.protocol = self._normalize_protocol(proto_field_b, protocol_id=event.protocol_id)
            event.length = self._to_int(self._safe_get(fields, 14))
            event.source_ip = self._safe_ip(self._safe_get(fields, 15))
            event.destination_ip = self._safe_ip(self._safe_get(fields, 16))
            transport_fields = fields[17:]
        else:
            event.protocol = self._normalize_protocol(proto_field_a, protocol_id=None)
            event.protocol_id = self._to_int(proto_field_b)
            event.protocol = self._normalize_protocol(event.protocol, protocol_id=event.protocol_id)
            event.length = self._to_int(self._safe_get(fields, 14))
            event.source_ip = self._safe_ip(self._safe_get(fields, 15))
            event.destination_ip = self._safe_ip(self._safe_get(fields, 16))
            transport_fields = fields[17:]

        self._parse_transport_segment(transport_fields, event)

    def _parse_transport_segment(self, fields: list[str], event: ParsedPfSenseEvent) -> None:
        """
        Parseia a parte do protocolo de transporte.

        O foco desta primeira versao e capturar:
        - portas TCP/UDP
        - flags TCP
        - tipo/codigo ICMP
        """
        protocol = str(event.protocol or "").lower()

        if protocol in {"tcp", "udp"}:
            source_port, destination_port = self._extract_ports_from_slice(fields)
            event.source_port = source_port
            event.destination_port = destination_port

            if protocol == "tcp":
                event.tcp_flags = self._find_tcp_flags(fields)
            return

        if protocol in {"icmp", "icmpv6"}:
            event.icmp_type = self._safe_get(fields, 0)
            event.icmp_code = self._safe_get(fields, 1)

    def _extract_filterlog_csv_payload(self, message: str) -> str | None:
        """
        Extrai o payload CSV do filterlog.

        Casos cobertos:
        - mensagem contendo "filterlog:"
        - processo filterlog ja entregando apenas o payload
        - linha bruta que ja e o CSV puro
        """
        direct_match = self.FILTERLOG_PREFIX_RE.search(message)
        if direct_match:
            payload = direct_match.group("payload").strip()
            return payload if payload else None

        if self._looks_like_filterlog_payload(message):
            return message.strip()

        return None

    @staticmethod
    def _safe_csv_split(payload: str) -> list[str]:
        """
        Divide o payload CSV de forma segura, respeitando campos vazios.
        """
        reader = csv.reader(io.StringIO(payload))
        row = next(reader)
        return [item.strip() for item in row]

    @staticmethod
    def _safe_get(fields: list[str], index: int) -> str | None:
        """
        Retorna um campo por indice sem disparar erro.
        """
        if 0 <= index < len(fields):
            value = fields[index].strip()
            return value if value else None
        return None

    @staticmethod
    def _to_int(value: str | None) -> int | None:
        """
        Converte string para inteiro quando possivel.
        """
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _safe_ip(value: str | None) -> str | None:
        """
        Normaliza um IP quando possivel.
        """
        if not value:
            return None
        try:
            return str(ip_address(value))
        except ValueError:
            return value

    @staticmethod
    def _extract_ports_from_slice(fields: list[str]) -> tuple[int | None, int | None]:
        """
        Extrai as portas de origem e destino na ordem esperada do payload.

        Para TCP/UDP no filterlog do pfSense, os dois primeiros campos do
        segmento de transporte correspondem as portas. Evitamos procurar
        "os dois primeiros numeros" no restante da fatia para nao mascarar
        parses parciais quando uma porta esta ausente.
        """
        source_port = PfSenseLogParser._normalize_port(PfSenseLogParser._safe_get(fields, 0))
        destination_port = PfSenseLogParser._normalize_port(PfSenseLogParser._safe_get(fields, 1))
        return source_port, destination_port

    @staticmethod
    def _normalize_port(value: str | None) -> int | None:
        """
        Converte uma porta para inteiro quando ela estiver em faixa valida.
        """
        candidate = PfSenseLogParser._to_int(value)
        if candidate is None:
            return None
        if 0 <= candidate <= 65535:
            return candidate
        return None

    @staticmethod
    def _find_tcp_flags(fields: list[str]) -> str | None:
        """
        Procura flags TCP conhecidas no restante do payload.
        """
        for field in fields:
            normalized = str(field or "").strip().upper()
            if normalized in KNOWN_TCP_FLAGS:
                return normalized
        return None

    @staticmethod
    def _normalize_text(value: str | None) -> str | None:
        """
        Padroniza textos livres em minusculo.
        """
        if not value:
            return None
        return value.strip().lower()

    def _normalize_protocol(
        self,
        value: str | None,
        *,
        protocol_id: int | None,
    ) -> str | None:
        """
        Normaliza o protocolo textual ou usa o ID numerico como fallback.
        """
        if value:
            normalized = value.strip().lower()
            if normalized:
                return normalized

        if protocol_id is not None:
            return PROTOCOL_ID_TO_NAME.get(protocol_id, str(protocol_id))

        return None

    def _normalize_syslog_timestamp(self, value: str) -> str | None:
        """
        Converte timestamps syslog para ISO-8601 sempre que possivel.

        O formato RFC3164 nao traz ano. Neste caso, usamos o ano atual do
        parser como referencia.
        """
        try:
            # Primeiro tentamos interpretar como timestamp ISO.
            if "T" in value or re.match(r"^\d{4}-\d{2}-\d{2}", value):
                normalized = value.replace("Z", "+00:00")
                return datetime.fromisoformat(normalized).isoformat()
        except ValueError:
            pass

        try:
            parsed = datetime.strptime(
                f"{self.default_year} {value}",
                "%Y %b %d %H:%M:%S",
            )
            return parsed.isoformat()
        except ValueError:
            return value
