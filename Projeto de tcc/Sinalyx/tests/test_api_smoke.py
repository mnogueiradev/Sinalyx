"""
Testes smoke da API Sinalyx contra uma instancia FastAPI em execucao.

Por padrao usa http://localhost:8000. Para testar rotas protegidas, defina:
SINALYX_TEST_ADMIN_EMAIL e SINALYX_TEST_ADMIN_PASSWORD.
"""

from __future__ import annotations

import json
import os
import unittest
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


API_BASE_URL = os.getenv("SINALYX_TEST_API_BASE_URL", "http://localhost:8000").rstrip("/")
ADMIN_EMAIL = os.getenv("SINALYX_TEST_ADMIN_EMAIL", "")
ADMIN_PASSWORD = os.getenv("SINALYX_TEST_ADMIN_PASSWORD", "")


class ApiResponse:
    """
    Resposta HTTP simples usada pelos testes sem depender de httpx.
    """

    def __init__(self, status: int, payload: dict[str, Any] | None) -> None:
        self.status = status
        self.payload = payload or {}


def request_json(
    method: str,
    path: str,
    *,
    token: str | None = None,
    payload: dict[str, Any] | None = None,
) -> ApiResponse:
    """
    Executa uma chamada JSON simples contra a API em execucao.
    """
    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = Request(
        f"{API_BASE_URL}{path}",
        data=body,
        headers=headers,
        method=method,
    )
    try:
        with urlopen(request, timeout=10) as response:
            raw = response.read().decode("utf-8")
            return ApiResponse(response.status, json.loads(raw) if raw else {})
    except HTTPError as exc:
        raw = exc.read().decode("utf-8")
        return ApiResponse(exc.code, json.loads(raw) if raw else {})


class SinalyxApiSmokeTests(unittest.TestCase):
    """
    Testes minimos dos contratos principais da API.
    """

    admin_token: str | None = None

    @classmethod
    def setUpClass(cls) -> None:
        try:
            health = request_json("GET", "/health")
        except URLError as exc:
            raise unittest.SkipTest(f"API indisponivel em {API_BASE_URL}: {exc}") from exc

        if health.status != 200:
            raise unittest.SkipTest(f"API retornou status inesperado em /health: {health.status}")

        if ADMIN_EMAIL and ADMIN_PASSWORD:
            login = request_json(
                "POST",
                "/auth/login",
                payload={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
            )
            if login.status == 200:
                cls.admin_token = str(login.payload["data"]["access_token"])

    def test_health(self) -> None:
        response = request_json("GET", "/health")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.payload["status"], "ok")
        self.assertIn("database", response.payload)

    def test_root_is_public(self) -> None:
        response = request_json("GET", "/")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.payload["app"], "Sinalyx API")

    def test_protected_routes_without_token_require_auth(self) -> None:
        protected_get_paths = [
            "/dashboard/summary",
            "/alerts/recent",
            "/history/summary",
            "/history/windows",
            "/history/windows/11",
            "/history/alerts",
            "/history/executions",
            "/live/pfsense/collector/status",
            "/live/pfsense/parser/status",
            "/live/pfsense/windows",
            "/analyses",
            "/analyses/test-analysis",
            "/analyses/test-analysis/results",
            "/admin/users",
            "/system/audit",
        ]
        for path in protected_get_paths:
            with self.subTest(path=path):
                response = request_json("GET", path)
                self.assertEqual(response.status, 401)

        live_run = request_json("POST", "/live/pfsense/run")
        self.assertEqual(live_run.status, 401)

        predict = request_json(
            "POST",
            "/predict",
            payload={
                "connections": 1,
                "bytes": 1,
                "packets": 1,
                "packet_size": 1,
                "ports": 1,
            },
        )
        self.assertEqual(predict.status, 401)

    def test_history_summary_with_admin_token(self) -> None:
        if not self.admin_token:
            raise unittest.SkipTest(
                "Defina SINALYX_TEST_ADMIN_EMAIL e SINALYX_TEST_ADMIN_PASSWORD para testar rotas autenticadas."
            )

        response = request_json("GET", "/history/summary", token=self.admin_token)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.payload["status"], "success")

    def test_history_window_by_id_with_admin_token(self) -> None:
        if not self.admin_token:
            raise unittest.SkipTest(
                "Defina SINALYX_TEST_ADMIN_EMAIL e SINALYX_TEST_ADMIN_PASSWORD para testar rotas autenticadas."
            )

        response = request_json("GET", "/history/windows/11", token=self.admin_token)
        if response.status == 404:
            raise unittest.SkipTest("Janela 11 nao existe no banco atual.")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.payload["status"], "success")
        self.assertIn("window", response.payload["data"])

    def test_auth_me_and_admin_users_with_admin_token(self) -> None:
        if not self.admin_token:
            raise unittest.SkipTest(
                "Defina SINALYX_TEST_ADMIN_EMAIL e SINALYX_TEST_ADMIN_PASSWORD para testar rotas autenticadas."
            )

        me = request_json("GET", "/auth/me", token=self.admin_token)
        self.assertEqual(me.status, 200)
        self.assertEqual(me.payload["status"], "success")

        users = request_json("GET", "/admin/users", token=self.admin_token)
        self.assertEqual(users.status, 200)
        self.assertEqual(users.payload["status"], "success")

    def test_system_audit_with_admin_token(self) -> None:
        if not self.admin_token:
            raise unittest.SkipTest(
                "Defina SINALYX_TEST_ADMIN_EMAIL e SINALYX_TEST_ADMIN_PASSWORD para testar /system/audit."
            )

        response = request_json("GET", "/system/audit", token=self.admin_token)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.payload["status"], "success")
        self.assertEqual(response.payload["data"]["system"]["name"], "Sinalyx")


if __name__ == "__main__":
    unittest.main()
