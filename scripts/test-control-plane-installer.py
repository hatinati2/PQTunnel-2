#!/usr/bin/env python3
"""Structural checks for the pinned HTTP-only mobile control-plane installer."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/pqtunnel-control-install.sh"
DOC = ROOT / "docs/CONTROL-PLANE.md"
WORKFLOW = ROOT / ".github/workflows/ci.yml"


class ControlPlaneInstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = SCRIPT.read_text(encoding="utf-8")
        cls.doc = DOC.read_text(encoding="utf-8")
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_installer_requires_immutable_commit_sha(self) -> None:
        self.assertIn('[[ "$REF" =~ ^[0-9a-f]{40}$ ]]', self.script)
        self.assertIn("mutable branch names are refused", self.script)

    def test_gateway_and_dialer_use_http_control_urls(self) -> None:
        self.assertIn("--panel-host YOUR_PUBLIC_IP_OR_DNS", self.script)
        self.assertIn("--control-url", self.script)
        self.assertIn('--public-http --public-host "$PANEL_HOST"', self.script)
        self.assertIn('[[ "$CONTROL_URL" == http://* ]]', self.script)
        self.assertIn("--pair-token", self.script)
        self.assertIn("--role gateway", self.script)
        self.assertIn("--role dialer", self.script)
        self.assertNotIn("certbot certonly", self.script)
        self.assertNotIn("https://control.", self.script)

    def test_builds_verified_linux_bundle_before_install(self) -> None:
        self.assertIn("scripts/build-release-bundles.sh", self.script)
        self.assertIn("sha256sum --check", (ROOT / "scripts/build-release-bundles.sh").read_text(encoding="utf-8"))
        self.assertIn('tar -xzf "$DIST/PQTunnel-$VERSION-linux-$GO_ARCH.tar.gz"', self.script)
        self.assertIn('--with-node-endpoint', self.script)
        self.assertIn('-f "$SOURCE/scripts/pqtunnel-node-setup-worker.py"', self.script)

    def test_agent_enrollment_does_not_enable_tunnel_service(self) -> None:
        self.assertIn("/usr/local/sbin/pqtunnel-agent --enroll", self.script)
        self.assertIn("--config /var/lib/pqtunnel-agent/agent.json", self.script)
        self.assertIn("systemctl enable --now pqtunnel-agent", self.script)
        service = (ROOT / "deploy/systemd/pqtunnel-agent.service").read_text(encoding="utf-8")
        self.assertIn("StateDirectory=pqtunnel-agent", service)
        self.assertIn("/var/lib/pqtunnel-agent/agent.json", service)
        self.assertNotIn("systemctl enable --now pqtunneld-transport", self.script)
        self.assertNotIn("systemctl enable --now pqtunnel-client-transport", self.script)

    def test_documented_gateway_command_is_single_line_and_pinned(self) -> None:
        self.assertRegex(
            self.doc,
            re.compile(
                r"curl -fsSL https://raw\.githubusercontent\.com/hatinati2/PQTunnel-2/COMMIT_SHA/scripts/pqtunnel-control-install\.sh \| sudo bash -s -- --ref COMMIT_SHA --role gateway --panel-host YOUR_PUBLIC_IP_OR_DNS --panel-port 6100"
            ),
        )

    def test_manager_installer_enables_explicit_http_only_lab_mode(self) -> None:
        manager = (ROOT / "scripts/install-manager.sh").read_text(encoding="utf-8")
        self.assertIn("--public-http", manager)
        self.assertIn("PQTUNNEL_MANAGER_ALLOW_INSECURE_PUBLIC_HTTP=true", manager)
        self.assertIn("PQTUNNEL_MANAGER_PUBLIC_URL=http://", manager)
        self.assertIn("restrict the panel TCP port to trusted", manager)
        self.assertNotIn("certbot", manager)

        # The older embedded pqtunneld admin page remains loopback-only.
        web_doc = (ROOT / "docs/WEB-ADMIN-PANEL.md").read_text(encoding="utf-8")
        self.assertNotIn("--public-http", web_doc)
        self.assertNotIn("PQTUNNEL_MANAGER_ALLOW_INSECURE_PUBLIC_HTTP=true", web_doc)

    def test_no_static_ip_or_secret_is_embedded(self) -> None:
        embedded_ipv4 = re.findall(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])", self.script)
        self.assertEqual([ip for ip in embedded_ipv4 if ip != "0.0.0.0"], [])
        self.assertNotIn("-----BEGIN PRIVATE KEY-----", self.script)


if __name__ == "__main__":
    unittest.main()
