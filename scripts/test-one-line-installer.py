#!/usr/bin/env python3
"""Safety and version regression tests for the experimental PQTunnel-2 entry point."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install.sh"


class OneLineInstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = INSTALLER.read_text(encoding="utf-8")
        cls.readme_en = (ROOT / "README.md").read_text(encoding="utf-8")
        cls.readme_fa = (ROOT / "README.fa.md").read_text(encoding="utf-8")
        cls.setup = (ROOT / "scripts/pqtunnel-site-to-site-setup.sh").read_text(encoding="utf-8")
        cls.pki_script = (ROOT / "scripts/prepare-site-to-site-pki.sh").read_text(encoding="utf-8")
        cls.pki_source = (ROOT / "cmd/pqtunnel-pki/main.go").read_text(encoding="utf-8")

    def test_alpha_version_is_consistent_across_docs_and_installer(self) -> None:
        version = "0.4.0-pqalpha.1"
        self.assertIn(f"**Version:** {version}", self.readme_en)
        self.assertIn(f"**نسخه: {version}", self.readme_fa)
        self.assertIn(f"## {version}", (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"))
        self.assertIn(f'VERSION="v{version}"', self.script)
        self.assertIn(f'VERSION="${{PQTUNNEL_SETUP_VERSION:-v{version}}}"', self.setup)

    def test_entrypoint_targets_the_new_repository(self) -> None:
        self.assertIn('REPO="hatinati2/PQTunnel-2"', self.script)
        self.assertIn('RAW_BASE="https://raw.githubusercontent.com/${REPO}/main"', self.script)
        self.assertNotIn('REPO="hatinati2/PQTunnel"', self.script)
        self.assertIn("PQTunnel-2/main/install.sh", self.script)

    def test_mutating_install_modes_fail_closed_before_dispatch(self) -> None:
        guard = self.script.index("Installation modes are disabled until a reviewed tagged release bundle is published")
        dispatcher = self.script.index('case "$MODE" in\n  site-to-site)')
        self.assertLess(guard, dispatcher)
        self.assertIn('  preflight) ;;', self.script)
        self.assertIn('MODE=preflight', self.script)
        self.assertIn("No server changes were made", self.script)

    def test_preflight_is_the_only_enabled_action(self) -> None:
        self.assertIn('curl --fail --silent --show-error --location "$RAW_BASE/scripts/site-to-site-preflight.sh"', self.script)
        self.assertIn("read-only host checks", self.script)
        self.assertIn("PQTunnel-2 is source-only experimental software", self.script)

    def test_pkI_generator_uses_ml_dsa_65_and_keeps_ca_offline(self) -> None:
        self.assertIn('"crypto/mldsa"', self.pki_source)
        self.assertIn("mldsa.MLDSA65()", self.pki_source)
        self.assertIn("x509.MLDSA65", self.pki_source)
        self.assertIn('0600', self.pki_source)
        self.assertIn('ca-offline', self.pki_script)
        self.assertNotIn("openssl", self.pki_script.lower())

    def test_no_deployment_ip_or_credential_is_embedded_by_installer(self) -> None:
        self.assertNotRegex(self.script, r"(?<![0-9])(?:[0-9]{1,3}\\.){3}[0-9]{1,3}(?![0-9])")
        self.assertNotIn("-----BEGIN PRIVATE KEY-----", self.script)
        self.assertNotIn("PQTUNNEL_MANAGER_TOKEN=replace-me", self.script)


if __name__ == "__main__":
    unittest.main()
