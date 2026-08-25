# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import os
import platform
import shutil
import ssl
import subprocess
import sys
from urllib.parse import urlparse

import pytest

from azure.confidentialledger import ConfidentialLedgerClient

from _shared.testcase import ConfidentialLedgerPreparer, ConfidentialLedgerTestCase

REQUIRED_HYBRID_GROUP = "X25519MLKEM768"


@pytest.mark.live_test_only
class TestHybridMlKemTlsQualification(ConfidentialLedgerTestCase):
    @ConfidentialLedgerPreparer()
    def test_hybrid_and_default_tls_with_sdk_request(self, **kwargs):
        if os.environ.get("CONFIDENTIALLEDGER_RUN_HYBRID_TLS_QUALIFICATION") != "true":
            pytest.skip("Set CONFIDENTIALLEDGER_RUN_HYBRID_TLS_QUALIFICATION=true to run this qualification")

        endpoint = kwargs.pop("confidentialledger_endpoint")
        ledger_id = kwargs.pop("confidentialledger_id")
        openssl = os.environ.get("CONFIDENTIALLEDGER_OPENSSL_PATH", "openssl")
        assert shutil.which(openssl), f"OpenSSL executable not found: {openssl}"

        print(f"Python: {sys.version}")
        print(f"Platform: {platform.platform()}")
        print(f"Python TLS library: {ssl.OPENSSL_VERSION}")
        print(_run(openssl, "version", "-a"))
        print(_run(openssl, "list", "-providers"))

        self.set_ledger_identity(ledger_id)
        host = urlparse(endpoint).hostname
        assert host

        forced_output = _probe(
            openssl, host, self.network_certificate_path, REQUIRED_HYBRID_GROUP
        )
        _assert_verified(forced_output)
        print(f"Forced {REQUIRED_HYBRID_GROUP} handshake succeeded:\n{forced_output}")

        default_output = _probe(openssl, host, self.network_certificate_path)
        _assert_verified(default_output)
        print(f"Default handshake (not forced):\n{default_output}")

        client = ConfidentialLedgerClient(
            endpoint=endpoint,
            credential=self.get_credential(ConfidentialLedgerClient),
            ledger_certificate_path=self.network_certificate_path,
        )
        try:
            constitution = client.get_constitution()
            assert constitution.digest
            assert constitution.script
        finally:
            client.close()


def _probe(openssl, host, certificate_path, group=None):
    command = [
        "s_client",
        "-connect",
        f"{host}:443",
        "-servername",
        host,
        "-verify_hostname",
        host,
        "-CAfile",
        certificate_path,
        "-verify_return_error",
        "-tls1_3",
        "-brief",
    ]
    if group:
        command.extend(["-groups", group])
    return _run(openssl, *command, input_text="")


def _run(executable, *arguments, input_text=None):
    completed = subprocess.run(
        [executable, *arguments],
        input=input_text,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    return output


def _assert_verified(output):
    assert (
        "Verification: OK" in output or "Verify return code: 0 (ok)" in output
    ), output
    assert "TLSv1.3" in output, output
