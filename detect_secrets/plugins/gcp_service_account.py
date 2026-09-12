"""
This plugin searches for GCP service account credentials.
"""
import re
from typing import Any
from typing import Generator
from typing import Set

from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.plugins.base import RegexBasedDetector
from detect_secrets.util.code_snippet import CodeSnippet

# Number of lines before and after the matched line to check for private_key_id
CONTEXT_WINDOW = 20


class GCPServiceAccountDetector(RegexBasedDetector):
    """Scans for GCP service account credentials.

    Detects the ``"type": "service_account"`` field that appears in service account
    JSON key files and verifies that ``private_key_id`` is present within
    CONTEXT_WINDOW lines of the match.
    """

    secret_type = 'GCP Service Account'

    denylist = [
        # Match "type": "service_account" with optional surrounding whitespace/quotes.
        re.compile(
            r'"type"\s*:\s*"service_account"',
            re.IGNORECASE,
        ),
    ]

    def analyze_line(
        self,
        filename: str,
        line: str,
        line_number: int = 0,
        context: CodeSnippet = None,
        **kwargs: Any,
    ) -> Set[PotentialSecret]:
        """Return secrets only when private_key_id is visible in the surrounding context."""
        secrets = super().analyze_line(
            filename=filename,
            line=line,
            line_number=line_number,
            context=context,
            **kwargs,
        )

        if not secrets:
            return secrets

        # Verify that private_key_id appears somewhere in the surrounding context.
        if context is not None and self._private_key_id_in_context(context):
            return secrets

        # No context available — fall back to scanning the raw snippet lines when
        # the CodeSnippet object is provided, otherwise emit the finding conservatively.
        if context is None:
            return secrets

        return set()

    def _private_key_id_in_context(self, context: CodeSnippet) -> bool:
        """Return True when any line in the code snippet contains 'private_key_id'."""
        for line in context.lines:
            if 'private_key_id' in line:
                return True
        return False

    def analyze_string(self, string: str) -> Generator[str, None, None]:
        for regex in self.denylist:
            for match in regex.findall(string):
                yield match
