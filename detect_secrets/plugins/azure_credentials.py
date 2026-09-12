"""
This plugin searches for Azure credentials: storage connection strings,
SAS tokens, and Azure AD client secrets.
"""
import re
from typing import Generator
from typing import Iterable
from typing import Pattern
from typing import Tuple

from detect_secrets.plugins.base import RegexBasedDetector


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

# Azure Storage connection string:
#   DefaultEndpointsProtocol=https;AccountName=<name>;AccountKey=<86 base64 chars>=
_AZURE_STORAGE_CONNECTION_STRING = re.compile(
    r'DefaultEndpointsProtocol=https;AccountName=[^;]{1,100};'
    r'AccountKey=[A-Za-z0-9+/]{86}=',
    re.IGNORECASE,
)

# Azure SAS token — must start with sv= (service version) and include the
# canonical SAS query parameters in any order.
_AZURE_SAS_TOKEN = re.compile(
    r'sv=\d{4}-\d{2}-\d{2}'
    r'(?:&(?:ss|srt|sp|se|st|spr|sig)=[^&\s"\']{1,200}){2,}',
    re.IGNORECASE,
)

# Azure AD client secret — 34-40 character string of alphanumeric / - / _ / ~
# characters that appear next to a keyword suggesting it is a credential value.
_AZURE_CLIENT_SECRET = re.compile(
    r'(?:secret|key|password|token|client_?secret|clientsecret)\s*[=:]\s*'
    r'["\']?([A-Za-z0-9\-_~]{34,40})["\']?',
    re.IGNORECASE,
)

# Map each pattern to a human-readable label returned as the "secret" value.
_PATTERNS: Tuple[Tuple[Pattern, str], ...] = (
    (_AZURE_STORAGE_CONNECTION_STRING, 'Azure Storage Connection String'),
    (_AZURE_SAS_TOKEN, 'Azure SAS Token'),
    (_AZURE_CLIENT_SECRET, 'Azure AD Client Secret'),
)


class AzureCredentialsDetector(RegexBasedDetector):
    """Scans for Azure credentials: storage connection strings, SAS tokens,
    and Azure AD client secrets."""

    secret_type = 'Azure Credentials'

    # RegexBasedDetector requires `denylist` to be set, but we override
    # analyze_string to handle the per-pattern labelling ourselves.
    denylist: Iterable[Pattern] = [p for p, _ in _PATTERNS]

    def analyze_string(self, string: str) -> Generator[str, None, None]:
        for regex, label in _PATTERNS:
            for match in regex.findall(string):
                if isinstance(match, tuple):
                    # Capture groups present — yield the first non-empty group.
                    for group in match:
                        if group:
                            yield group
                            break
                else:
                    yield match
