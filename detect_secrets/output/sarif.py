"""
SARIF 2.1.0 output formatter for leakwatch / detect-secrets.

Usage (CLI):
    detect-secrets scan --output-format sarif [path ...]

The output conforms to the Static Analysis Results Interchange Format (SARIF)
version 2.1.0 as described in https://docs.oasis-open.org/sarif/sarif/v2.1.0/
"""
from typing import Any
from typing import Dict
from typing import List

from detect_secrets.__version__ import VERSION
from detect_secrets.core.secrets_collection import SecretsCollection


def format_sarif(secrets: SecretsCollection) -> Dict[str, Any]:
    """Convert a SecretsCollection to a SARIF 2.1.0 document.

    :param secrets: the collection of potential secrets to serialise.
    :returns: a dict that can be passed directly to ``json.dumps``.
    """
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for filename, secret in secrets:
        rule_id = secret.type

        # Accumulate unique rules (one per detector/secret type).
        if rule_id not in rules:
            rules[rule_id] = {
                'id': rule_id,
                'name': rule_id.replace(' ', ''),
                'shortDescription': {
                    'text': rule_id,
                },
                'helpUri': 'https://github.com/unrandoms/leakwatch',
                'properties': {
                    'tags': ['security', 'secret-detection'],
                },
            }

        result: Dict[str, Any] = {
            'ruleId': rule_id,
            'level': 'error',
            'message': {
                'text': (
                    'Potential {} detected.'.format(secret.type)
                ),
            },
            'locations': [
                {
                    'physicalLocation': {
                        'artifactLocation': {
                            'uri': filename,
                            'uriBaseId': '%SRCROOT%',
                        },
                        'region': {
                            'startLine': secret.line_number if secret.line_number else 1,
                        },
                    },
                },
            ],
            'fingerprints': {
                'leakwatch/v1': secret.secret_hash,
            },
        }

        results.append(result)

    sarif_document: Dict[str, Any] = {
        'version': '2.1.0',
        '$schema': (
            'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/'
            'sarif-schema-2.1.0.json'
        ),
        'runs': [
            {
                'tool': {
                    'driver': {
                        'name': 'leakwatch',
                        'version': VERSION,
                        'informationUri': 'https://github.com/unrandoms/leakwatch',
                        'rules': list(rules.values()),
                    },
                },
                'results': results,
            },
        ],
    }

    return sarif_document
