# SPDX-License-Identifier: MIT
"""Small, offline English/Russian message catalogue (one language per bot)."""
import json
from pathlib import Path

_RU = json.loads((Path(__file__).parent / 'locales' / 'ru.json').read_text(encoding='utf-8'))
_LANGUAGE = 'en'
_CONTEXT = {'ports': '22', 'timezone': 'UTC'}


def configure_language(language='en', ports=None, timezone='UTC'):
    global _LANGUAGE
    if language not in ('en', 'ru'):
        raise ValueError('Supported languages: en, ru')
    _LANGUAGE = language
    _CONTEXT['timezone'] = timezone
    _CONTEXT['ports'] = ', '.join(str(p) for p in ports) if ports is not None else '22'


def tr(message, **values):
    template = _RU.get(message, message) if _LANGUAGE == 'ru' else message
    return template.format(**(_CONTEXT | values))
