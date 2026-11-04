"""Prompt templates live as files next to this module. Each file has a system part and a
user part separated by a line `=== user ===`. Jinja2 renders the user part."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

from jinja2 import Environment, StrictUndefined

PROMPT_DIR = Path(__file__).parent / "prompts"
LANGUAGES = {
    "nb": "Norwegian (bokmål)",
    "nn": "Norwegian (nynorsk)",
    "en": "English",
    "sv": "Swedish",
    "da": "Danish",
    "de": "German",
}


@dataclass(frozen=True, slots=True)
class Prompt:
    name: str
    version: str
    system: str
    user_template: str


@cache
def _env() -> Environment:
    return Environment(undefined=StrictUndefined, trim_blocks=True, lstrip_blocks=True)


@cache
def load_prompt(name: str) -> Prompt:
    text = (PROMPT_DIR / f"{name}.md").read_text()
    head, _, user = text.partition("\n=== user ===\n")
    version = "1"
    lines = head.splitlines()
    if lines and lines[0].startswith("version:"):
        version = lines[0].split(":", 1)[1].strip()
        head = "\n".join(lines[1:])
    return Prompt(name=name, version=version, system=head.strip(), user_template=user.strip())


def render(prompt: Prompt, language: str, **ctx: Any) -> tuple[str, str]:
    lang = LANGUAGES.get(language, language)
    system = _env().from_string(prompt.system).render(language=lang, **ctx)
    user = _env().from_string(prompt.user_template).render(language=lang, **ctx)
    return system, user
