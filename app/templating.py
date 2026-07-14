from __future__ import annotations

from pathlib import Path

from fastapi.templating import Jinja2Templates

templates_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))

# Workaround for Jinja2 LRU cache incompatibility with recent Starlette
# See: https://github.com/pallets/jinja/issues/2180
templates.env.cache = None
