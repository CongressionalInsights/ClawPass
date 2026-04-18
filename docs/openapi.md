# OpenAPI Export

Use FastAPI's generated OpenAPI document:

- Runtime endpoint: `/openapi.json`
- Interactive docs: `/docs`
- Checked-in export: [`docs/openapi.json`](./openapi.json)

Auth model in the current export:
- bootstrap routes are available before initialization
- producer-facing approval routes use bearer API keys
- approval-decision routes rely on the authenticated human session
- operator routes rely on the admin session overlay plus the CSRF header

For contributor and agent workflow, treat [../CONTRIBUTING.md](../CONTRIBUTING.md) as the canonical source for validation and regeneration steps.

To export locally from the repo virtualenv:

```bash
source .venv/bin/activate
python - <<'PY'
import json
from clawpass_server.app import create_app
app = create_app()
print(json.dumps(app.openapi(), indent=2))
PY
```
