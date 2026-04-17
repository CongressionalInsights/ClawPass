# OpenAPI Export

Use FastAPI's generated OpenAPI document:

- Runtime endpoint: `/openapi.json`
- Interactive docs: `/docs`

To export locally:

```bash
python - <<'PY'
import json
from clawpass_server.app import create_app
app = create_app()
print(json.dumps(app.openapi(), indent=2))
PY
```
