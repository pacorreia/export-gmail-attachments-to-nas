# Plugins

Plugins are called every time an attachment is successfully saved to a file share. They let you integrate the exporter with external systems — send a notification, trigger a workflow, or run post-processing logic.

Two plugin types are supported: **Webhook** and **Subprocess**.

---

## Event payload

Both plugin types receive the same JSON event:

```json
{
  "rule_id": 1,
  "account_id": 2,
  "file_share_id": 3,
  "filename": "invoice_march.pdf",
  "nas_path": "invoices/2024/03/invoice_march.pdf",
  "size_bytes": 204800,
  "email_date": "2024-03-15T09:30:00Z",
  "subject": "Invoice #1234",
  "sender": "billing@example.com",
  "mime_type": "application/pdf"
}
```

---

## Webhook plugin

Posts the event JSON to an HTTP endpoint via POST.

### Configuration

| Field | Required | Default | Description |
|---|---|---|---|
| `url` | ✅ | — | Full URL to POST to, e.g. `https://n8n.example.com/webhook/abc123` |
| `secret` | ❌ | — | If set, the request includes an `X-Signature-SHA256` header: `HMAC-SHA256(secret, body)` |
| `retries` | ❌ | `3` | Number of attempts before giving up (exponential backoff: 1s, 2s, 3s) |

### Example config JSON

```json
{
  "url": "https://hooks.example.com/gmail-export",
  "secret": "my-webhook-secret",
  "retries": 3
}
```

### Signature verification

If you set a `secret`, verify the signature on the receiving end:

```python
import hmac, hashlib

def verify(body: bytes, header_sig: str, secret: str) -> bool:
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header_sig)
```

---

## Subprocess plugin

Runs an external executable and writes the event JSON to its stdin. The subprocess must exit with code 0 to be considered successful.

### Configuration

| Field | Required | Default | Description |
|---|---|---|---|
| `executable` | ✅ | — | Path to the executable, e.g. `/usr/local/bin/my-script` |
| `args` | ❌ | `[]` | Additional command-line arguments |
| `timeout_sec` | ❌ | `30` | Maximum execution time in seconds |

### Example config JSON

```json
{
  "executable": "/usr/local/bin/notify.sh",
  "args": ["--mode", "email"],
  "timeout_sec": 15
}
```

### Example script (bash)

```bash
#!/usr/bin/env bash
set -e
# Read JSON from stdin
EVENT=$(cat)
FILENAME=$(echo "$EVENT" | jq -r '.filename')
echo "New attachment saved: $FILENAME"
# ... further processing ...
```

The subprocess receives the full JSON event on stdin. Any output to stdout/stderr is discarded; a non-zero exit code is logged as an error.

---

## Testing plugins

Use the **Test** button on the Plugins page to fire a sample event at any configured plugin. The test result (success or error message) is shown as a toast notification.

---

## Plugin execution order

Plugins are dispatched in the order they were added. Each plugin runs synchronously within the same goroutine as the rule run. A plugin failure is logged but does not prevent the next plugin from running.
