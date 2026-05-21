# Rules

Rules define _what_ to export and _where_ to save it. Each rule is a combination of:

- A **Gmail query** that selects messages
- A **subfolder template** that determines the save path within the file share
- Optional **PDF→PNG conversion**
- One or more **account + file share** assignments

---

## Gmail query syntax

Rules use [Gmail search operators](https://support.google.com/mail/answer/7190). Some useful examples:

| Goal | Query |
|---|---|
| Subject contains "Invoice" | `subject:Invoice` |
| Has a PDF attachment | `filename:.pdf` |
| From a specific sender | `from:billing@example.com` |
| Received this year | `after:2024/01/01` |
| Unread messages only | `is:unread` |
| Combine conditions | `from:billing@example.com subject:Invoice filename:.pdf` |

> **Tip:** Use the **Preview** button in the rule builder to run the query against a real Gmail account and see up to 10 matching messages before saving the rule.

> **Inline validation:** The query field validates your input as you type. If an operator is misspelled or its value is in the wrong format (for example `newer_than:30x` instead of `newer_than:30d`), a warning list appears below the field immediately — no need to save first.

---

## Subfolder template

The **Subfolder template** field controls the directory structure within the file share. You can use static paths or dynamic placeholders:

| Placeholder | Value |
|---|---|
| `{year}` | 4-digit year from the email date, e.g. `2024` |
| `{month}` | 2-digit month, e.g. `03` |
| `{day}` | 2-digit day, e.g. `15` |
| `{sender}` | Sender address (unsafe path characters replaced with `_`) |
| `{subject}` | Email subject (unsafe path characters replaced with `_`) |

### Examples

| Template | Result for a 15 Mar 2024 email from billing@example.com |
|---|---|
| `invoices/{year}/{month}` | `invoices/2024/03/invoice.pdf` |
| `{year}-{month}-{day}` | `2024-03-15/invoice.pdf` |
| `by-sender/{sender}` | `by-sender/billing@example.com/invoice.pdf` |
| _(empty)_ | `invoice.pdf` (saved at the share root / base path) |

Characters that are not allowed in file system paths (`/ \ : * ? " < > |`) in `{sender}` and `{subject}` are replaced with underscores.

---

## PDF → PNG conversion

When **Convert PDF to PNG** is enabled, the service:

1. Saves the original PDF attachment to the file share.
2. Converts each page of the PDF to a PNG image at 150 DPI using `pdftoppm` (bundled in the Docker image via `poppler-utils`).
3. Saves each page image alongside the PDF, named `<original>_page_001.png`, `<original>_page_002.png`, etc.

This requires `poppler-utils` to be installed in the runtime environment. It is included in the provided `Dockerfile`.

---

## Delete after export

When **Delete after export** is enabled on a rule, the Gmail message is permanently deleted after all its attachments have been successfully saved. Use with care — this is irreversible.

> The message is only deleted if every file share save succeeds. A partial failure leaves the message in place.

---

## Assignments

A rule can be assigned to multiple **Gmail accounts** and multiple **file shares** simultaneously. Each combination runs independently — useful for mirroring the same attachments to a backup share, or exporting from several accounts under a single rule.

---

## Run now

Use the **Run now** button on any rule card to trigger an immediate execution outside the normal schedule. The run fires in the background; results appear in the **Logs** page.

---

## Schedule

Each rule has its own schedule. When a rule's schedule is left empty it falls back to the global **Settings → Scheduler interval (minutes)** value (default: 60 minutes).

### Schedule types

| Type | Description |
|---|---|
| **Interval** | Repeat every N minutes, hours, or days (e.g. `30m`, `4h`, `7d`). Runs immediately when the service starts. |
| **Daily** | Run once per day at a fixed time. |
| **Weekly** | Run on selected days of the week at a fixed time. |
| **Monthly** | Run on a specific day of the month at a fixed time. |
| **Once** | Run at a single point in time, then stop. |

All schedule types accept an optional **Until** date; the rule stops scheduling new runs after that date.

### Global fallback interval

The global interval is stored in the database and read on every tick — changing it in **Settings** takes effect at the next scheduled check, without a service restart.
