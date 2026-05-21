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

## Assignments

A rule can be assigned to multiple **Gmail accounts** and multiple **file shares** simultaneously. Each combination runs independently — useful for mirroring the same attachments to a backup share, or exporting from several accounts under a single rule.

---

## Scheduler interval

The interval between rule runs is set globally in **Settings → Scheduler interval (minutes)**. The default is 60 minutes. Changes take effect after a service restart.
