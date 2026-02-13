# Publishing to PyPI

This guide explains how to publish the `export-gmail-attachments-to-nas` package to PyPI.

## Prerequisites

1. **PyPI Account**: Create an account at [pypi.org](https://pypi.org/account/register/)
2. **API Token**: Generate an API token at [pypi.org/manage/account/token/](https://pypi.org/manage/account/token/)
   - Save this token securely - you'll need it for authentication

## One-Time Setup

### 1. Install Build Tools

```bash
pip install build twine
```

### 2. Configure PyPI Credentials

Create or edit `~/.pypirc`:

```ini
[pypi]
username = __token__
password = pypi-YOUR_API_TOKEN_HERE
```

**Important**: Replace `pypi-YOUR_API_TOKEN_HERE` with your actual PyPI API token.

## Publishing Steps

### 1. Update Version

Edit `export_gmail_attachments_to_nas/__init__.py`:

```python
__version__ = '1.0.1'  # Increment version appropriately
```

### 2. Clean Previous Builds

```bash
Remove-Item -Recurse -Force dist, build, *.egg-info -ErrorAction SilentlyContinue
```

### 3. Build the Package

```bash
python -m build
```

This creates:
- `dist/export_gmail_attachments_to_nas-X.Y.Z.tar.gz` (source distribution)
- `dist/export_gmail_attachments_to_nas-X.Y.Z-py3-none-any.whl` (wheel)

### 4. Check the Package

```bash
twine check dist/*
```

Verify that all checks pass.

### 5. Test Upload (Optional but Recommended)

First, test on TestPyPI:

```bash
twine upload --repository testpypi dist/*
```

Then test installation:

```bash
pip install --index-url https://test.pypi.org/simple/ export-gmail-attachments-to-nas
```

### 6. Upload to PyPI

```bash
twine upload dist/*
```

Enter your PyPI credentials when prompted (or use the token from `~/.pypirc`).

### 7. Verify

Visit your package page: https://pypi.org/project/export-gmail-attachments-to-nas/

## Versioning

Follow [Semantic Versioning](https://semver.org/):

- **Major** (1.0.0 → 2.0.0): Breaking changes
- **Minor** (1.0.0 → 1.1.0): New features, backward compatible
- **Patch** (1.0.0 → 1.0.1): Bug fixes

## GitHub Release Workflow (Automated)

For automated publishing, you can create a GitHub Actions workflow:

1. Add your PyPI token as a GitHub secret: `PYPI_API_TOKEN`
2. Create `.github/workflows/publish.yml` (see below)
3. Push a new tag: `git tag v1.0.1 && git push origin v1.0.1`

### Example Workflow

```yaml
name: Publish to PyPI

on:
  release:
    types: [published]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install build twine
      
      - name: Build package
        run: python -m build
      
      - name: Publish to PyPI
        env:
          TWINE_USERNAME: __token__
          TWINE_PASSWORD: ${{ secrets.PYPI_API_TOKEN }}
        run: twine upload dist/*
```

## Quick Reference

```bash
# Complete publishing workflow
Remove-Item -Recurse -Force dist, build, *.egg-info -ErrorAction SilentlyContinue
python -m build
twine check dist/*
twine upload dist/*
```

## Troubleshooting

### "File already exists" error
- You cannot overwrite an existing version on PyPI
- Increment the version number in `__init__.py`

### Authentication failures
- Verify your API token is correct in `~/.pypirc`
- Use `__token__` as username, not your PyPI username

### Import errors after installation
- Ensure all dependencies are listed in `install_requires`
- Check that `MANIFEST.in` includes necessary files
