# Publishing

This project is distributed as a Docker image, automatically built and pushed to the GitHub Container Registry (ghcr.io) on every GitHub Release.

## Table of Contents
- [Automated Docker publish (GitHub Actions)](#automated-docker-publish)
- [Manual Docker build and push](#manual-docker-build-and-push)
- [Running a specific release](#running-a-specific-release)

---

## Automated Docker publish

The workflow [`.github/workflows/publish-package.yml`](.github/workflows/publish-package.yml) triggers on every published GitHub Release. It:

1. Builds a multi-arch Docker image (`linux/amd64`, `linux/arm64`) — including the frontend build step.
2. Pushes it to `ghcr.io/pacorreia/export-gmail-attachments-to-nas` with the version tag and `latest`.

**Steps to publish a new release:**

1. **Update the version tag** (optional — the image tag comes from the git tag):
   ```bash
   git tag v1.2.0
   git push origin v1.2.0
   ```

2. **Create a GitHub Release** from the tag:
   - Go to your repo → **Releases** → **Draft a new release**
   - Select the tag you just pushed (`v1.2.0`)
   - Fill in release title and notes
   - Click **Publish release**

3. The `Publish Docker Image` workflow runs automatically and pushes:
   - `ghcr.io/pacorreia/export-gmail-attachments-to-nas:1.2.0`
   - `ghcr.io/pacorreia/export-gmail-attachments-to-nas:1.2`
   - `ghcr.io/pacorreia/export-gmail-attachments-to-nas:latest`

No additional secrets are needed — the workflow uses `GITHUB_TOKEN` to authenticate with ghcr.io.

---

## Manual Docker build and push

```bash
# Build locally (includes Node.js frontend build inside the Dockerfile)
docker build -t ghcr.io/pacorreia/export-gmail-attachments-to-nas:dev .

# Push (requires docker login ghcr.io first)
docker login ghcr.io -u <your-github-username> --password-stdin <<< "$GITHUB_TOKEN"
docker push ghcr.io/pacorreia/export-gmail-attachments-to-nas:dev
```

Multi-arch build with buildx:
```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ghcr.io/pacorreia/export-gmail-attachments-to-nas:dev \
  --push .
```

---

## Running a specific release

```bash
# Pull and run a specific version
docker run -d \
  -p 8080:8080 \
  -v ./data:/data \
  -e SECRET_KEY=$(openssl rand -hex 32) \
  -e GOOGLE_CLIENT_ID=your-client-id \
  -e GOOGLE_CLIENT_SECRET=your-client-secret \
  ghcr.io/pacorreia/export-gmail-attachments-to-nas:1.2.0

# Or use docker compose (recommended)
docker compose up -d
```

## Table of Contents
- [GitHub Releases](#github-releases) (Easiest, Automated)
- [PyPI](#pypi)
- [Direct Git Installation](#direct-git-installation)

---

## GitHub Releases

GitHub Releases allow you to attach built packages to version tags. This is automated through GitHub Actions.

### Advantages
- Integrated with GitHub repository
- Automatic via GitHub Actions
- No separate credentials needed
- Users can download packages directly

### Publishing via GitHub Actions (Automated)

The included workflow [`.github/workflows/publish-package.yml`](.github/workflows/publish-package.yml) automatically:
1. Builds the package
2. Attaches `.tar.gz` and `.whl` files to the release
3. Optionally publishes to PyPI (if configured)

**Steps to publish:**

1. **Update version** in `export_gmail_attachments_to_nas/__init__.py`:
   ```python
   __version__ = '1.0.1'
   ```

2. **Commit and push** the version change:
   ```bash
   git add export_gmail_attachments_to_nas/__init__.py
   git commit -m "Bump version to 1.0.1"
   git push
   ```

3. **Create a new release** on GitHub:
   - Go to your repo → **Releases** → **Create a new release**
   - Click **Choose a tag** → type `v1.0.1` → **Create new tag**
   - Fill in release title and notes
   - Click **Publish release**

4. **Workflow runs automatically** and attaches packages to the release

### Installing from GitHub Releases

Users can install directly from the release:

```bash
# Install latest release
pip install https://github.com/pacorreia/export-gmail-attachments-to-nas/releases/latest/download/export_gmail_attachments_to_nas-1.0.0-py3-none-any.whl

# Or specific version
pip install https://github.com/pacorreia/export-gmail-attachments-to-nas/releases/download/v1.0.1/export_gmail_attachments_to_nas-1.0.1-py3-none-any.whl
```

---

## Direct Git Installation

Users can install directly from the GitHub repository:

```bash
# Install from main branch
pip install git+https://github.com/pacorreia/export-gmail-attachments-to-nas.git

# Install specific version/tag
pip install git+https://github.com/pacorreia/export-gmail-attachments-to-nas.git@v1.0.1

# Install specific branch
pip install git+https://github.com/pacorreia/export-gmail-attachments-to-nas.git@feature-branch
```

---

## PyPI (Optional)

PyPI (Python Package Index) is the official package repository for Python. Publishing here makes your package available via `pip install export-gmail-attachments-to-nas`.

### Advantages
- Standard Python installation method (`pip install`)
- Discoverable through PyPI search
- Official Python ecosystem

### Automatic PyPI Publishing

The workflow [`.github/workflows/publish-package.yml`](.github/workflows/publish-package.yml) can automatically publish to PyPI when you create a release.

**To enable:**

1. **Create PyPI Account**: [pypi.org/account/register/](https://pypi.org/account/register/)

2. **Generate API Token**: [pypi.org/manage/account/token/](https://pypi.org/manage/account/token/)

3. **Add GitHub Secret**:
   - Go to your repo → **Settings** → **Secrets and variables** → **Actions**
   - Click **New repository secret**
   - Name: `PYPI_API_TOKEN`
   - Value: Your PyPI token (starting with `pypi-...`)
   - Click **Add secret**

4. **Create a release** - The workflow will automatically publish to both GitHub Releases and PyPI!

### Manual PyPI Publishing

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

## Quick Reference

**GitHub Release (Recommended):**
```bash
# Update version, commit, push, then create GitHub release - workflow handles the rest
```

**Manual PyPI Publishing:**
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
