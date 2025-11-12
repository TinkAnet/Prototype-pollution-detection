# Quick Start Guide

Get up and running in 5 minutes.

## 1. Install

```bash
git clone <repository-url>
cd Prototype-pollution-detection
pip install -r requirements.txt
pip install -e .
```

## 2. Configure (Optional)

For GitHub crawler, create `.env`:

```bash
cp .env.example .env
# Edit .env and add: GITHUB_TOKEN=your_token
```

Get token: https://github.com/settings/tokens

## 3. Use

### Analyze Files

```bash
prototype-pollution-detector analyze examples/unsafe_extend.js
```

### Crawl GitHub

```bash
prototype-pollution-detector crawl --max-results 20 -o results.json
```

## Common Issues

**"Requires authentication"** → Add `GITHUB_TOKEN` to `.env`

**"PyGithub not installed"** → Run `pip install -r requirements.txt`

**No vulnerabilities found** → Check file extensions (.js, .html)

## Next Steps

- Read [README.md](README.md) for full documentation
- Check [examples/](examples/) for sample vulnerable code
