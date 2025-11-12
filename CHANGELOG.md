# Changelog

## Version 0.2.0

### New Features

- **GitHub Crawler**: Search GitHub for vulnerable code
- **LLM Analysis**: Optional AI-powered filtering (requires OpenAI API key)
- **Better CLI**: Subcommands (`analyze` and `crawl`)

### Changes

- CLI now uses subcommands: `prototype-pollution-detector analyze file.js`
- GitHub token required for crawler
- Improved HTML injection detection

### Dependencies

- Added: PyGithub, openai, python-dotenv, requests, ratelimit

## Version 0.1.0

Initial release with basic detection capabilities.
