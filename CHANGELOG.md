# Changelog

## Version 0.2.1 (November 26, 2025)

### Analysis Engine Improvements

- **Reduced false positives by 6.2%** (102 vulnerabilities eliminated)
- **Enhanced guard recognition**: `hasOwnProperty` now treated as full validation
- **Object.keys() detection**: Recognizes safe iteration patterns
- **Framework support**: Added jQuery, Lodash safe pattern recognition
- **Better taint path reporting**: Clear visualization of data flow from source to sink

### Technical Changes

- Enhanced `_is_guarded()` to recognize Object.keys() and property whitelisting
- Improved `_get_function_name_from_ast()` to handle deep member expression chains
- Added `_is_likely_user_controlled_json_parse()` for smarter source detection
- Added support for hasOwnProperty aliases (hasOwn, hop, etc.)
- Improved `Object.create(null)` validation

### Bug Fixes

- Fixed: `Object.prototype.hasOwnProperty.call` not recognized
- Fixed: `Object.keys()` iteration flagged as vulnerable
- Fixed: jQuery's `hasOwn` alias not recognized
- Fixed: Taint path messages unclear

### Impact

- MEDIUM severity false positives reduced by 9.7% (81 vulnerabilities)
- 5 files completely cleaned (e.g., gruntfile.js: 3 → 0)
- jQuery files improved by 10-13%
- deepCopy.js improved by 33%

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
