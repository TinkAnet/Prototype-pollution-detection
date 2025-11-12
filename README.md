# Prototype Pollution Detection Tool

A static analysis tool for detecting client-side prototype pollution vulnerabilities in JavaScript and HTML files.

**Group Project** - Web Security Class at Johns Hopkins University  
**Team:** Letao Zhao, Ethan Lee, Bingyan He, Qi Sun

## What is Prototype Pollution?

Prototype pollution occurs when attackers inject properties into JavaScript object prototypes (like `Object.prototype`). This can lead to security issues like XSS and CSRF attacks.

## Features

- ✅ Static analysis of JavaScript and HTML files
- ✅ Detects HTML injection vectors (like pace-js vulnerability)
- ✅ GitHub crawler for finding vulnerable code
- ✅ LLM-assisted analysis (optional)
- ✅ Detailed vulnerability reports with severity levels

## Quick Start

### Installation

```bash
# Clone and install
git clone https://github.com/TinkAnet/Prototype-pollution-detection.git
cd Prototype-pollution-detection
pip install -r requirements.txt
pip install -e .
```

### Setup API Keys

Create a `.env` file:

```bash
cp .env.example .env
```

Add your keys:
- `GITHUB_TOKEN` - **Required** for GitHub crawler (create at https://github.com/settings/tokens)
- `OPENAI_API_KEY` - Optional for LLM analysis

## Usage

### Analyze Local Files

```bash
# Single file
prototype-pollution-detector analyze file.js

# Directory
prototype-pollution-detector analyze src/

# Save results
prototype-pollution-detector analyze file.js -o results.json
```

### Crawl GitHub

```bash
# Search GitHub
prototype-pollution-detector crawl --max-results 50 -o results.json

# Specific repository
prototype-pollution-detector crawl --repo owner/repo -o results.json
```

## What It Detects

**Focus: Detecting recursive/deep merge functions vulnerable to prototype pollution**

The detector analyzes all functions to identify recursive/deep merge functions that traverse nested objects without validating dangerous properties. These are the main source of prototype pollution vulnerabilities.

### 1. Vulnerable Recursive Merge Functions
```javascript
// Recursive merge - traverses nested objects
function extend(out, src) {
    for (key in src) {
        val = src[key];
        if (out[key] != null && typeof out[key] === 'object' && typeof val === 'object') {
            extend(out[key], val);  // Recursive call - VULNERABLE!
        } else {
            out[key] = val;  // No validation of __proto__, constructor, prototype
        }
    }
}
```

**Detection**: 
- Analyzes ALL functions, not just those with suspicious names
- Detects recursive merge patterns: functions that call themselves recursively
- Detects deep merge patterns: functions that check `typeof === 'object'` and merge nested objects
- Checks if functions validate dangerous properties (`__proto__`, `constructor`, `prototype`) before recursive merging

**Why Recursive Merges are Dangerous**: 
- They traverse nested objects recursively
- When encountering `__proto__` as a key, they recursively merge into `Object.prototype`
- This allows attackers to pollute the prototype chain

**Severity**: HIGH if no validation, MEDIUM if partial validation

### 2. Direct Dangerous Property Assignments
```javascript
obj.__proto__.polluted = "test";  // HIGH severity
```

**Detection**: Finds direct assignments to `__proto__`, `constructor`, or `prototype`.

**Severity**: HIGH

## Python API

```python
from prototype_pollution_detector import PrototypePollutionDetector

detector = PrototypePollutionDetector()
results = detector.analyze(Path("file.js"))
detector.print_results(results)
```

## Examples

See `examples/` directory:
- `pace_vulnerability.html` - HTML injection example
- `unsafe_extend.js` - Vulnerable code
- `safe_extend.js` - Safe version

## Documentation

- [Quick Start Guide](QUICKSTART.md) - Get started quickly
- [Detection Logic](DETECTION_LOGIC.md) - How detection works
- [Design Document](DESIGN.md) - Architecture details

## Contributing

Contributions welcome! Fork, create a branch, and submit a PR.

## License

MIT License - see [LICENSE](LICENSE) file.
