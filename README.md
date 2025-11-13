# Prototype Pollution Detection Tool

A static analysis tool for detecting prototype pollution vulnerabilities in JavaScript and HTML files using semantic AST analysis and taint tracking.

**Group Project** - Web Security Class at Johns Hopkins University  
**Team:** Letao Zhao, Ethan Lee, Bingyan He, Qi Sun

## What is Prototype Pollution?

Prototype pollution occurs when attackers inject properties into JavaScript object prototypes (like `Object.prototype`). This can lead to security issues like XSS and CSRF attacks. The vulnerability typically occurs when user-controlled data flows into merge/extend functions that copy properties without validating dangerous keys like `__proto__`, `constructor`, or `prototype`.

## Features

- Semantic AST analysis (no regex pattern matching)
- Source-to-sink taint tracking across files
- Detects data flow from sources (JSON.parse, DOM attributes, user input) to sinks (merge/extend functions)
- Cross-file analysis for multi-file codebases
- Guard detection (recognizes hasOwnProperty checks and property exclusion guards)
- Performance optimizations (O(1) parent lookups, precomputed sink functions)
- Detects HTML injection vectors (like pace-js vulnerability)
- GitHub crawler for finding vulnerable code
- LLM-assisted analysis (optional)
- Detailed vulnerability reports with severity levels

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

**Focus: Source-to-sink taint analysis for prototype pollution vulnerabilities**

The detector performs comprehensive taint analysis to track data flow from untrusted sources to vulnerable sink functions. It uses semantic AST analysis (not regex) to identify actual vulnerabilities with high precision.

### Detection Capabilities

#### 1. Source Detection

The tool identifies data sources that could contain user-controlled input:

- **JSON.parse() calls**: `var data = JSON.parse(userInput);`
- **DOM attribute access**: `element.getAttribute('data-config')`, `element.dataset.config`
- **Query selectors**: `document.querySelector('[data-config]')`
- **User input**: Form field values, URL parameters, request bodies

#### 2. Sink Detection

The tool identifies vulnerable operations (sinks) where tainted data could cause prototype pollution:

- **Property assignments**: `target[key] = source[key]` (computed property access)
- **Object.assign**: `Object.assign(target, source)`
- **Object.defineProperty/defineProperties**: Property definition operations
- **Object.setPrototypeOf**: Prototype manipulation
- **Merge/extend functions**: Custom functions that copy properties without validation
- **Library helpers**: Recognizes common library functions like `_.merge`, `$.extend`, `deepmerge`

#### 3. Source-to-Sink Flow Tracking

The tool tracks taint propagation across files:

```javascript
// File: source.js
var userConfig = JSON.parse(element.getAttribute('data-config'));  // SOURCE

// File: sink.js  
function extend(target, source) {
    for (var key in source) {
        target[key] = source[key];  // SINK - no validation
    }
}

// File: main.js
extend({}, userConfig);  // FLOW: tainted data flows from source to sink
```

**Detection**: The tool detects that `userConfig` is tainted from a JSON.parse source and flows into the vulnerable `extend` function, creating a prototype pollution vulnerability.

#### 4. Guard Recognition

The tool recognizes when sinks are protected by validation:

- **Property exclusion**: `if (key !== '__proto__' && key !== 'constructor' && key !== 'prototype')`
- **hasOwnProperty checks**: `if (source.hasOwnProperty(key))` or `Object.prototype.hasOwnProperty.call(source, key)`
- **Safe targets**: `Object.assign(Object.create(null), source)` (null prototype is safer)

**Severity**: 
- HIGH: Sink with no validation
- MEDIUM: Sink with partial validation or safe target
- LOW: Sink with full validation (still reported for awareness)

#### 5. Direct Dangerous Property Assignments

```javascript
obj.__proto__.polluted = "test";  // HIGH severity
```

**Detection**: Finds direct assignments to `__proto__`, `constructor`, or `prototype`.

**Severity**: HIGH

### Analysis Approach

- **Semantic AST Analysis**: Uses Abstract Syntax Tree traversal instead of regex patterns
- **Cross-file Analysis**: Tracks taint across multiple files in a codebase
- **Performance Optimized**: 
  - Single-pass AST indexing with parent pointers
  - O(1) sink function lookups
  - Precomputed function indexes
- **Accurate Guard Detection**: Walks AST ancestors to detect guards that protect sinks
- **Deduplication**: Prevents duplicate vulnerability reports

## Python API

```python
from prototype_pollution_detector import PrototypePollutionDetector

detector = PrototypePollutionDetector()
results = detector.analyze(Path("file.js"))
detector.print_results(results)
```

## Examples

See `examples/` directory for complete test cases:

- `example1_client_side_json_parse/` - Client-side JSON.parse source to merge sink
- `example2_server_side_nodejs/` - Server-side Node.js request parsing to merge sink
- `example3_mixed_html_js/` - Mixed HTML and JavaScript with DOM sources
- `example4_dom_chain/` - Complex DOM attribute extraction to merge sink
- `example5_express_server/` - Express.js server with request body parsing

Each example demonstrates source-to-sink data flow across different files, showing how the tool detects taint propagation.

## Documentation

- [Quick Start Guide](QUICKSTART.md) - Get started quickly
- [Detection Logic](DETECTION_LOGIC.md) - How detection works
- [Design Document](DESIGN.md) - Architecture details

## Contributing

Contributions welcome! Fork, create a branch, and submit a PR.

## License

MIT License - see [LICENSE](LICENSE) file.
