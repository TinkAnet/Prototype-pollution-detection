# Prototype Pollution Detection Tool

A tool for detecting client-side prototype pollution vulnerabilities in JavaScript code.

**Group Project** - Web Security Class at Johns Hopkins University  
**Team Members:** Letao Zhao, Ethan Lee, Bingyan He, Qi Sun

## Overview

Prototype pollution is a critical vulnerability in JavaScript that occurs when an attacker can inject properties into existing object prototypes. This tool analyzes JavaScript code to identify potential prototype pollution vulnerabilities.

## Features

- 🔍 Static analysis of JavaScript files
- 📁 Recursive directory scanning
- 📊 Detailed vulnerability reports
- 🎯 Multiple severity levels (high, medium, low)
- 💻 Command-line interface
- 📝 JSON output support

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/TinkAnet/Prototype-pollution-detection.git
cd Prototype-pollution-detection

# Install the package
pip install -e .

# Or install with development dependencies
pip install -e ".[dev]"
```

### Using pip (once published)

```bash
pip install prototype-pollution-detector
```

## Usage

### Command-Line Interface

Analyze a single JavaScript file:
```bash
prototype-pollution-detector path/to/file.js
```

Analyze a directory (recursively):
```bash
prototype-pollution-detector path/to/directory/
```

Save results to a JSON file:
```bash
prototype-pollution-detector path/to/file.js -o results.json
```

Enable verbose output:
```bash
prototype-pollution-detector path/to/file.js --verbose
```

Display help:
```bash
prototype-pollution-detector --help
```

### Python API

```python
from pathlib import Path
from prototype_pollution_detector import PrototypePollutionDetector

# Create a detector instance
detector = PrototypePollutionDetector(verbose=True)

# Analyze a file or directory
results = detector.analyze(Path("path/to/file.js"))

# Print results to console
detector.print_results(results)

# Save results to a file
detector.save_results(results, Path("output.json"))
```

## Project Structure

```
Prototype-pollution-detection/
├── src/
│   └── prototype_pollution_detector/
│       ├── __init__.py          # Package initialization
│       ├── cli.py               # Command-line interface
│       ├── detector.py          # Main detector orchestration
│       ├── parser.py            # JavaScript parsing module
│       └── analysis.py          # Vulnerability analysis logic
├── tests/
│   ├── __init__.py
│   ├── test_cli.py              # CLI tests
│   ├── test_detector.py         # Detector tests
│   ├── test_parser.py           # Parser tests
│   └── test_analysis.py         # Analysis tests
├── setup.py                     # Setup configuration
├── pyproject.toml               # Modern Python project configuration
├── requirements.txt             # Package dependencies
├── README.md                    # This file
├── LICENSE                      # MIT License
└── .gitignore                   # Git ignore rules
```

## Development

### Running Tests

```bash
# Run all tests
python -m pytest tests/

# Run with coverage
python -m pytest --cov=prototype_pollution_detector tests/

# Run specific test file
python -m pytest tests/test_cli.py
```

### Code Formatting

```bash
# Format code with black
black src/ tests/

# Check code style
flake8 src/ tests/

# Type checking
mypy src/
```

## Detection Capabilities

This tool currently provides a framework for detecting:

- Direct `__proto__` assignments
- Unsafe merge/extend operations
- User-controlled property access
- Recursive property copying without safeguards

**Note:** The current version provides stubs and a framework. Full detection capabilities will be implemented in future versions.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Johns Hopkins University Web Security Class
- Course instructors and teaching assistants
- Security research community

## Future Work

- [ ] Implement full JavaScript AST parsing
- [ ] Add support for popular JavaScript libraries
- [ ] Taint analysis for user input tracking
- [ ] Integration with CI/CD pipelines
- [ ] VSCode extension
- [ ] Web-based interface

## Contact

For questions or feedback, please open an issue on GitHub.