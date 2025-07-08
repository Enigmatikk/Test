# YARA Testing Framework

A lightweight framework for testing YARA rules against files and directories.

## Features

- Test YARA rules against individual files or entire directories
- Generate detailed match reports in various formats (JSON, CSV, console)
- Validate YARA rule syntax
- Support for rule tagging and categorization
- Performance metrics for rule execution

## Installation

1. Clone this repository
2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```python
from yara_test_framework import YaraTestFramework

# Initialize framework
ytf = YaraTestFramework()

# Add YARA rules
ytf.add_rule_file("path/to/rules.yar")

# Test against a file
results = ytf.scan_file("path/to/sample/file")

# Print results
ytf.print_results(results)
```

### Directory Scanning

```python
# Scan entire directory
results = ytf.scan_directory("path/to/samples/", recursive=True)

# Export results to JSON
ytf.export_results(results, "results.json", format="json")
```

### Rule Validation

```python
# Validate YARA rule syntax
valid, errors = ytf.validate_rule("path/to/rule.yar")
if not valid:
    print(f"Rule validation failed: {errors}")
```

## Command Line Interface

The framework also provides a command-line interface:

```bash
python yara_test_framework.py --rules rules.yar --target /path/to/scan --recursive --output results.json
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.