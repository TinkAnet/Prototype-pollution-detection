# Test Commands for PolluTaint

This guide provides ready-to-use command-line examples for testing PolluTaint's crawler and batch analyzer functionality.

## Prerequisites

Make sure you have installed the package:

```bash
pip install -r requirements.txt
pip install -e .
```

## Test Commands

### 1. Test Regular Analyze Command

#### Single File Analysis

```bash
# Test with a known vulnerable file
pollutaint analyze crawler_sources/bohewei/SKY/jq.js -v

# Save results to file
pollutaint analyze crawler_sources/bohewei/SKY/jq.js -v -o test_single_file.json

# Test with another file
pollutaint analyze crawler_sources/william-simon/william-simon.github.io/ua.js -v
```

#### Directory Analysis

```bash
# Analyze a single repository directory
pollutaint analyze crawler_sources/bohewei/SKY/ -v -o test_repo.json

# Analyze multiple repositories
pollutaint analyze crawler_sources/bohewei/ -v -o test_owner.json

# Analyze all crawled sources (large test)
pollutaint analyze crawler_sources/ -v -o test_all_sources.json
```

### 2. Test Batch Analyzer

The batch analyzer is optimized for analyzing crawled sources with cross-file analysis.

#### Basic Batch Analysis

```bash
# Analyze all crawled sources (uses organized structure automatically)
pollutaint batch-analyze crawler_sources/ -v

# With custom output
pollutaint batch-analyze crawler_sources/ -v -o custom_batch_results.json

# Limit files per repository (faster testing)
pollutaint batch-analyze crawler_sources/ --max-files-per-repo 5 -v
```

#### Analyze Specific Repository

```bash
# Analyze a single repository
pollutaint batch-analyze crawler_sources/bohewei/SKY/ -v

# Analyze multiple repositories from same owner
pollutaint batch-analyze crawler_sources/bohewei/ -v
```

#### Quick Test (Small Dataset)

```bash
# Test with just a few repositories (create a test directory first)
mkdir -p test_sources/bohewei/SKY
cp crawler_sources/bohewei/SKY/jq.js test_sources/bohewei/SKY/

mkdir -p test_sources/william-simon/william-simon.github.io
cp crawler_sources/william-simon/william-simon.github.io/ua.js test_sources/william-simon/william-simon.github.io/

# Analyze test directory
pollutaint batch-analyze test_sources/ -v
```

### 3. Test GitHub Crawler

**Note:** Requires `GITHUB_TOKEN` in `.env` file. If you don't have a token, skip this section and test batch-analyze instead.

#### Basic GitHub Crawl

```bash
# Small test crawl (10 results)
pollutaint crawl --max-results 10 -v

# Medium crawl (50 results)
pollutaint crawl --max-results 50 -v

# Large crawl (100 results) - takes longer
pollutaint crawl --max-results 100 -v
```

#### Crawl Specific Repository

```bash
# Crawl a specific repository
pollutaint crawl --repo bohewei/SKY -v

# Another repository
pollutaint crawl --repo william-simon/william-simon.github.io -v
```

#### Crawl with Filters

```bash
# JavaScript only
pollutaint crawl --max-results 20 --languages javascript -v

# TypeScript only
pollutaint crawl --max-results 20 --languages typescript -v

# Multiple languages
pollutaint crawl --max-results 20 --languages javascript typescript -v

# Minimum stars filter
pollutaint crawl --max-results 20 --min-stars 10 -v
```

#### Crawl Without LLM Filter (Faster)

```bash
# Skip LLM filtering for faster results
pollutaint crawl --max-results 50 --no-llm -v

# Skip analysis (just crawl, don't analyze)
pollutaint crawl --max-results 50 --skip-analysis -v
```

### 4. Complete Workflow Test

#### Full Pipeline: Crawl → Batch Analyze

```bash
# Step 1: Crawl GitHub (saves to data/crawled/TIMESTAMP/sources/)
pollutaint crawl --max-results 20 --no-llm -v

# Step 2: Find the latest crawl directory
# (Check data/crawled/ for the latest timestamp directory)

# Step 3: Batch analyze the crawled sources
pollutaint batch-analyze data/crawled/latest/sources/ -v

# Or use the timestamp directly
pollutaint batch-analyze data/crawled/2024-01-15_14-30-00/sources/ -v
```

### 5. Quick Test Script

Create a test script `test_quick.sh`:

```bash
#!/bin/bash
# Quick test script for PolluTaint

echo "=== Test 1: Analyze Single File ==="
pollutaint analyze crawler_sources/bohewei/SKY/jq.js -v

echo ""
echo "=== Test 2: Batch Analyze Small Dataset ==="
mkdir -p test_data/bohewei/SKY
cp crawler_sources/bohewei/SKY/jq.js test_data/bohewei/SKY/
pollutaint batch-analyze test_data/ -v

echo ""
echo "=== Test 3: Analyze Directory ==="
pollutaint analyze crawler_sources/bohewei/SKY/ -v

echo ""
echo "Tests complete!"
```

Make it executable and run:
```bash
chmod +x test_quick.sh
./test_quick.sh
```

## Expected Output

### Analyze Command Output

```
Analyzing file: crawler_sources/bohewei/SKY/jq.js
Performing cross-file taint analysis...

=== Analysis Results for crawler_sources/bohewei/SKY/jq.js ===

Vulnerabilities found: X

[HIGH] Line Y, Column Z
Type: source_to_sink_pollution
Message: Function 'extend' receives data from json_parse source...
Code: ...
```

### Batch Analyze Output

```
Analyzing crawled sources in: crawler_sources/
Found 19 repositories
Total files: 19

Analyzing repository: bohewei/SKY (1 files)
...

Batch Analysis Summary
================================================================================

Repositories analyzed: 19
Total files: 19
Total vulnerabilities: 1109

Average vulnerabilities per repository: 58.37
Average vulnerabilities per file: 58.37

Severity distribution:
  HIGH: 1109
  MEDIUM: 0
  LOW: 0

Results saved to organized structure: results/batch/2024-01-15_14-30-00/
```

### Crawl Command Output

```
Starting GitHub crawl...
Crawled sources will be saved to: data/crawled/2024-01-15_14-30-00/sources/
Step 1: Searching GitHub for vulnerable code patterns...
Found X potential code snippets from GitHub
Step 2: Filtering results with LLM...
Step 3: Analyzing code snippets with detector...
...

Results saved to: results/crawl/2024-01-15_14-30-00/summary.json
Crawl session directory: data/crawled/2024-01-15_14-30-00
Results directory: results/crawl/2024-01-15_14-30-00
```

## Troubleshooting

### "Command not found: pollutaint"

```bash
# Reinstall the package
pip install -e .

# Or use Python module directly
python3 -m prototype_pollution_detector.cli analyze crawler_sources/bohewei/SKY/jq.js -v
```

### "GITHUB_TOKEN not set" (for crawler)

```bash
# Create .env file
echo "GITHUB_TOKEN=your_token_here" > .env

# Or skip GitHub crawler and test batch analyzer instead
pollutaint batch-analyze crawler_sources/ -v
```

### "No vulnerabilities found"

This is normal if:
- The file doesn't contain vulnerable patterns
- The code has proper guards/validation
- Try a different file: `pollutaint analyze crawler_sources/bohewei/SKY/jq.js -v`

## Performance Testing

### Small Test (Fast)

```bash
# Single file - should complete in seconds
pollutaint analyze crawler_sources/bohewei/SKY/jq.js -v
```

### Medium Test (1-2 minutes)

```bash
# Single repository
pollutaint batch-analyze crawler_sources/bohewei/SKY/ -v
```

### Large Test (5-10 minutes)

```bash
# All crawled sources
pollutaint batch-analyze crawler_sources/ -v
```

## Verification

After running tests, check the results:

```bash
# View latest batch results
cat results/batch/latest/summary.json | python3 -m json.tool | head -50

# View latest crawl results
cat results/crawl/latest/summary.json | python3 -m json.tool | head -50

# Count vulnerabilities
cat results/batch/latest/summary.json | python3 -c "import sys, json; data=json.load(sys.stdin); print(f'Total: {data[\"total_vulnerabilities\"]}')"
```

## Recommended Test Sequence

1. **Start Small**: Test single file analysis
   ```bash
   pollutaint analyze crawler_sources/bohewei/SKY/jq.js -v
   ```

2. **Test Batch**: Test batch analyzer on small dataset
   ```bash
   pollutaint batch-analyze crawler_sources/bohewei/SKY/ -v
   ```

3. **Test Crawler** (if you have GITHUB_TOKEN):
   ```bash
   pollutaint crawl --max-results 10 --no-llm -v
   ```

4. **Full Test**: Test complete workflow
   ```bash
   pollutaint batch-analyze crawler_sources/ -v
   ```

