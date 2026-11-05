# Squid Log Analyzer CLI

Command-line tool to analyze Squid Proxy access logs supporting plain text and `.gz` streams.

## Features
- **Streaming Parser**: Memory-efficient line-by-line processing of large log files and gzip archives (`.gz`).
- **Comprehensive Metrics**:
  - Most Frequent IP (`--mfip`)
  - Least Frequent IP (`--lfip`)
  - Events Per Second (`--eps`)
  - Total Bytes Transferred (`--bytes`)
- **JSON Output**: Clean, structured output written directly to the target destination.
- **Robust Error Handling**: Graceful recovery from malformed records with informative logging.
- **Production-Ready Packaging**: Conforms to PEP 621 packaging standards with unit tests and multi-stage Docker build.

## Local Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

To install development dependencies (testing and linting):
```bash
pip install -e ".[dev]"
pytest
```

## CLI Usage

```bash
log-analyzer \
  --input /path/to/access.log.gz \
  --output /path/to/report.json \
  --mfip --lfip --eps --bytes
```

If no analytical flags are passed, all metrics are computed by default:
```bash
log-analyzer -i access.log -o results.json
```

## Running with Docker

Build the Docker image:
```bash
docker build -t log-analyzer .
```

Run container with mounted volume:
```bash
docker run --rm \
  -v $(pwd)/data:/data \
  log-analyzer \
  --input /data/access.log.gz \
  --output /data/output.json \
  --mfip --lfip --eps --bytes
```
