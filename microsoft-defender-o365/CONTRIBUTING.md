# Contributing to Microsoft Defender for Office 365 Collector

This document provides guidance for contributing to the Microsoft Defender for Office 365 collector for OpenAEV. This collector is scaffolded from the OpenAEV collector template and is under active implementation (MVP1 - email focused: collect and match Defender for O365 alerts).

## Current Implementation Status

**IN PROGRESS**: The `src` and `tests` directories are not yet implemented for this collector. The scaffolding below reflects the target architecture inherited from the template and will be completed as the collector is built out.

### Core Components (to implement)
-  **Collector Core** (`src/collector/collector.py`) - Main daemon with Microsoft Defender for Office 365 service integration
-  **Expectation Handler** (`src/collector/expectation_handler.py`) - Generic handler using service provider pattern
-  **Expectation Manager** (`src/collector/expectation_manager.py`) - Batch processing and API interactions
-  **Configuration System** (`src/models/configs/`) - Hierarchical configuration with Microsoft Defender for Office 365 settings
-  **Service Providers** - Microsoft Defender for Office 365-specific implementation

### Microsoft Defender for Office 365 Implementation (to implement)
-  **Data Fetcher** (`src/services/fetcher_data.py`) - Email alert data correlation
-  **Expectation Service** (`src/services/expectation_service.py`) - Business logic implementation
-  **Trace Service** (`src/services/trace_service.py`) - Trace creation
-  **Data Converter** (`src/services/converter.py`) - Microsoft Defender for Office 365 to OAEV format conversion

### Supported Features (target)
-  **Signature Support**: `start_date`, `end_date`
-  **Retry Mechanism**: Configurable retries with ingestion delay handling
-  **Trace Generation**: Links back to external tool available
-  **Error Handling**: Comprehensive exception handling and logging
-  **Configuration Management**: YAML, environment variables, defaults

## Installation and Setup

### Poetry Dependency Groups

- `--with dev`: Development tools (ruff, mypy, black, etc.)
- `--with test`: Testing tools (pytest, coverage, etc.)

### Poetry Extras

- `--extra prod`: Get pyoaev from PyPI (production releases)
- `--extra current`: Get pyoaev from Git release/current branch
- `--extra local`: Get pyoaev locally from `../../client-python`

### Development Installation

```bash
# Development setup with current pyoaev version
poetry install -E current --with dev,test

# Production setup
poetry install -E prod

# Local development with local pyoaev
poetry install -E local --with dev,test
```

### Running the Collector

```bash
# Direct execution
MicrosoftDefenderO365Collector

# Using Python module execution
python -m src

# Using Poetry to run
poetry run python -m src
```

## Development Workflow

### Setting Up Development Environment

1. **Clone and Install**:
   ```bash
   git clone <collector-repo>
   cd microsoft-defender-o365
   poetry install -E current --with dev,test
   ```

2. **Configure for Development**:
   ```bash
   # Copy sample config
   cp src/config.yml.sample src/config.yml

   # Edit with your Microsoft Defender for Office 365 details
   vim src/config.yml
   ```

3. **Run Development Tools**:
   ```bash
   # Format code
   poetry run black src/

   # Lint code
   poetry run ruff check src/

   # Type checking
   poetry run mypy src/

   # Run tests
   poetry run pytest
   ```

### Code Organization

The codebase follows a clean architecture with clear separation of concerns:

```
src/
├── collector/          # Generic collector framework
│   ├── collector.py    # Main collector daemon
│   ├── expectation_handler.py
│   ├── expectation_manager.py
│   ├── trace_manager.py
│   └── models.py       # Pydantic data models
├── services/           # Microsoft Defender for Office 365-specific implementation
│   ├── expectation_service.py  # Business logic
│   ├── trace_service.py        # Trace creation
│   ├── converter.py    # Data conversion
│   ├── fetcher_*.py    # Data fetchers
│   └── model_*.py      # Data models
└── models/             # Configuration management
    └── configs/        # Hierarchical config system
```

## Testing

### Test Structure

```bash
# Run all tests
poetry run pytest

# Run specific test files
poetry run pytest tests/test_expectation_service.py

# Run with verbose output
poetry run pytest -v
```

### Test Categories

- **Unit Tests**: Test individual components in isolation
- **Integration Tests**: Test external tool interactions
- **Configuration Tests**: Validate config loading and validation
- **Service Provider Tests**: Test expectation handling logic

## Code Quality Standards

### Formatting and Linting

- **Black**: Code formatting (line length: 88)
- **Ruff**: Fast Python linter
- **MyPy**: Static type checking
- **Pre-commit**: Automated checks before commits

### Code Style Guidelines

- Use type hints throughout
- Follow Python PEP 8 conventions
- Write descriptive docstrings for public methods
- Implement comprehensive error handling
- Add meaningful logging with appropriate levels
- Use Pydantic models for data validation

### Error Handling Patterns

```python
# Use custom exceptions from src/collector/exception.py
from src.collector.exception import CollectorProcessingError

try:
    result = process_expectation(expectation)
except MicrosoftDefenderO365ServiceError as e:
    logger.error(f"Microsoft Defender for Office 365 error: {e}")
    raise CollectorProcessingError(f"Processing failed: {e}") from e
```

### Logging Best Practices

```python
# Use consistent log prefixes
LOG_PREFIX = "[ComponentName]"

# Include context in error logs
logger.error(
    f"{LOG_PREFIX} Error processing expectation: {e} "
    f"(Context: expectation_id={expectation_id}, retry_count={retries})"
)
```

## Contributing Guidelines

### Making Changes

1. **Create Feature Branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Changes**:
   - Follow existing code patterns
   - Add/update tests
   - Update documentation
   - Ensure type hints are complete

3. **Test Changes**:
   ```bash
   poetry run pytest
   poetry run mypy src/
   poetry run ruff check src/
   ```

4. **Commit and Push**:
   ```bash
   git add .
   git commit -m "feat: description of your changes"
   git push origin feature/your-feature-name
   ```

### Pull Request Guidelines

- Provide clear description of changes
- Update documentation as needed
- Ensure all CI checks pass
- Request review from maintainers

### Extending the Collector

#### Adding New Signature Types

1. Update `SUPPORTED_SIGNATURES` in `src/services/expectation_service.py`
2. Update fetching processes in `src/services/fetcher_data.py`
3. Update data conversion logic in `src/services/converter.py`
4. Add corresponding tests

#### Adding New API Endpoints

1. Create fetcher class following pattern of existing fetchers
2. Update client API to use new fetcher
3. Add data models in `src/services/model_*.py`
4. Update service provider logic

#### Configuration Changes

1. Add fields to appropriate config models in `src/models/configs/`
2. Update config loader and validation
3. Update sample configuration files
4. Document new configuration options

## Common Issues and Solutions

### Development Issues

#### Import Errors
- Ensure Poetry environment is activated
- Check that all dependencies are installed with correct extras

#### Configuration Loading
- Verify YAML structure matches Pydantic models
- Check environment variable naming conventions
- Validate required fields are present

#### API Integration Testing
- Use mock objects for unit tests
- Set up test Microsoft Defender for Office 365 environment for integration tests
- Handle rate limits in test environments

### Production Issues

#### Performance Optimization
- Monitor API response times and adjust retry intervals
- Use batch processing for large expectation sets
- Optimize query time windows based on data volume

#### Error Recovery
- Implement circuit breakers for persistent API failures
- Add health checks for service monitoring
- Use graceful degradation when possible

## Documentation

### Code Documentation
- Write clear docstrings for all public interfaces
- Include type hints and parameter descriptions
- Provide usage examples for complex functions

### Configuration Documentation
- Document all configuration options
- Provide example configurations for different scenarios
- Include troubleshooting guides for common issues

This collector aims to provide a production-ready Microsoft Defender for Office 365 integration for OpenAEV with comprehensive error handling, configurable retry logic, and detailed trace generation.
