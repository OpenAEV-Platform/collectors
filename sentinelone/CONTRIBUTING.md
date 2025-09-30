# Contributing to SentinelOne Collector

This document provides guidance for contributing to the SentinelOne collector for OpenBAS. This collector is now feature-complete with SentinelOne-specific implementation.

## Current Implementation Status

**COMPLETED**: The SentinelOne collector is fully implemented with the following components:

### Core Components
-  **Collector Core** ([`src/collector/collector.py`](src/collector/collector.py)) - Main daemon with SentinelOne service integration
-  **Expectation Handler** ([`src/collector/expectation_handler.py`](src/collector/expectation_handler.py)) - Generic handler using service provider pattern
-  **Expectation Manager** ([`src/collector/expectation_manager.py`](src/collector/expectation_manager.py)) - Batch processing and API interactions
-  **Configuration System** ([`src/models/configs/`](src/models/configs/)) - Hierarchical configuration with SentinelOne settings
-  **Service Providers** - Complete SentinelOne-specific implementation

### SentinelOne Implementation
-  **SentinelOne API Client** ([`src/services/client_api.py`](src/services/client_api.py)) - Full API integration
-  **Deep Visibility Fetcher** ([`src/services/fetcher_deep_visibility.py`](src/services/fetcher_deep_visibility.py)) - Process event queries
-  **Threat Fetcher** ([`src/services/fetcher_threat.py`](src/services/fetcher_threat.py)) - Prevention data correlation
-  **Expectation Service** ([`src/services/expectation_service.py`](src/services/expectation_service.py)) - Business logic implementation
-  **Trace Service** ([`src/services/trace_service.py`](src/services/trace_service.py)) - Trace creation with SentinelOne links
-  **Data Converter** ([`src/services/converter.py`](src/services/converter.py)) - SentinelOne to OAEV format conversion

### Supported Features
-  **Signature Support**: `parent_process_name`, `start_date`, `end_date`
-  **Detection Expectations**: Deep Visibility event validation
-  **Prevention Expectations**: Combined event + threat validation
-  **Retry Mechanism**: Configurable retries with ingestion delay handling
-  **Trace Generation**: Links back to SentinelOne console
-  **Error Handling**: Comprehensive exception handling and logging
-  **Configuration Management**: YAML, environment variables, defaults

## Installation and Setup

### Poetry Dependency Groups

- `--with dev`: Development tools (ruff, mypy, black, etc.)
- `--with test`: Testing tools (pytest, coverage, etc.)

### Poetry Extras

- `--extra prod`: Get pyobas from PyPI (production releases)
- `--extra current`: Get pyobas from Git release/current branch
- `--extra local`: Get pyobas locally from `../../client-python`

### Development Installation

```bash
# Development setup with current pyobas version
poetry install -E current --with dev,test

# Production setup
poetry install -E prod

# Local development with local pyobas
poetry install -E local --with dev,test
```

### Running the Collector

```bash
# Direct execution
SentinelOneCollector

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
   cd sentinelone
   poetry install -E current --with dev,test
   ```

2. **Configure for Development**:
   ```bash
   # Copy sample config
   cp src/config.yml.sample src/config.yml

   # Edit with your SentinelOne details
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
├── services/           # SentinelOne-specific implementation
│   ├── client_api.py   # API client
│   ├── expectation_service.py  # Business logic
│   ├── trace_service.py        # Trace creation
│   ├── converter.py    # Data conversion
│   ├── fetcher_*.py    # API-specific fetchers
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
- **Integration Tests**: Test SentinelOne API interactions
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
except SentinelOneServiceError as e:
    logger.error(f"SentinelOne API error: {e}")
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

1. Update `SUPPORTED_SIGNATURES` in [`src/services/expectation_service.py`](src/services/expectation_service.py)
2. Modify query building in [`src/services/client_api.py`](src/services/client_api.py)
3. Update data conversion logic in [`src/services/converter.py`](src/services/converter.py)
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

## Template Adaptation

This collector is built on a reusable foundation that can be adapted for other security platforms. If you want to create a similar collector for another platform (e.g., CrowdStrike, Microsoft Defender):

### SentinelOne-Specific References to Change

#### Configuration Files
- [ ] `pyproject.toml` - Update project name and script names
- [ ] [`src/config.yml`](src/config.yml) - Update collector ID
- [ ] [`src/config.yml.sample`](src/config.yml.sample) - Update sample configuration

#### Code References
- [ ] [`src/services/utils/config_loader.py`](src/services/utils/config_loader.py) - Rename config classes
- [ ] [`src/collector/collector.py`](src/collector/collector.py) - Update service imports
- [ ] [`src/models/configs/collector_configs.py`](src/models/configs/collector_configs.py) - Update defaults
- [ ] Platform-specific service implementations in `src/services/`

### Reusable Components

The following components are platform-agnostic and can be reused:
- Generic collector daemon
- Service provider protocols
- Configuration management system
- Expectation processing pipeline
- Signature registry system
- Trace management system

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
- Set up test SentinelOne environment for integration tests
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

This collector provides a production-ready SentinelOne integration for OpenBAS with comprehensive error handling, configurable retry logic, and detailed trace generation.
