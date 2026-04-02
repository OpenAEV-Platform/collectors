# Contributing to HTTP-logwatcher

## Development and testing setup

Note: for development purposes, it is highly recommended to use an enclosed environment such as `venv` ([Python documentation for venv](https://docs.python.org/3/library/venv.html)) or such as a container. This will help you ensuring you are using the right Python version and dependencies' versions in an environment free of outside interference.

```bash
# Install
poetry install --extra local --with dev,test
```

The `--extra` flag can be changed from `local` to `prod` (to get pyoaev from PyPI) or to `current` (to get pyoaev from Git release/current branch). For more details about the dev and test dependencies, do not hesitate to check the content of the `pyproject.toml` file.

## Testing

### Unit testing

```bash
# Run all the tests with verbose output and coverage assessment
poetry run pytest --cov=src -v
```

### Integration testing

1. Deploy locally an instance of OpenAEV using the docker stack ([OpenAEV Docker Deployment](https://github.com/OpenAEV-Platform/docker))
    ```bash
    podman compose -f docker-compose.yml -d
    ```
2. Install locally the OpenAEV agent using OpenAEV webUI
3. Launch a nginx server locally on the same network as the docker stack with an exposed :80 port and a binding for the logfiles
    ```bash
    podman run -it --network xtm_default -p 80:80 -v $PWD/:/var/log/nginx/ nginx
    ```
4. In OpenAEV, create atomic tests with a curl-like payload, one for the detection testing (request to `http://localhost/`) and one for the prevention testing (request to `http://localhost/this-page-does-not-exist`).
    ```powershell
    # detection payload for a Windows agent
    curl -UseBasicParsing http://localhost
    ```
5. Update the collector settings (e.g. `src/config.yml`) to match your local OpenAEV instance and run the collector using poetry
    ```bash
    poetry run python -m src
    ```
6. Run the atomic tests and check for the proper expectations in OpenAEV webUI

## Code Quality Standards

### Formatting and Linting

- **Black**: Code formatting (line length: 88)
    ```bash
    poetry run black src/
    ```
- **Ruff**: Fast Python linter
    ```bash
    poetry run ruff check src/
    ```
- **MyPy**: Static type checking
    ```bash
    poetry run mypy src/
    ```
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
from src.collector.exception import HTTPLogwatcherValidationError

if config is None:
    raise HTTPLogwatcherValidationError("config cannot be None")
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

### Beyond

Please for more details and information report to more overall contributing guidelines provided by Filigran at project-level or in the online documentation.
