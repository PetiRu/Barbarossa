# Contributing to BARBAROSSA

Thank you for your interest in contributing! This document provides guidelines for contributing.

## Code of Conduct

Please read and abide by our [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Ways to Contribute

1. **Report Bugs** - Open an issue with reproduction steps
2. **Suggest Features** - Describe the feature and its value
3. **Write Documentation** - Improve guides and comments
4. **Submit Code** - Bug fixes and new features via PR
5. **Add Tests** - Improve test coverage

## Development Setup

```bash
# Clone the repo
git clone https://github.com/PetiRu/Barbarossa.git
cd Barbarossa

# Create virtual environment
python3.12 -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
ruff check .
mypy barbarossa

# Format code
ruff format .
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes with tests
4. Run tests and linting locally
5. Commit with clear messages
6. Push to your fork
7. Open a pull request with description

### Before Submitting

- [ ] Tests pass: `pytest`
- [ ] Code formatted: `ruff format .`
- [ ] Linting passes: `ruff check .`
- [ ] Type checking passes: `mypy barbarossa`
- [ ] Documentation updated if needed
- [ ] Commit messages are clear

## Adding Rules

### Adding a Static Inspection Rule

1. Add detection function to appropriate module in `barbarossa/inspect/`
2. Return `Finding` objects
3. Add tests in `tests/`
4. Document in `docs/static-inspection.md`

Example:

```python
def detect_my_issue(file_path: str, content: str) -> Generator[Finding, None, None]:
    """Detect my security issue."""
    if "bad_pattern" in content:
        yield Finding(
            id="MY_RULE_ID",
            title="Title",
            category=Category.INJECTION,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            description="Description",
            evidence="bad_pattern",
            file_path=file_path,
            line_number=1,
            recommendation="Fix it by...",
            references=["https://..."],
        )
```

### Adding an HTTP Probe

1. Add probe function to `barbarossa/probe/runner.py`
2. Yield `Finding` objects
3. Add tests
4. Update documentation

## Code Style

- Follow PEP 8
- Use type hints throughout
- Maximum line length: 100 characters
- Use `ruff` for formatting
- Use `mypy` for type checking

## Documentation

- Keep README.md up to date
- Add docstrings to all functions
- Comment complex logic
- Update docs/ for new features

## Reporting Issues

When reporting bugs, include:

- BARBAROSSA version
- Python version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Error messages and tracebacks

## Questions?

- Check existing issues and discussions
- Open a discussion if you have questions
- Read the documentation thoroughly

Thank you for contributing!
