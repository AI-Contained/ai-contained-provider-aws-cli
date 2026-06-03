# ai-contained-provider-aws-cli

AWS CLI provider for [AI-Contained](https://github.com/AI-Contained).

## Installation

### Local Development

```bash
uv sync --extra dev
```

### Production

```bash
uv pip install "ai-contained-provider-aws-cli @ git+https://github.com/AI-Contained/ai-contained-provider-aws-cli.git@main"
```

## Running Tests

```bash
uv run --extra dev pytest -v
```
