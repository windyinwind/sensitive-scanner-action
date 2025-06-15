# Sensitive Content Scanner GitHub Action

[![GitHub release](https://img.shields.io/github/v/release/windyinwind/sensitive-scanner-action)](https://github.com/windyinwind/sensitive-scanner-action/releases)
[![GitHub marketplace](https://img.shields.io/badge/marketplace-sensitive--content--scanner-blue?logo=github)](https://github.com/marketplace/actions/sensitive-content-scanner)
[![CI](https://github.com/windyinwind/sensitive-scanner-action/actions/workflows/test.yml/badge.svg)](https://github.com/windyinwind/sensitive-scanner-action/actions/workflows/test.yml)
[![CI](https://github.com/windyinwind/sensitive-scanner-action/actions/workflows/release.yml/badge.svg)](https://github.com/windyinwind/sensitive-scanner-action/actions/workflows/release.yml)


A GitHub Action that automatically scans pull requests for sensitive content, including secrets, credentials, and potentially harmful code patterns. It helps prevent accidental exposure of sensitive information in your codebase.

## ✨ Features

- 🔍 **Comprehensive Scanning**: Detects API keys, passwords, tokens, and other secrets
- 🎯 **Smart Pattern Recognition**: Identifies suspicious code patterns and potential security issues
- 📝 **Detailed Reporting**: Posts informative comments on PRs with context and suggestions
- ⚙️ **Highly Configurable**: Customize patterns, severity levels, and exclusions
- 🚀 **Fast & Efficient**: Only scans changed files and lines in PRs
- 📊 **Severity Levels**: Categorizes findings by importance (low, medium, high)

## 🚀 Quick Start

Create a workflow file (e.g., `.github/workflows/sensitive-scan.yml`):

```yaml
name: Sensitive Content Scanner

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: windyinwind/sensitive-scanner-action@v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

## 📋 Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `github-token` | GitHub token for API access | Yes | `${{ github.token }}` |
| `sensitive-words-file` | Path to custom sensitive words file | No | `.github/sensitive-words.txt` |
| `custom-patterns` | Additional regex patterns (JSON array) | No | `[]` |
| `exclude-files` | File patterns to exclude (comma-separated) | No | `*.min.js,*.lock,package-lock.json,yarn.lock,*.map` |
| `severity-level` | Minimum severity to report | No | `medium` |
| `fail-on-detection` | Fail workflow when issues found | No | `true` |
| `comment-mode` | Comment handling mode | No | `create` |

## 📤 Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Number of findings detected |
| `has-high-severity` | Whether high severity issues were found |
| `scan-status` | Overall scan status |

## 🔧 Configuration Examples

### Basic Usage
```yaml
- uses: windyinwind/sensitive-scanner-action@v1
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

### Advanced Configuration
```yaml
- uses: windyinwind/sensitive-scanner-action@v1
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    sensitive-words-file: '.github/custom-words.txt'
    custom-patterns: '["(?i)todo.*hack", "(?i)fixme.*security"]'
    exclude-files: '*.min.js,*.bundle.js,dist/**,build/**'
    severity-level: 'low'
    fail-on-detection: 'false'
```

### Using Outputs
```yaml
- name: Scan for sensitive content
  id: scan
  uses: windyinwind/sensitive-scanner-action@v1
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}

- name: Handle scan results
  if: steps.scan.outputs.has-high-severity == 'true'
  run: |
    echo "High severity issues found!"
    echo "Total findings: ${{ steps.scan.outputs.findings-count }}"
```

## 📝 Custom Sensitive Words File

Create a `.github/sensitive-words.txt` file in your repository:

```
# Sensitive words (one per line)
# Lines starting with # are comments

password
secret
apikey
token
confidential
internal_only

# Add your organization-specific terms
```

## 🎯 What It Detects

### 🚨 High Severity
- API keys and tokens (OpenAI, GitHub, Slack, etc.)
- Database connection strings
- Private keys and certificates
- Hardcoded passwords

### ⚠️ Medium Severity
- Suspicious code patterns (`eval`, `innerHTML`, etc.)
- Template injection patterns
- Custom sensitive words
- Debug statements in production code

### ℹ️ Low Severity
- Development URLs (localhost, .local domains)
- TODO/FIXME comments with security implications
- Hardcoded development credentials

## 🛡️ Security Considerations

- The action only scans **changed lines** in pull requests
- No sensitive data is stored or transmitted outside GitHub
- All processing happens within your GitHub Actions environment
- Comments are posted using the provided GitHub token permissions

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Related Actions

- [GitLeaks Action](https://github.com/marketplace/actions/gitleaks) - Another secret scanning tool
- [TruffleHog](https://github.com/marketplace/actions/trufflehog-oss) - Secrets scanner
- [Semgrep](https://github.com/marketplace/actions/semgrep) - Static analysis tool

## 💬 Support

- 📖 [Documentation](https://github.com/windyinwind/sensitive-scanner-action/wiki)
- 🐛 [Report Issues](https://github.com/windyinwind/sensitive-scanner-action/issues)
- 💬 [Discussions](https://github.com/windyinwind/sensitive-scanner-action/discussions)

---

⭐ If this action helps you, please consider giving it a star!
