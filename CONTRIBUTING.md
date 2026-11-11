# Contributing to CloudCompliance

Thank you for considering contributing to CloudCompliance! ❤️

We welcome contributions of all kinds: bug fixes, new compliance controls, multi-cloud modules, documentation improvements, and feature requests.

---

## Code of Conduct

This project and everyone participating in it is governed by the [CloudCompliance Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to [kadhiravanegk@gmail.com](mailto:kadhiravanegk@gmail.com).

---

## How Can I Contribute?

### Reporting Bugs
- Check the [existing issues](https://github.com/KADHIRAVANEG/terraform-aws-cloudcompliance/issues) to avoid duplicates.
- Open a new issue with a clear title, description, and steps to reproduce.
- Include your operating system, Python version, and Terraform version.
- **For security vulnerabilities**: Please do NOT report security vulnerabilities through public GitHub issues. Follow our [Security Policy](SECURITY.md) and report privately via [GitHub Security Advisories](https://github.com/KADHIRAVANEG/terraform-aws-cloudcompliance/security/advisories) or email [kadhiravanegk@gmail.com](mailto:kadhiravanegk@gmail.com).

### Suggesting Enhancements
- Open a feature request in [GitHub Discussions](https://github.com/KADHIRAVANEG/terraform-aws-cloudcompliance/discussions) or create an issue.
- Clearly describe the feature, the problem it solves, and the intended compliance impact.

### Pull Requests
1. Fork the repository.
2. Create a feature branch (`git checkout -b feat/my-new-feature`).
3. Make your changes adhering to code style and type safety.
4. Add or update unit tests in `tests/`.
5. Ensure all tests pass (`pytest tests/`).
6. Commit with clear, descriptive commit messages (following [Conventional Commits](https://www.conventionalcommits.org/)).
7. Push to your branch and open a Pull Request against `main`.

---

## Development Setup

### 1. Clone the repository
```bash
git clone https://github.com/KADHIRAVANEG/terraform-aws-cloudcompliance.git
cd terraform-aws-cloudcompliance
```

### 2. Set up Python virtual environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
```

### 3. Run the test suite
```bash
pytest tests/ -v
```

### 4. Code quality & linting
```bash
ruff check .
```

---

## Contact & Maintainer

Maintained by **Kadhiravan E.G.**  
- Email: [kadhiravanegk@gmail.com](mailto:kadhiravanegk@gmail.com)  
- GitHub: [@KADHIRAVANEG](https://github.com/KADHIRAVANEG)  
