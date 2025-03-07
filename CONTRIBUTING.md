# Contributing to Verizon AI Burp Extensions

Thank you for your interest in contributing to the Verizon AI Burp Extensions! This document provides guidelines for contributing and reporting issues to help maintain a collaborative and productive environment.

All contributors are expected to follow our [Code of Conduct](CODE_OF_CONDUCT.md) in all interactions related to this project, including issues, pull requests, and any real-time communications.

## Table of Contents

- [Getting Started](#getting-started)
- [Reporting Issues](#reporting-issues)
- [Pull Request Process](#pull-request-process)
- [Development Workflow](#development-workflow)
- [Security Vulnerabilities](#security-vulnerabilities)
- [Other Ways to Contribute](#other-ways-to-contribute)
- [Communication](#communication)

## Getting Started

1. **Fork the Repository**
   - Click the "Fork" button in the top-right corner of the repository page.

2. **Clone Your Fork**
   ```bash
   git clone https://github.com/YOUR-USERNAME/verizon_burp_extensions_ai.git
   cd verizon_burp_extensions_ai
   ```

3. **Set Up Upstream Remote**
   ```bash
   git remote add upstream https://github.com/verizon/verizon_burp_extensions_ai.git
   ```

4. **Keep Your Fork Updated**
   ```bash
   git fetch upstream
   git checkout main
   git merge upstream/main
   git push origin main
   ```

## Reporting Issues

Before creating a new issue:

1. **Search Existing Issues**: Check the [issue tracker](https://github.com/verizon/verizon_burp_extensions_ai/issues) to ensure the issue hasn't been reported or fixed.

2. **Create a New Issue With**:
   - A clear, descriptive title
   - Detailed description of the problem
   - Steps to reproduce the issue
   - Expected behavior vs. actual behavior
   - Environment information (OS, software versions, etc.)
   - Screenshots or error logs if applicable

3. **Response Timeline**: 
   - We aim to review issues within 10 days
   - Issues with no activity for 60 days may be closed

## Pull Request Process

### Preparing Your Contribution

1. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Your Changes**
   - Follow the project's coding standards
   - Include tests for new features or bug fixes
   - Update documentation as needed

3. **Check for Sensitive Information**
   ```bash
   trufflehog filesystem --exclude-paths=.trufflehogignore
   ```

4. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "Descriptive message about your changes"
   ```

5. **Push to Your Fork**
   ```bash
   git push origin feature/your-feature-name
   ```

### Submitting a Pull Request

1. **Open a Pull Request** from your feature branch to the main repository's `main` branch.

2. **Complete the PR Template** with:
   - Description of changes
   - Issue number(s) addressed
   - Any breaking changes
   - Testing performed

3. **Review Process**:
   - Maintainers will review PRs within 10 days
   - Address any requested changes
   - PRs with no activity for 60 days may be closed

4. **Merge Requirements**:
   - All tests must pass
   - Required reviews must be approved
   - No conflicts with the base branch

## Development Workflow

1. **Code Standards**
   - Follow the established code style of the project
   - Use meaningful variable and function names
   - Comment complex code sections

2. **Testing**
   - Write tests for all new features and bug fixes
   - Ensure all tests pass locally before submitting

3. **Documentation**
   - Update README.md if adding new features
   - Include inline code comments
   - Update any affected documentation

## Security Vulnerabilities

If you discover a security vulnerability:

1. **DO NOT** report it through GitHub Issues
2. Follow the security procedures in [SECURITY.md](SECURITY.md)

## Other Ways to Contribute

We welcome these valuable contributions:

1. **Triage Issues**:
   - Help categorize and clarify existing issues
   - Verify if issues are reproducible
   - Suggest solutions or workarounds

2. **Improve Documentation**:
   - Fix typos or clarify existing documentation
   - Add examples or tutorials
   - Translate documentation

3. **Quality Assurance**:
   - Test existing features for bugs
   - Review and test open pull requests
   - Add missing test cases


---

Thank you for contributing to the Verizon AI Burp Extensions! Your efforts help make this project better for everyone.

:heart:
