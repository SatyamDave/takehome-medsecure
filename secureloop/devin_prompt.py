"""
Devin Prompt Engineering Module

This module generates highly effective prompts for Devin AI to fix security vulnerabilities.
The prompts are designed to ensure:
1. Root cause fixes (NOT suppression)
2. Following existing code patterns
3. Proper validation and sanitization
4. Test additions/updates
5. Clear PR descriptions with CWE tags

Author: SecureLoop Team
Version: 1.0.0
"""

import os
from typing import Dict, Any, Optional


class DevinPromptGenerator:
    """
    Generates strong prompts for Devin AI to fix security vulnerabilities.

    Key design principles:
    - Explain vulnerability clearly with CWE reference
    - Provide file path and relevant code snippets
    - Instruct to fix ROOT CAUSE, not suppress warnings
    - Require following existing code patterns
    - Mandate test additions
    - Request detailed PR explanation with severity + CWE tags
    """

    def __init__(self, repo_root: Optional[str] = None):
        """
        Initialize the prompt generator.

        Args:
            repo_root: Path to repository root (auto-detected if not provided)
        """
        self.repo_root = repo_root or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "medsecure-platform"
        )

    def generate_fix_prompt(self, issue: Dict[str, Any]) -> str:
        """
        Generate a comprehensive prompt for fixing a security issue.

        Args:
            issue: Security issue dictionary from SECURITY_ISSUES.json

        Returns:
            Formatted prompt string for Devin
        """
        issue_id = issue["id"]
        title = issue["title"]
        description = issue["description"]
        severity = issue["severity"]
        cwe = issue["cwe"]
        file_path = issue["file_path"]
        line_range = issue["line_range"]

        # Read the vulnerable code
        vulnerable_code = self._read_vulnerable_code(file_path, line_range)

        prompt = f"""# Security Vulnerability Fix Task

## Issue Information
- **Issue ID**: {issue_id}
- **Severity**: {severity.upper()}
- **CWE**: {cwe}
- **File**: {file_path}
- **Lines**: {line_range}

## Vulnerability Description
{title}

{description}

## CRITICAL: Repository Access
The code is provided BELOW in the "Vulnerable Code" section. 
- The entire vulnerable file content is provided inline below
- Use ONLY the code provided below to understand and fix the issue

## GitHub Access for PR Creation
You have been provided with a GitHub token via the GITHUB_TOKEN secret.
- Use this token to clone, push, and create PRs on: https://github.com/SatyamDave/takehome-medsecure
- The token has full write access to this repository
- When creating branches/PRs, authenticate using: git push with the token

## Vulnerable Code
The following code in `{file_path}` contains the security vulnerability (full file content):

```{self._get_language_for_file(file_path)}
{self._get_file_path_relative(file_path)}
---
{vulnerable_code}
```

## Required Fix

### CRITICAL REQUIREMENTS

1. **FIX THE ROOT CAUSE** - Do NOT suppress warnings or add ignore comments. You must fix the actual vulnerability in the code logic.

2. **Follow Existing Patterns** - Study the surrounding code and existing patterns in the codebase. Maintain consistency with:
   - Code style and formatting
   - Error handling approaches
   - Logging conventions
   - Import structure

3. **Add Proper Validation** - Where applicable, add input validation, sanitization, or proper encoding:
   - SQL queries: Use parameterized queries
   - User input: Validate and sanitize all inputs
   - URLs: Validate against allowlists
   - XML: Disable external entity resolution
   - Auth: Use proper secrets management

4. **Add Tests** - Create or update tests to verify the fix:
   - Unit tests for the fixed functionality
   - Test that the vulnerability is no longer present
   - Follow existing test patterns in the codebase

5. **Security Best Practices** - Apply industry-standard security practices:
   - Use bcrypt/Argon2 for password hashing (NOT MD5/SHA1)
   - Use parameterized queries for all database operations
   - Use environment variables or secrets managers for sensitive config
   - Validate all user inputs
   - Use constant-time comparisons for secrets

## Repository Context
- **Repository**: medsecure-platform
- **Language**: Python (Flask)
- **Framework**: Flask with PostgreSQL, MongoDB
- **Key Files**: 
  - `src/auth/` - Authentication modules
  - `src/patients/` - Patient record services
  - `src/api/` - API endpoints and integrations
  - `src/config.py` - Configuration
  - `tests/` - Test files

## Output Requirements

### Code Changes
- Make minimal, targeted changes to fix the vulnerability
- Do NOT make unrelated changes
- Ensure code compiles and runs correctly

### Commit/PR Requirements
When creating the pull request:
1. Use the following format for PR title: <severity> <cwe>: <short description>
   Example: [Critical] CWE-89: Fix SQL injection in authentication
2. Add severity label to the PR
3. Add CWE tag to the PR
4. In the PR description:
   - Explain the vulnerability
   - Show the fix (before/after)
   - List test additions
   - Reference the issue ID

### For Configuration Issues (debug mode, hardcoded secrets)
- Change configuration to use environment variables
- Add validation that fails if secrets are not properly configured
- Do NOT commit actual secret values

## Example Fix Patterns

### SQL Injection Fix
```python
# BEFORE (vulnerable)
query = "SELECT * FROM users WHERE username = '" + username + "'"

# AFTER (safe)
query = "SELECT * FROM users WHERE username = %s"
cursor.execute(query, (username,))
```

### Path Traversal Fix
```python
# BEFORE (vulnerable)
full_path = os.path.join(base_path, patient_id, document_path)

# AFTER (safe)
# Normalize and validate path
requested_path = os.path.normpath(os.path.join(patient_id, document_path))
if requested_path.startswith('..'):
    raise ValueError("Invalid path")
full_path = os.path.join(base_path, requested_path)
```

### Hardcoded Secret Fix
```python
# BEFORE (vulnerable)
SECRET_KEY = "hardcoded-secret"

# AFTER (safe)
import os
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable must be set")
```

---

Now please fix this vulnerability. Create a branch, make the fix, add tests, and create a pull request with proper descriptions and tags."""

        return prompt

    def _read_vulnerable_code(self, file_path: str, line_range: str) -> str:
        """
        Read the vulnerable code section from the file.

        Args:
            file_path: Path to the file
            line_range: String like "56-65" representing line numbers

        Returns:
            Code snippet as string
        """
        full_path = os.path.join(self.repo_root, file_path)

        if not os.path.exists(full_path):
            return f"File not found: {file_path}"

        try:
            with open(full_path, "r") as f:
                lines = f.readlines()

            # Parse line range
            if "-" in line_range:
                start, end = map(int, line_range.split("-"))
            else:
                start = int(line_range)
                end = start

            # Adjust to 0-indexed
            start = max(0, start - 1)
            end = min(len(lines), end)

            return "".join(lines[start:end])

        except Exception as e:
            return f"Error reading file: {e}"

    def _get_file_path_relative(self, file_path: str) -> str:
        """Get relative path for display."""
        return file_path

    def _get_language_for_file(self, file_path: str) -> str:
        """Get language identifier for syntax highlighting."""
        ext = os.path.splitext(file_path)[1]
        language_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".java": "java",
            ".go": "go",
            ".rb": "ruby",
            ".sh": "bash",
            ".yml": "yaml",
            ".yaml": "yaml",
            ".json": "json",
            ".xml": "xml",
        }
        return language_map.get(ext, "text")

    def generate_trivial_fix_prompt(self, issue: Dict[str, Any]) -> str:
        """
        Generate a simpler prompt for trivial fixes (config changes, etc).

        Args:
            issue: Security issue dictionary

        Returns:
            Formatted prompt for trivial fix
        """
        return f"""# Quick Security Fix - {issue["id"]}

## Issue
- **Severity**: {issue["severity"].upper()}
- **CWE**: {issue["cwe"]}
- **File**: {issue["file_path"]}
- **Lines**: {issue["line_range"]}

## Problem
{issue["title"]}

{issue["description"]}

## Required Action
This is a configuration or simple change. The code context is provided below.

1. Make the necessary fix in `{issue["file_path"]}`
2. Ensure the fix follows security best practices
3. Create a branch and PR with title: `[{issue["severity"].upper()}] {issue["cwe"]}: {issue["title"]}`
4. Add appropriate labels to the PR

**IMPORTANT**: Do NOT try to clone or access any external repository. The fix should be based on the code provided in this prompt.
"""

    def generate_human_review_prompt(self, issue: Dict[str, Any]) -> str:
        """
        Generate a prompt for issues that need human review.

        Args:
            issue: Security issue dictionary

        Returns:
            Formatted prompt for human review
        """
        return f"""# Security Issue Requires Human Review - {issue["id"]}

## Issue Information
- **Issue ID**: {issue["id"]}
- **Severity**: {issue["severity"].upper()}
- **CWE**: {issue["cwe"]}
- **File**: {issue["file_path"]}

## Problem
{issue["title"]}

{issue["description"]}

## Assessment Required
This issue requires human assessment because:
- It may involve complex architectural changes
- It may have breaking change implications
- It may need design decision input

## Action Required
Please review this issue and determine:
1. The recommended fix approach
2. Any potential breaking changes
3. Required testing approach
4. Priority for scheduling the fix

Create a detailed analysis comment on the issue with your findings.
"""


def generate_test_prompt(file_path: str, vulnerability_type: str) -> str:
    """
    Generate a prompt for creating security tests.

    Args:
        file_path: Path to the file to test
        vulnerability_type: Type of vulnerability (SQL injection, XSS, etc.)

    Returns:
        Test generation prompt
    """
    return f"""# Security Test Generation Task

## Context
Create security-focused tests for `{file_path}` to detect {vulnerability_type}.

## Requirements
1. Write tests that would FAIL on vulnerable code
2. Write tests that would PASS on fixed code
3. Follow existing test patterns in the codebase
4. Test edge cases and boundary conditions

## Test File Location
Place tests in the `tests/` directory, following existing conventions.

## Output
Provide complete, runnable test code that can be added to the test suite.
"""
