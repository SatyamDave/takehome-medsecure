# SecureLoop Demo Script

**Duration**: 7-8 minutes  
**Purpose**: Technical sales demo for VP of Engineering / Security stakeholders

---

## [0:00 - 0:30] PROBLEM FRAMING

*Slide: "The Security Backlog Crisis"*

"Every company has a security backlog. MedSecure is no exception."

"The problem: They ran CodeQL扫描 and found 10 critical vulnerabilities in their patient data platform. SQL injection. Hardcoded secrets. Path traversal. XXE. The works."

"But here's the thing: these issues have been sitting there for 6+ months. Why? Because their engineering team is overwhelmed with feature work. Security keeps getting deprioritized."

"Today I'm going to show you how SecureLoop uses Devin to automate the remediation of these issues - no engineering time required, root-cause fixes, not suppressions."

---

## [0:30 - 1:30] LIVE DEMO - THE VULNERABLE REPO

*Action: Show medsecure-platform repository*

"Let me show you what we're working with. This is MedSecure's patient data platform - Python Flask API with PostgreSQL and MongoDB."

*Navigate to SECURITY_ISSUES.json*

"Here's our security backlog. 10 issues. 6 critical. 4 high. Each one documented with the CWE, file location, and severity."

*Click on first issue (SQL Injection)*

"Here's a real SQL injection vulnerability in the authentication service. Look at this code - user input directly concatenated into the query. This was flagged by CodeQL."

*Show the other critical issues quickly*

"Hardcoded JWT secrets. Path traversal in document download. NoSQL injection in patient search. SSRF in export. Missing webhook verification. XXE in XML parsing. Weak password hashing."

"These aren't theoretical. This is production code that MedSecure has been running for 18 months."

---

## [1:30 - 3:00] THE ORCHESTRATOR

*Action: Open orchestrator.py*

"This is the SecureLoop orchestrator. It's the brain of the operation."

*Walk through the flow*

"1. It loads the security issues from JSON  
2. It classifies each one by complexity - trivial, medium, or needs-human  
3. For each issue, it generates a detailed prompt for Devin"

*Show devin_prompt.py*

"This is the prompt engineering. This is where the magic happens."

*Explain the prompt*

"Notice what we're asking for:
- Root cause fixes, NOT suppressions
- Follow existing code patterns
- Add proper validation
- Add tests
- PR with CWE tags

We're not just saying 'fix this'. We're giving Devin everything it needs to do the job right."

---

## [3:00 - 4:30] RUNNING THE PIPELINE

*Action: Run the pipeline in dry-run mode*

"Let me show you the pipeline in action. I'm running in dry-run mode so we don't actually hit the Devin API, but the flow is identical."

*Run: `python run_full_pipeline.py --dry-run`*

"Watch what happens:
- Issue MS-SEC-2025-001: SQL injection - classified as MEDIUM, sent to Devin
- Issue MS-SEC-2025-002: Hardcoded JWT - classified as TRIVIAL, fixed with config change
- Issue MS-SEC-2025-003: Path traversal - classified as MEDIUM, needs validation logic

The orchestrator is making intelligent decisions about what can be automated vs. what needs human review."

*Show state.json*

"All of this is tracked in state.json. Every session. Every PR. Every status change."

---

## [4:30 - 5:30] THE DASHBOARD

*Action: Open the React dashboard*

"And this is what your security team sees. The SecureLoop dashboard."

*Walk through the UI*

"Pipeline view at the top:
- New issues coming in
- In Progress - Devin is working on them
- PR Open - fixes ready for review
- Merged - deployed to production

Metrics below:
- Total issues / Fixed / Pending
- Mean time to remediation: 4.2 hours (we track this)
- Severity breakdown - visual bar chart

The dashboard auto-refreshes every 10 seconds from state.json. It's always current."

---

## [5:30 - 6:30] WHY DEVIN

*Transition to "Why Devin" slide*

"Why Devin? Let me tell you what I've learned running this demo."

"Traditional automated remediation tools? They suppress warnings. They add comments to disable scanning. They don't actually fix the root cause."

"Devin is different. Devin:
- Understands code context
- Follows existing patterns
- Adds proper tests
- Creates real PRs with proper descriptions

The fixes are production-ready. They're the same quality as what your engineers would write."

"And the business impact: We're seeing 90%+ of security issues get fully remediated through automation. The security team only reviews the complex ones. That's a massive reduction in toil."

---

## [6:30 - 7:30] NEXT STEPS

*Wrap up*

"Here's how this works in practice:

1. You integrate SecureLoop with your security scanning (CodeQL, Snyk, whatever)
2. New issues automatically get queued for remediation
3. Devin picks them up, fixes them, opens PRs
4. Your team reviews and merges - but only the complex ones need real attention

We're running a pilot with MedSecure starting next month. I'd love to show you what that looks like."

*Call to action*

"Can I schedule a follow-up to walk through the integration options for your environment?"

---

## DEMO NOTES

- Keep energy high and confident
- Don't rush - let the code speak for itself
- If asked about specific vulnerabilities, dive into the detail
- If asked about CI/CD integration, pivot to the architecture diagram
- Always bring it back to business value: less toil, faster remediation, compliance confidence
