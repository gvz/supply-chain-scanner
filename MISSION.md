# Issue this Project Solves

In modern software development a vast amount of third party code is used.
This opens developers and their projects to supply chain attacks.

# Goal

This project serves as a proxy for package and dependency management tools. It
scans the packages a developer wants to install and denies the download if the
package fails a check. Nothing is installed on the developer's machine: only the
registry URL changes, so the tool believes it is talking to the public registry.

The proxy holds a database that stores the result of its scan for each version
of a package, so later requests are answered faster and each package version is
only scanned once. A verdict is tied to the policy that produced it, so
tightening the policy re-scans rather than trusting an older answer.

It also records every fetch: which client asked for which package version, and
which versions were withheld from them and why. That is what makes the question
"a CVE was just disclosed, which of our machines pulled this version?"
answerable after the fact.

## Flow

1. developer requests a package to install via a standard tool like pip, npm or
   cargo
2. tool requests the package at the proxy
3. proxy checks whether that exact version was scanned before, under the policy
   currently in force
   1. previous scan found a problem
      1. proxy answers that the package is not available, with a reason and a
         link explaining it
   2. previous scan was clean
      1. proxy returns the package to install
   3. the version was never scanned under this policy, so it is scanned now and
      the package is only returned if every check passes:
      1. release age, if the org requires a minimum
      2. open CVE databases
      3. download the package
      4. check that the registry-declared hash matches the downloaded bytes
      5. run the checks the org specified
      6. AI review of the package's own source, if configured

Every check is fail-closed: a check that cannot run makes the package
unverifiable, and unverifiable is never a reason to serve it. The one deliberate
exception is data a registry simply does not publish — a PyPI index predating
PEP 700 reports no upload time at all — which is a gap in the protocol rather
than a check that failed, and is documented where it applies.

Where the refusal lands differs by ecosystem, because the tools differ. On PyPI
the download itself is refused. On cargo and npm the index response *is* the
gate: a version that failed is simply absent from it, so the tool never asks for
it and resolves to something that passed. Both shapes are refusals; only one of
them is visible to the developer as an error.

## Supported Languages

Longterm multiple languages will be supported.

Currently supported:

- Python (PyPI)
- Rust (crates.io)
- JavaScript and TypeScript (npm)

One process serves exactly one ecosystem. An organization running all three runs
three deployments, each with its own configuration and its own database.

# Implementation

## Language

Rust
