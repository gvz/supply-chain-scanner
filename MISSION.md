# Issue this Project Solves

In modern software development vast amount of third party code is used.
This opens to developers and the projects to supply chain attacks.

# Goal

This project serves as a proxy for package and dependency management tools that scans the packages the developers wants to install and denys the download if the package is known to be malicious.
The proxy hold a database that stores the result of it scan for the version of the package, so later request can be answered faster and each package version is only scanned once.

## Flow

1. developer requstes package to install via standart tool like pip, npm, cargo
2. tool requests package at proxy
3. proxy checks if package in the requested version was scanned before
  1. previous scan found malicious code
    1. proxy returns that package is not available due to security issue
  2. previous scan was clean
    1. proxy checks open CVE databases
    2. if no cve found, proxy retruns the package to install
    3. if cve found, proxy returns that package is not available due to security issue
  3. package version was never scanned, stop an retrun secutity issues  if any of the following returns with security concerns
    1. check CVE databases
    2. download package
    3. check if specified hash fits downloaded hash
    4. run user specified checks
    5. if all check are green, return package to install

## Supported Languages

Longterm multiple languages will be supported

Currently supported:

- Python

# Implementation

## Language 
Rust