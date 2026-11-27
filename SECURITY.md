# Security Policy

## Project context
StreamCrack is intended for WPA2 Wi-Fi password auditing and recovery in authorized environments. Security reports concerning the application, its input handling, and its treatment of sensitive data are in scope.

## In-scope reports
- Parser crashes and memory-safety defects.
- Malformed-input handling and resource exhaustion.
- Unsafe logging or exposure of sensitive data.
- Incorrect result handling or reporting.
- Vulnerable dependencies and CI integrity issues.

## Reporting
Do not publish sensitive details, private captures, credentials, or personal traffic in public issues. Use GitHub private vulnerability reporting if enabled; otherwise contact the maintainers privately through the repository profile.

## Data handling
Treat capture files and all parsed fields as untrusted. Only synthetic or redistributable fixtures may be committed. Protect local input files and generated reports from unintended disclosure.

## Responsible use
Users are responsible for obtaining authorization before assessing networks or data. Security reports should include enough detail to reproduce the issue without disclosing third-party secrets.
