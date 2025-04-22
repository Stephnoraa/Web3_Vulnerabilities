# Lab 2: SSRF Vulnerability in NFT Metadata Fetcher (Rust)

This lab demonstrates how Server-Side Request Forgery (SSRF) vulnerabilities can impact Web3 applications, particularly in services that fetch metadata for NFTs from user-supplied sources. The lab is implemented in Rust using the Actix Web framework to showcase both vulnerable and secure implementations.

## Overview

Server-Side Request Forgery (SSRF) is a web security vulnerability that allows an attacker to induce the server-side application to make requests to an unintended location. In the context of Web3 applications, this can be particularly dangerous as it may allow attackers to:

- Access internal blockchain nodes
- Retrieve private keys or sensitive configuration
- Interact with internal services that should not be publicly accessible
- Bypass network security controls

## Vulnerable Implementation

The vulnerable implementation in `lab2/vulnerable/src/main.rs` demonstrates a common mistake in Web3 applications: accepting user-provided URLs without proper validation. This allows attackers to:

1. Access internal services (e.g., `http://localhost:8080/internal/api`)
2. Read local files (e.g., `file:///etc/passwd`)
3. Scan internal networks (e.g., `http://192.168.1.1`)
4. Exploit other services that trust the server's IP

## Secure Implementation

The secure implementation in `lab2/fixed/src/main.rs` demonstrates proper URL validation techniques:

1. Parsing and validating URLs using Rust's `url` crate
2. Enforcing HTTPS-only connections
3. Implementing a domain allowlist
4. Proper error handling without exposing sensitive information

## Running the Lab

### Prerequisites

- Rust and Cargo installed
- Basic knowledge of Web3 concepts and HTTP

### Setup

1. Clone the repository
2. Navigate to the lab2 directory
3. Run the vulnerable or fixed implementation:

\`\`\`bash
# Run the vulnerable implementation
cd vulnerable
cargo run

# Run the fixed implementation
cd fixed
cargo run
\`\`\`

## Security Recommendations for Web3 Developers

When implementing services that fetch data from user-provided URLs:

1. Always validate and sanitize user input
2. Implement a strict allowlist of domains
3. Enforce HTTPS-only connections
4. Consider using a proxy service for external requests
5. Implement proper network segmentation to protect sensitive internal services
6. Apply the principle of least privilege to service accounts

## Real-World Impact

SSRF vulnerabilities have been discovered in several Web3 platforms, including:

- NFT marketplaces that fetch metadata from user-provided URLs
- Blockchain explorers that render external content
- DeFi platforms that integrate with external price oracles

These vulnerabilities can lead to unauthorized access to internal systems, data breaches, and in some cases, theft of cryptocurrency assets.

## References

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger Web Security Academy: SSRF](https://portswigger.net/web-security/ssrf)
- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
\`\`\`

```dockerfile file="lab2/Dockerfile"
# Use the official Rust image as the base image
FROM rust:1.70 as builder

# Create a new empty shell project
WORKDIR /usr/src/web3-security-lab2
COPY . .

# Build the application
RUN cargo build --release

# Use a smaller image for the runtime
FROM debian:bullseye-slim

# Install necessary dependencies
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the binary from the builder stage
COPY --from=builder /usr/src/web3-security-lab2/target/release/web3-security-lab2-vulnerable /usr/local/bin/vulnerable
COPY --from=builder /usr/src/web3-security-lab2/target/release/web3-security-lab2-fixed /usr/local/bin/fixed

# Set the working directory
WORKDIR /usr/local/bin

# Expose the ports
EXPOSE 8080 8081

# Create a non-root user to run the application
RUN useradd -m appuser
USER appuser

# Command to run the application
CMD ["bash", "-c", "vulnerable & fixed"]
