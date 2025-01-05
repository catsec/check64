# Base64 Script Command Detector

This tool decodes a Base64-encoded string, detects its character encoding, and checks for the presence of potentially malicious or harmful script commands. It supports both normal decoding and XOR-decoded content for enhanced detection.

## Features

- Decodes Base64 strings and checks for encoding.
- Detects script commands for Bash, PowerShell, and Windows command-line environments.
- Supports XOR decoding for additional checks.
- Identifies the encoding type and provides an assurance score.
- Designed for security audits and input validation.

## Usage

### Command-line Usage
```bash
check64.exe <base64_string>
```

### Example
```bash
check64.exe Y2QgLi4=
```

Output:
```plaintext
error: script commands found
Was XORed: false
Detected encoding: UTF-8
Assurance: 98%
Detected script commands: ["cd"]
```

### System Requirements
- Rust (for building from source)
- Pre-built binaries available for Linux (AMD64)

## Installation

### Download Pre-built Binary
Download the latest release binary from the [Releases](https://github.com/yourusername/yourrepository/releases/latest) page.

1. Navigate to the [Latest Release](https://github.com/yourusername/yourrepository/releases/latest).
2. Download the binary for your platform

### Build from Source
1. Clone the repository:
   ```bash
   git clone https://github.com/catsec/check64
   cd check64
   ```
2. Build the binary:
   ```bash
   cargo build --release
   ```
3. The binary will be available in the `target/release` directory.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

