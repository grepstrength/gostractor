# GoStractor

GoStractor is a command-line tool designed to automate the extraction of Indicators of Compromise (IOCs) from potentially malicious files. Built in Go, it provides fast and efficient static analysis capabilities for malware researchers and incident responders.

## Features

- Extracts multiple IOC types from mobile .apk's, DLLs, and Windows executables.
- Records the SHA-256 hash of the analyzed file.
- Identifies network-related indicators of compromise (URLs, IPs, domains).
- Detects strings referencing the modification of the Windows Registry. 
- Outputs results in CSV format for easy analysis.
- Cross-platform compatible (Windows x64-focused).

## Supported IOC Types

- SHA-256 file hashes
- IP addresses (IPv4)
- Domain names with valid TLDs
- URLs (HTTP, HTTPS, FTP, SFTP)
- Windows Registry keys

## Supported File Types

- Windows Executables (.exe)
- Dynamic Link Libraries (.dll)
- Android Package Files (.apk)
- Windows Installer Packages (.msi)

## Installation

```bash
go install github.com/yourusername/gostractor@latest
```

## Usage
```cmd
.\gostractor.exe <input_file> [output_file]
```

If no output file is specified, results will be saved as <input_file>_IOCs.csv

Output Format
The CSV output contains three columns:

- IOC: The extracted indicator
- Type: The type of indicator (SHA-256, IP, Domain, URL, Registry)
- Offset: The location in the file where the IOC was found

## Example
```cmd
.\gostractor.exe malware.exe results.csv
```