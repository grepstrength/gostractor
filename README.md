# goStractor

goStractor is a command-line tool, written in Go, designed to automate the extraction of (mainly) network indicators of compromise (IOCs) from potentially malicious files. 

***Note: It's recommended to run this is an isolated sandbox VM to prevent accidential infection of your host machine. This sandbox VM shoud have no network route to your LAN or the internet.***

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

***Recommended***

Download the latest release from [Releases](https://github.com/grepstrength/gostractor/releases)

***For Go developers only:***
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

## Limitations
This is not perfect and not all strings found will be legitimate URLs. This tool is meant only to help speeed up the static analysis process of malware analysis. 

Additionally, not all URLs will necessarily be malicious. Further analysis will be required upon finding valid URLs within this tool's output.

## Future Plans
There are several planned improvements:
- GUI
- Greater input file support (ELF, JS, VBA, etc.)
- Greater output file support (JSON, TXT, etc.)
- Improvements to detection logic