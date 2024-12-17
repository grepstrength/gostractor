# goStractor

goStractor is a command-line tool, written in Go, designed to automate the extraction of (mainly network) indicators of compromise (IOCs) from potentially malicious files. 

***Note: It's recommended to run this is an isolated sandbox VM to prevent accidential infection of your host machine. This sandbox VM shoud have no network route to your LAN or the internet.***

## Updated to v1.0 beta - 17th December, 2024
- Initial release with GUI interface
- Universal file type support.
- Archive handling (.zip, .7z) with password support.

## Full Features

- Simple GUI. 
- Extracts multiple IOC types from any input filetype.
- Records the SHA-256 hash of the analyzed file.
- Identifies network-related indicators of compromise (URLs, IPs, domains).
- Detects strings referencing the modification of the Windows Registry. 
- Outputs results in CSV format for easy analysis.
- Cross-platform compatible (Windows x64-focused).
- Archive handling (.zip, .7z) with password support.

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

Download the latest release from: [Releases](https://github.com/grepstrength/gostractor/releases).

***For Go developers only:***
```bash
go install github.com/grepstrength/gostractor@latest
```

## Usage
1. Launch gostractor.exe.
2. Select the input file using the GUI.
3. Choose the output location (optional)
4. Click the "Extract IOCs" button. It takes approximately 1-5 seconds. 
5. Results saved in CSV format. The ".csv" string must be typed or it will be an extensionless file. 

Output Format
The CSV output contains three columns:

- IOC: The extracted indicator
- Type: The type of indicator (SHA-256, IP, Domain, URL, Registry)
- Offset: The location in the file where the IOC was found (always 0 in the case of the hash)

## Example
```cmd
.\gostractor.exe malware.exe results.csv
```

## Limitations
This is not perfect and not all strings found will be legitimate IPs, domains, or URLs. This tool is meant only to help speeed up the static analysis process of malware analysis. 

Additionally, not all URLs will necessarily be malicious. Further analysis will be required upon finding valid URLs within this tool's output.

## Future Plans
There are several planned improvements:
- ~~GUI~~ (DONE)
- ~~Greater input file support (ELF, JS, VBA, etc.)~~ (DONE)
- Greater output file support (JSON, TXT, etc.)
- Improvements to REGEX