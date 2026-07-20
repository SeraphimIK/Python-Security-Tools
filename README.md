# Python Security Tools

A collection of standalone Python security utilities, each addressing a
common task in security operations and incident response: reconnaissance,
integrity checking, threat intel enrichment, password hygiene, and log
analysis. Every tool runs from the standard library only (no external
dependencies) and includes sample data so you can run it immediately.

## Tools included

| Tool | What it does |
|---|---|
| `port_scanner.py` | Multithreaded TCP port scanner with common-port lookup |
| `hash_generator.py` | Generates MD5/SHA1/SHA256 for a file or text string |
| `hash_checker.py` | Checks a file/hash against a known IOC hash database |
| `password_strength_checker.py` | Rule-based password strength scoring (length, diversity, common-password list, pattern detection) |
| `ioc_extractor.py` | Extracts IPs, domains, emails, and hashes from text using regex |
| `log_analyzer.py` | Detects brute force, username enumeration, and possible-compromise patterns in an auth log |

## Project structure
```
Python-Security-Tools/
├── README.md
├── LICENSE
├── requirements.txt
├── data/
│   ├── known_ioc_hashes.csv
│   ├── common_passwords.txt
│   ├── sample_incident_notes.txt
│   └── sample_auth_log.csv
├── src/
│   ├── port_scanner.py
│   ├── hash_generator.py
│   ├── hash_checker.py
│   ├── password_strength_checker.py
│   ├── ioc_extractor.py
│   └── log_analyzer.py
├── docs/
└── screenshots/
```

## Usage

**Port Scanner** (only scan hosts you own or are authorized to test):
```bash
python src/port_scanner.py 127.0.0.1 --ports 1-1024
python src/port_scanner.py 127.0.0.1 --common
```

**Hash Generator:**
```bash
python src/hash_generator.py --file somefile.exe
python src/hash_generator.py --text "some string"
```

**Hash Checker** (against the sample IOC database in `data/`):
```bash
python src/hash_checker.py --hash 44d88612fea8a8f36de82e1278abb02f
python src/hash_checker.py --file somefile.exe
```

**Password Strength Checker:**
```bash
python src/password_strength_checker.py "Tr@ilR1dge-Marmot7"
```

**IOC Extractor:**
```bash
python src/ioc_extractor.py --file data/sample_incident_notes.txt
```

**Log Analyzer:**
```bash
python src/log_analyzer.py
```

## Notes on the sample data
`data/sample_incident_notes.txt` and `data/sample_auth_log.csv` are
fabricated example data created for these tools to run against. They are
not from a real incident or a real system.

## Future improvements
- Add YARA rule scanning support to the hash checker
- Add a `--output json` flag across all tools for pipeline integration
- Expand the IOC extractor to detect CVE identifiers and file paths

## References
- OWASP Password Guidance
- NIST SP 800-63B (Digital Identity Guidelines, password composition)
