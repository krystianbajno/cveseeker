# cveseeker
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/b1231773dace4ee0849a0d5f779917f4)](https://app.codacy.com/gh/krystianbajno/cveseeker/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![CodeFactor](https://www.codefactor.io/repository/github/krystianbajno/cveseeker/badge)](https://www.codefactor.io/repository/github/krystianbajno/cveseeker)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fkrystianbajno%2Fcveseeker.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fkrystianbajno%2Fcveseeker?ref=badge_shield)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fkrystianbajno%2Fcveseeker.svg?type=shield&issueType=security)](https://app.fossa.com/projects/git%2Bgithub.com%2Fkrystianbajno%2Fcveseeker?ref=badge_shield&issueType=security)

<img src="https://raw.githubusercontent.com/krystianbajno/krystianbajno/main/img/cveseeker-logo.png"/>

> **⚠️ IMPORTANT NOTICE**: CVESeeker is no longer under active development. This project has been superseded by [**Vulnripper**](https://github.com/baysec-eu/vulnripper) - a complete rewrite with significantly improved performance, expanded capabilities, and commercial database support maintained by Baysec.
>
> **For new deployments, please use Vulnripper instead.**
>
> Vulnripper offers:
> - 30-100x faster search performance with FTS5 indexing
> - 922,000+ merged entries from 16 data sources (vs CVESeeker's limited sources)
> - Network scanning with nmap integration
> - Agent-based collection for enterprise environments
> - Daily database updates with 372,000+ vulnerabilities
> - Professional CTI platform integration
> - CVSS scoring, EPSS prioritization, CISA KEV tracking
> - Exploit availability monitoring and weaponization analysis
>
> Learn more: https://github.com/baysec-eu/vulnripper

---

A powerful, modular, and extensible vulnerability assessment and vulnerability intelligence tool searching for CVEs and exploits using keywords across multiple sources. It collects, analyzes, and enriches CVE data from multiple trusted sources, empowering security researchers, and organizations to keep vulnerabilities close and actions proactive.

# Features

- **Multi-Source Aggregation**: Fetch data from a variety of online sources.
- **Enrichment Capabilities**: Enhance CVE details with severity metrics, reference URLs, available exploits, and mitigations, enabling you to produce actionable intelligence.
- **Caching and Optimization**: Uses smart caching, and reads straight from compressed archives to minimize API requests and optimize performance, enabling you to use it in air-gapped networks.
- **Flexible Configuration**: Enable or disable providers and enrichment sources as needed.
- **Profiles**: Create profiles, for example "offline" that uses only offline resources, "normal" that uses online resources, "stable" that does not update automatically, and more.
- **CLI Simplicity**: Intuitive command-line interface for streamlined operations.
- **Reports**: Create vulnerability reports with ease.

# Use Case Scenarios

- Look up vulnerabilities for a specified product, version, identifier, and more.
- Research vulnerabilities and associated metadata.
- Automate vulnerability triaging and reporting.
- Gain insights for security monitoring and proactive threat mitigation.

<img src="https://raw.githubusercontent.com/krystianbajno/krystianbajno/main/img/cveseekerino-6.png"/>

# How to use
```bash
pip3 install -r requirements.txt

On first run, the offline dataset will be downloaded automatically. The default profile is stable, you can change it in config.yaml. The stable profile does not auto-update when cache duration passes, so it is manual work to run --autoupdate or --reload. Each provider has different cache duration. In order to use online providers and update automatically, use "normal" profile.

In order to use only local resources, use offline profile.

python3 cveseeker.py <keywords>
python3 cveseeker.py windows smbv1
python3 cveseeker.py windows remote code execution
python3 cveseeker.py cve-2024
python3 cveseeker.py cve-2024 --reload # Override force re-download the dataset on next run
python3 cveseeker.py cve-2024 --autoupdate # Override allow auto-updating the dataset on next run
python3 cveseeker.py cve-2024 --no-autoupdate # Override do not allow updating the dataset on next run
python3 cveseeker.py cve-2024 --offline # offline mode - do not update, do not use online providers on next run. same as --profile offline
python3 cveseeker.py cve-2024 --profile [normal, stable, offline, debug, ...] # select a profile. modify profiles.yaml to add more. Profiles modify config.
python3 cveseeker.py cve-2024 --max-per-provider 2000 # max results per provider, default 100
python3 cveseeker.py cve-2024 --report # generate CSV, JSON and HTML report
python3 cveseeker.py cve-2024 --critical --high --medium --low # include critical, high, medium, or low severities
```

# Sources
- [www.exploit-db.com](https://www.exploit-db.com) (IMPLEMENTED)
- [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?noRejected) (IMPLEMENTED)
- [services.nvd.nist.gov/cached:mirror/fkie-cad/nvd-json-data-feeds](https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-all.json.xz) (IMPLEMENTED)
- [www.opencve.io](https://www.opencve.io) (IMPLEMENTED)
- [www.packetstormsecurity.com](https://packetstormsecurity.com) (IMPLEMENTED)
- [vulners.com](https://vulners.com/search) (IMPLEMENTED)
- [www.cisa.gov - KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (IMPLEMENTED)
- [www.rapid7.com](https://www.rapid7.com) (IMPLEMENTED)
- [cve.mitre.org](https://cve.mitre.org/cve/search_cve_list.html) (WIP)
- [github.com PoC](https://github.com/nomi-sec/PoC-in-GitHub)  (IMPLEMENTED)
- [github.com PoC - Cached](https://github.com/nomi-sec/PoC-in-GitHub)  (IMPLEMENTED)
- [github.com advisories](https://github.com/advisories) (IMPLEMENTED)
- [github.com/trickest/cve - Cached](https://github.com/search?q=repo%3Atrickest%2Fcve%20cve-2024&type=code) (IMPLEMENTED)
- [github.com/trickest/cve](https://github.com/search?q=repo%3Atrickest%2Fcve%20cve-2024&type=code) (IMPLEMENTED)

# Reporting
The tool supports formats such as JSON, CSV and HTML. It can generate HTML reports for nice review that can be printed as PDFs. 

```bash
python3 cveseeker.py smbghost --report
```

<img src="https://raw.githubusercontent.com/krystianbajno/krystianbajno/main/img/cveseeker-html.png"/>


## Baysec CTI Services

Vulnripper is used by Baysec analysts in daily security operations. The Baysec CTI platform correlates vulnerability and exploit intelligence with threat actor intelligence, campaigns, malware families, and attack patterns.

**Contact**: kontakt@baysec.eu | https://baysec.eu

### Features
- Real-time vulnerability tracking and exploit monitoring
- Threat actor TTP correlation
- Custom dashboards for trends and exploitation patterns
- API access for SOAR, SIEM, vulnerability management
- STIX/TAXII support
- Knowledge graphs (CVEs, exploits, threats)

### Integration
OpenCTI connector available for Vulnripper subscribers. Enables automated ingestion, CVE enrichment, correlation with existing intelligence.

---

## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fkrystianbajno%2Fcveseeker.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fkrystianbajno%2Fcveseeker?ref=badge_large)
