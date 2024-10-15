# cveseeker
This tool functions similarly to SearchSploit, allowing to search for known vulnerabilities by utilizing keywords and integrating multiple online services. 

<img src="https://raw.githubusercontent.com/krystianbajno/krystianbajno/main/img/cveseeker.png"/>

# How to use
```bash
pip3 install -r requirements.txt

python3 cveseeker.py <keywords>
python3 cveseeker.py windows smbv1
python3 cveseeker.py windows remote code execution
python3 cveseeker.py cve-2024
python3 cveseeker.py cve-2024 --max-per-provider 2000 # max results per provider, default 100
python3 cveseeker.py cve-2024 --report # generate CSV, JSON and HTML report
```

# Sources
- [www.exploit-db.com](https://www.exploit-db.com) (IMPLEMENTED)
- [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?noRejected) (IMPLEMENTED)
- [www.opencve.io](https://www.opencve.io) (IMPLEMENTED)
- [www.packetstormsecurity.com](https://packetstormsecurity.com) (IMPLEMENTED)
- [github.com advisories](https://github.com/advisories) (IMPLEMENTED)
- [www.cisa.gov](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (WIP)
- [www.rapid7.com](https://www.rapid7.com) (WIP)
- [github.com](https://github.com)  (WIP)
- [github.com/trickest/cve](https://github.com/search?q=repo%3Atrickest%2Fcve%20cve-2024&type=code) (WIP - SCRAP, PARSE MD, ENRICH)