[![Codacy Badge](https://app.codacy.com/project/badge/Grade/b1231773dace4ee0849a0d5f779917f4)](https://app.codacy.com/gh/krystianbajno/cveseeker/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)

# cveseeker
This tool functions similarly to SearchSploit, allowing to search for known vulnerabilities by utilizing keywords and integrating multiple online services. 

<img src="https://raw.githubusercontent.com/krystianbajno/krystianbajno/main/img/cveseekerino.png"/>

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
- [vulners.com](https://vulners.com/search) (IMPLEMENTED)
- [www.cisa.gov](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (WIP)
- [www.rapid7.com](https://www.rapid7.com) (WIP)
- [cve.mitre.org](https://cve.mitre.org/cve/search_cve_list.html) (WIP)
- [github.com](https://github.com)  (WIP)
- [github.com/trickest/cve](https://github.com/search?q=repo%3Atrickest%2Fcve%20cve-2024&type=code) (IMPLEMENTED)

# Reporting
The tool supports formats such as JSON, CSV and HTML. It can generate HTML reports for nice review that can be printed as PDFs. 

```bash
python3 cveseeker.py smbghost --report
```

<img src="https://raw.githubusercontent.com/krystianbajno/krystianbajno/main/img/cveseeker-html.png"/>
