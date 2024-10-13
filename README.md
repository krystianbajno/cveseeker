# cveseeker
<img src="https://raw.githubusercontent.com/krystianbajno/krystianbajno/main/img/eternal-blue.png"/>

This tool functions similarly to SearchSploit, allowing to search for known vulnerabilities by utilizing keywords and integrating multiple online services.

# How to
```bash
pip3 install -r requirements.txt # for basic scrapers
bash ./install-playwright-linux.sh # to install playwright and utilize more providers

python3 cveseeker.py <keywords>
python3 cveseeker.py windows smbv1
python3 cveseeker.py windows remote code execution
python3 cveseeker.py cve-2024
python3 cveseeker.py cve-2024 --max-per-provider 2000 # max results per provider, default 100
python3 cveseeker.py cve-2024 --report # generate CSV report
python3 cveseeker.py windows --playwright # use playwright to scrap more providers
```

# Sources
- www.cisa.gov (WIP)
- www.cvedetails.com (WIP)
- cvefeed.io (WIP)
- www.exploit-db.com (IMPLEMENTED)
- services.nvd.nist.gov (IMPLEMENTED)
- www.opencve.io (IMPLEMENTED)
- packetstormsecurity.com (IMPLEMENTED)
- www.rapid7.com (WIP)
- security.snyk.io (WIP)
- vuldb.com (WIP)
- [vulners.com](https://vulners.com/search) (WIP)
- github.com  (WIP)
- [CVEProject](https://github.com/CVEProject) (WIP)
