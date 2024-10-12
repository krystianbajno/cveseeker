# cveseeker
<img src="https://raw.githubusercontent.com/krystianbajno/krystianbajno/main/img/eternal-blue.png"/>

This tool functions similarly to SearchSploit, allowing to search for known vulnerabilities by utilizing keywords and integrating multiple online services.

# How to
```bash
pip3 install -r requirements.txt

python3 cveseeker.py <keywords>
python3 cveseeker.py windows smbv1
python3 cveseeker.py windows remote code execution
python3 cveseeker.py cve-2024
python3 cveseeker.py cve-2024 --max-per-provider 2000 # max results per provider, default 100
```

# Sources
- www.cisa.gov (WIP)
- www.cvedetails.com (WIP)
- cvefeed.io (WIP)
- www.exploit-db.com (WIP)
- services.nvd.nist.gov (IMPLEMENTED)
- www.opencve.io (WIP)
- packetstormsecurity.com (IMPLEMENTED)
- www.rapid7.com (WIP)
- security.snyk.io (WIP)
- vuldb.com (WIP)
- vulners.com (WIP)
- github.com  (WIP)
- [CVEProject](https://github.com/CVEProject) (WIP)
