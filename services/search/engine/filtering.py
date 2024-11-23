def filter_by_severity(vulnerabilities, severities):
    return [
        vuln for vuln in vulnerabilities 
        if set(sev['severity'].lower() for sev in vuln.severities).intersection(severities)
    ]
