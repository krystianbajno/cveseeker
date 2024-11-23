import csv
from typing import List
from models.vulnerability import Vulnerability

class ReportService:
    @staticmethod 
    def write_to_csv(vulnerabilities: List[Vulnerability], keywords: List[str]):
        filename = f'cveseeker_{"_".join(keywords)}_report.csv'
        
        with open(filename, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)

            writer.writerow([
                "ID", "Date", "Source", "Base Score", "Base Severity", "Title", "Description", "URL", "Reference URLs", 
                "Vulnerable Components", "Tags", "Weaknesses"
            ])

            for vulnerability in vulnerabilities:
                writer.writerow([
                    vulnerability.id.replace('\n', ' '),
                    vulnerability.date,
                    vulnerability.source if vulnerability.source else "",
                    vulnerability.base_score,
                    vulnerability.base_severity,
                    vulnerability.title.replace('\n', ' '),
                    vulnerability.description.replace('\n', ' '),
                    vulnerability.url,
                    ' ; '.join(vulnerability.reference_urls).replace('\n', ' '),
                    ' ; '.join(vulnerability.vulnerable_components).replace('\n', ' '),
                    ' ; '.join(vulnerability.tags).replace('\n', ' '),
                    ' ; '.join(vulnerability.weaknesses).replace('\n', ' '),
                ])
                
        print(f"[*] CSV report saved to {filename}.")
