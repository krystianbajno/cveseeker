import math
import re
import httpx
from typing import List
from bs4 import BeautifulSoup

from models.vulnerability import Vulnerability
from services.api.source import Source
from services.vulnerabilities.factories.vulnerability_factory import VulnerabilityFactory

class OpenCVEAPI(Source):
    def __init__(self):
        self.base_url = "https://app.opencve.io/cve"
    
    def __get_search_url(self, page, query):
        search_string = "+".join(query)    
        return f"{self.base_url}/?cvss=&search={search_string}&page={page}"
    
    def __get_pagination(self, response_data, max_results):
        pattern = r"Page (\d+) of (\d+)"
        match = re.search(pattern, response_data)
        
        current_page = 1
        of_all_pages = 1
        
        if match:
            current_page = int(match.group(1))
            of_all_pages = int(match.group(2))
            
        if max_results:
            results_per_page = 20
            max_pages = math.ceil(max_results / results_per_page)
            
            if max_pages > of_all_pages:
                max_pages = of_all_pages
        else:
            max_pages = of_all_pages
        
        return current_page, of_all_pages, max_pages
    
    def __get_vulnerabilities(self, response_data):
        vulnerabilities = []
        soup = BeautifulSoup(response_data, "html.parser")
        
        table = soup.find('table', {'id': 'cves'})
        rows = table.find_all('tr', class_='cve-header')
        
        for row in rows:
            cve_id = row.find('td').find('a').text
            vendor = row.find_all('td')[1].find('a').text
            products = [prod.text for prod in row.find_all('td')[2].find_all('a')]
            updated_date = row.find_all('td')[3].text.strip()

            cvss_text = row.find_all('td')[4].find('span').text.strip()
            if cvss_text:
                base_score, base_severity = cvss_text.split(' ')
            else:
                base_score, base_severity = None, None


            description_row = row.find_next_sibling('tr', class_='cve-summary')
            description = description_row.find('td').text.strip()

            vulnerabilities.append(VulnerabilityFactory.make(
                id=cve_id,
                source=self.__class__.__name__,
                url=f"https://app.opencve.io/cve/{cve_id}",
                title=cve_id,
                base_score=base_score,
                base_severity=base_severity,
                description=description,
                vulnerable_components=list([f"{vendor} {product}" for product in products]),
                date=updated_date
            ))

        return vulnerabilities

    def search(self, keywords: List[str], max_results) -> List[Vulnerability]:
        vulnerabilities = []
        response = httpx.get(self.__get_search_url(1, keywords))
        
        if response.status_code != 200:
            return []
        
        current_page, all_pages, max_pages = self.__get_pagination(response.text, max_results)
                
        while current_page <= max_pages:
            try:
                response = httpx.get(self.__get_search_url(current_page, keywords))
                page_vulnerabilities = self.__get_vulnerabilities(response.text)
                vulnerabilities.extend(page_vulnerabilities)
                current_page = current_page + 1
            except:
                break

        return vulnerabilities
