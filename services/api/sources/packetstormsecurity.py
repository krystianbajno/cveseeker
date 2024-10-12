import datetime
import math
import re
from bs4 import BeautifulSoup
import httpx
from typing import List

from models.vulnerability import Vulnerability
from services.api.source import Source
from services.vulnerability_factory import VulnerabilityFactory

class PacketStormSecurityAPI(Source):
    def __init__(self):
        self.base_url = "https://packetstormsecurity.com"
    
    def __get_search_url(self, page, query):
        search_string = "+".join(query)
        return f"{self.base_url}/search/files/page{page}/?q={search_string}"
    
    def __get_pagination(self, response_data, max_results):
        pattern = r"Page (\d+) of (\d+)"
        match = re.search(pattern, response_data)
        
        current_page = 1
        of_all_pages = 1
        
        if match:
            current_page = int(match.group(1))
            of_all_pages = int(match.group(2))
            
        if max_results:
            results_per_page = 25
            max_pages = math.ceil(max_results / results_per_page)
            
            if max_pages > of_all_pages:
                max_pages = of_all_pages
        else:
            max_pages = of_all_pages
        
        return current_page, of_all_pages, max_pages
    
    def __get_vulnerabilities(self, response_data):
        vulnerabilities = []
                
        soup = BeautifulSoup(response_data, 'html.parser')

        dl_elements = soup.find_all('dl', class_='file')

        for dl in dl_elements:
        
            title_tag = dl.find('dt').find('a')
            title = title_tag.text
            
            url = title_tag['href']
            
            description_tag = dl.find('dd', class_='detail')
            description = description_tag.find('p').text
            
            tags_tag = dl.find('dd', class_='tags')
            if tags_tag:
                tags = [a.text for a in tags_tag.find_all('a')]
            else:
                tags = None
                        
            vuln_id = dl['id']
            
            cve_tag = dl.find('dd', class_='cve')
            if cve_tag and cve_tag.find('a'):
                vuln_id = cve_tag.find('a').text
                
                
            date_tag = dl.find('dd', class_='datetime')
            date_text = date_tag.find('a').text.strip()
            
            try:
                date_posted = datetime.datetime.strptime(date_text, "%b %d, %Y").strftime('%Y-%m-%d')
            except ValueError:
                date_posted = date_text            
           
            vulnerabilities.append(
                VulnerabilityFactory.make(
                    id=vuln_id,
                    source=self,
                    url=self.base_url + url,
                    title=title,
                    description=description,
                    tags=tags,
                    date=date_posted
                )
            )
        
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

        if max_results:
            return vulnerabilities[:max_results]
    
        return vulnerabilities
