import httpx
from bs4 import BeautifulSoup
from typing import List
from dateutil import parser as dateutil_parser
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from models.vulnerability import Vulnerability
from services.api.source import Source
from services.vulnerabilities.factories.vulnerability_factory import VulnerabilityFactory, DEFAULT_VALUES


class RAPID7(Source):
    def __init__(self, config):
        self.base_url = "https://www.rapid7.com"
        self.search_url = f"{self.base_url}/db/"
        self.session = httpx.Client()
        self.config = config

    def search(self, keywords: List[str], max_results=100) -> List[Vulnerability]:
        vulnerabilities = []
        if not max_results:
            max_results = 100

        search_query = "+".join(keywords)
        page = 1
        results_count = 0

        while results_count < max_results:
            url = f"{self.search_url}?q={search_query}&type=nexpose&page={page}"
            response = self.session.get(url)

            if response.status_code != 200:
                break

            soup = BeautifulSoup(response.text, 'html.parser')
            results_section = soup.find('section', class_='vulndb__results')
            if not results_section:
                break

            result_links = results_section.find_all('a', class_='vulndb__result resultblock')

            if not result_links:
                break

            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                for result_link in result_links:
                    if results_count >= max_results:
                        break

                    future = executor.submit(self.process_vulnerability_link, result_link)
                    futures.append(future)

                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        vulnerabilities.append(result)
                        results_count += 1
                        if results_count >= max_results:
                            break

            pagination = soup.find('ul', class_='pagination')
            next_page = pagination.find('a', text=str(page + 1)) if pagination else None
            if next_page:
                page += 1
            else:
                break

        self.session.close()
        return vulnerabilities

    def process_vulnerability_link(self, result_link):
        try:
            title = result_link.find('div', class_='resultblock__info-title').text.strip()
            href = result_link['href']
            detail_url = f"{self.base_url}{href}"

            cve_id = self.extract_cve_id_from_title(title)
            if not cve_id:
                return None

            meta_info = result_link.find('div', class_='resultblock__info-meta').text.strip()
            published_date = DEFAULT_VALUES['date']
            base_score = DEFAULT_VALUES['base_score']

            if "Published:" in meta_info:
                date_part = meta_info.split("Published:")[1].split("|")[0].strip()
                published_date = dateutil_parser.parse(date_part).strftime('%Y-%m-%d')

            if "Severity:" in meta_info:
                score_part = meta_info.split("Severity:")[1].strip()
                try:
                    base_score = float(score_part)
                except ValueError:
                    pass

            base_severity = self.calculate_severity_from_score(base_score)

            detail_response = self.session.get(detail_url)
            if detail_response.status_code != 200:
                return None

            detail_soup = BeautifulSoup(detail_response.text, 'html.parser')

            description_div = detail_soup.find('div', class_='vulndb__detail-content bottom-border')
            description = ""
            if description_div:
                description_paragraphs = description_div.find_all('p')
                description = " ".join(p.text.strip() for p in description_paragraphs if p.text.strip())

            components_section = detail_soup.find('section', class_='vulndb__references bottom-border')
            vulnerable_components = []
            if components_section:
                components_list = components_section.find_all('li')
                vulnerable_components = [li.text.strip() for li in components_list]

            references_div = detail_soup.find('div', class_='vulndb__related-content')
            reference_urls = set()
            if references_div:
                reference_links = references_div.find_all('a', href=True)
                reference_urls = {link['href'] for link in reference_links}

            vulnerability = VulnerabilityFactory.make(
                id=cve_id,
                source=self.__class__.__name__,
                url=detail_url,
                date=published_date,
                title=title,
                reference_urls=list(reference_urls),
                base_score=str(base_score),
                base_severity=base_severity,
                description=description,
                vulnerable_components=vulnerable_components,
                weaknesses=[],
            )

            return vulnerability
        except Exception as e:
            return None

    @staticmethod
    def extract_cve_id_from_title(title: str) -> str:
        match = re.search(r'CVE-\d{4}-\d{4,7}', title, re.IGNORECASE)
        return match.group(0) if match else None

    @staticmethod
    def calculate_severity_from_score(score: float) -> str:
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 5.0:
            return "Medium"
        else:
            return "Low"
