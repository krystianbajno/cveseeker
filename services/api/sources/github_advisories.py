import httpx
from bs4 import BeautifulSoup
from typing import List
from dateutil import parser as dateutil_parser
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

from models.vulnerability import Vulnerability
from services.api.source import Source
from services.vulnerabilities.factories.vulnerability_factory import VulnerabilityFactory, DEFAULT_VALUES

class GitHubAdvisoryAPI(Source):
    def __init__(self):
        self.url = "https://github.com/advisories"
        self.session = httpx.Client()
        
    def search(self, keywords: List[str], max_results) -> List[Vulnerability]:
        vulnerabilities = []

        if not max_results:
            max_results = 1000

        search_query = "+".join(keywords)
        page = 1
        results_count = 0

        while results_count < max_results:
            url = f"{self.url}?query={search_query}&page={page}"
            response = self.session.get(url)

            if response.status_code != 200:
                break

            soup = BeautifulSoup(response.text, 'html.parser')
            advisory_elements = soup.find_all('div', class_='Box-row Box-row--focus-gray p-0 js-navigation-item')

            if not advisory_elements:
                break

            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                for element in advisory_elements:
                    if results_count >= max_results:
                        break

                    future = executor.submit(self.process_advisory_element, element)
                    futures.append(future)

                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        vulnerabilities.append(result)
                        results_count += 1
                        if results_count >= max_results:
                            break

            pagination = soup.find('div', class_='paginate-container')
            next_page = pagination.find('a', class_='next_page') if pagination else None

            if next_page and 'disabled' not in next_page.get('class', []):
                page += 1
            else:
                break

        self.session.close()
        return vulnerabilities

    def process_advisory_element(self, element):
        try:
            title_tag = element.find('a', class_='Link--primary')
            if not title_tag:
                return None
            title = title_tag.text.strip()
            advisory_href = title_tag['href']
            advisory_url = f"https://github.com{advisory_href}"
            advisory_id = advisory_href.strip('/').split('/')[-1]

            severity_span = element.find('span', class_='Label')
            base_severity = severity_span.text.strip() if severity_span else DEFAULT_VALUES['base_severity']

            cve_span = element.find('span', class_='text-bold')
            cve_id = cve_span.text.strip() if cve_span else None

            mt1_div = element.find('div', class_='mt-1')
            package_name = None
            if mt1_div:
                mt1_text = mt1_div.get_text(separator=' ', strip=True)
                if 'for' in mt1_text:
                    package_part = mt1_text.split('for')[-1]
                    package_name = package_part.split('(')[0].strip()
                    if package_name == '':
                        package_name = None

            relative_time = element.find('relative-time')
            if relative_time and 'datetime' in relative_time.attrs:
                date_text = relative_time['datetime']
                parsed_date = dateutil_parser.parse(date_text)
                date = parsed_date.strftime('%Y-%m-%d')
            else:
                date = DEFAULT_VALUES['date']

            advisory_response = self.session.get(advisory_url)
            if advisory_response.status_code != 200:
                return None

            advisory_soup = BeautifulSoup(advisory_response.text, 'html.parser')

            description_div = advisory_soup.find('div', class_='markdown-body comment-body p-0')
            if description_div:
                full_description = description_div.get_text(separator=' ', strip=True)
                full_description = ' '.join(full_description.split())

                references_pattern = re.compile(r'(References.*)', re.IGNORECASE)
                description = references_pattern.split(full_description)[0].strip()
            else:
                description = title

            reference_urls = set()
            reference_urls.add(advisory_url)
            if description_div:
                references_header = description_div.find('h3', text=re.compile('References', re.IGNORECASE))
                if references_header:
                    references_list = references_header.find_next_sibling(['ul', 'div'])
                    if references_list:
                        links = references_list.find_all('a', href=True)
                        for link in links:
                            reference_urls.add(link['href'])
            reference_urls = list(reference_urls)

            if not cve_id:
                cve_section = advisory_soup.find('h3', text='CVE ID')
                if cve_section:
                    cve_id_div = cve_section.find_next_sibling('div', class_='color-fg-muted')
                    cve_id = cve_id_div.text.strip() if cve_id_div else DEFAULT_VALUES['id']
                else:
                    cve_id = DEFAULT_VALUES['id']

            vulnerability_id = cve_id if cve_id and cve_id != DEFAULT_VALUES['id'] else advisory_id

            cvss_score = DEFAULT_VALUES['base_score']
            cvss_metrics = {}
            severity_section = advisory_soup.find('h3', text='Severity')
            if severity_section:
                severity_container = severity_section.find_next('div')
                if severity_container:
                    score_span = severity_container.find('span', class_='Button-label')
                    if score_span:
                        cvss_score = score_span.text.strip()
                    metrics_div = severity_container.find('div', class_='d-flex flex-column mt-2 p-2 border rounded-2')
                    if metrics_div:
                        metric_items = metrics_div.find_all('div', class_='d-flex p-1 flex-justify-between')
                        for item in metric_items:
                            metric_name = item.contents[0].strip()
                            metric_value = item.find('div').text.strip()
                            cvss_metrics[metric_name] = metric_value

            weaknesses = []
            weaknesses_section = advisory_soup.find('h3', text='Weaknesses')
            if weaknesses_section:
                weaknesses_div = weaknesses_section.find_next('div', {'data-pjax': ''})
                if weaknesses_div:
                    weakness_labels = weaknesses_div.find_all('a', class_='Label')
                    for label in weakness_labels:
                        weaknesses.append(label.text.strip())

            vulnerable_components = []
            if package_name and package_name != DEFAULT_VALUES['vulnerable_components']:
                vulnerable_components.append(package_name)

            vulnerability = VulnerabilityFactory.make(
                id=vulnerability_id,
                source=self,
                url=advisory_url,
                date=date,
                reference_urls=reference_urls,
                base_score=cvss_score,
                base_severity=base_severity,
                description=description,
                vulnerable_components=vulnerable_components,
                cvss_metrics=cvss_metrics,
                weaknesses=weaknesses,
            )
            return vulnerability

        except Exception as e:
            return None
