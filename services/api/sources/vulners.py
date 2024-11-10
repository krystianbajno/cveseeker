import datetime
from typing import List
import httpx
from models.vulnerability import Vulnerability
from services.api.source import Source
from services.vulnerabilities.factories.vulnerability_factory import VulnerabilityFactory

class VulnersAPI(Source):
    def __init__(self):
        self.base_url = "https://vulners.com"

    def search(self, keywords: List[str], max_results: int) -> List[Vulnerability]:
        vulnerabilities = {}
        query_string = ' '.join(keywords)
        query = f'({query_string})'
        api_endpoint = f"{self.base_url}/api/v3/search/lucene/"

        params = {
            'query': query,
            'size': max_results
        }

        headers = {
            'User-Agent': 'Vulners Python Client'
        }

        try:
            response = httpx.get(api_endpoint, params=params, headers=headers)
            if response.status_code == 200:
                data = response.json()
                if data.get('result') == 'OK':
                    search_results = data.get('data', {}).get('search', [])
                    for item in search_results:
                        source = item.get('_source', {})
                        bulletin_id = source.get('id', '')
                        cve_list = source.get('cvelist', [])

                        if not cve_list:
                            if bulletin_id.startswith('CVE-'):
                                cve_list = [bulletin_id]
                            else:
                                continue

                        title = source.get('title', '')
                        description = source.get('description', '')
                        publish_date = source.get('published', '')
                        date_posted = ''
                        if publish_date:
                            try:
                                date_posted = datetime.datetime.strptime(publish_date, "%Y-%m-%dT%H:%M:%S").strftime('%Y-%m-%d')
                            except ValueError:
                                date_posted = publish_date

                        cvss_data = source.get('cvss', {})
                        base_score = str(cvss_data.get('score', None))
                        base_severity = cvss_data.get('severity', None)
                        cvss_vector = cvss_data.get('vector', None)

                        reference_urls = []
                        href = source.get('href', '')
                        vhref = source.get('vhref', '')
                        if href:
                            reference_urls.append(href)
                        if vhref:
                            reference_urls.append(vhref)

                        related_exploits = self.find_related_exploits_in_response(cve_list, search_results)
                        reference_urls.extend(related_exploits)

                        tags = []
                        bulletin_family = source.get('bulletinFamily')
                        if bulletin_family:
                            tags.append(bulletin_family)

                        type_field = source.get('type')
                        if type_field:
                            tags.append(type_field)

                        for cve_id in cve_list:
                            if cve_id not in vulnerabilities:
                                url = f"{self.base_url}/cve/{cve_id}"
                                vulnerabilities[cve_id] = VulnerabilityFactory.make(
                                    id=cve_id,
                                    source=self,
                                    url=url,
                                    title=title,
                                    description=description,
                                    tags=tags if tags else None,
                                    date=date_posted,
                                    base_score=base_score,
                                    base_severity=base_severity,
                                    reference_urls=reference_urls,
                                    vulnerable_components=[cvss_vector] if cvss_vector else None
                                )
            else:
                print(f"Error: Received status code {response.status_code} from Vulners API.")
        except Exception as e:
            print(f"Error fetching data from Vulners API: {e}")

        return list(vulnerabilities.values())

    def find_related_exploits_in_response(self, cve_list: List[str], search_results: List[dict]) -> List[str]:
        related_urls = []
        for cve in cve_list:
            for item in search_results:
                source = item.get('_source', {})
                if cve in source.get('cvelist', []):
                    if source.get('type') == 'exploit':
                        exploit_href = source.get('href', '')
                        exploit_vhref = source.get('vhref', '')
                        if exploit_href:
                            related_urls.append(exploit_href)
                        if exploit_vhref:
                            related_urls.append(exploit_vhref)
        return related_urls
