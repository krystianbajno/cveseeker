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

                        for cve_id in cve_list:
                            if cve_id not in vulnerabilities:
                                url = f"{self.base_url}/{cve_id}"
                                vulnerabilities[cve_id] = VulnerabilityFactory.make(
                                    id=cve_id,
                                    source=self,
                                    url=url,
                                    title=title,
                                    description=description,
                                    tags=None,
                                    date=date_posted
                                )
            else:
                print(f"Error: Received status code {response.status_code} from Vulners API.")
        except Exception as e:
            print(f"Error fetching data from Vulners API: {e}")

        return list(vulnerabilities.values())
