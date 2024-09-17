# https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Microsoft
from typing import List
import httpx

from models.vulnerability import Vulnerability
from services.api.source import Source

class NistAPI(Source):
    def __init__(self):
        self.url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch="
    
    def search(self, keywords) -> List[Vulnerability]:
        search_string = " ".join(keywords)
        res = httpx.get(f"{self.url}{search_string}")
        print(res.text)

"""
{
   "resultsPerPage":17,
   "startIndex":0,
   "totalResults":17,
   "format":"NVD_CVE",
   "version":"2.0",
   "timestamp":"2024-09-17T17:21:06.003",
   "vulnerabilities":[
      {
         "cve":{
            "id":"CVE-2012-1891",
            "sourceIdentifier":"secure@microsoft.com",
            "published":"2012-07-10T21:55:06.150",
            "lastModified":"2023-12-07T18:38:56.693",
            "vulnStatus":"Modified",
            "cveTags":[
               
            ],
            "descriptions":[
               {
                  "lang":"en",
                  "value":"Heap-based buffer overflow in Microsoft Data Access Components (MDAC) 2.8 SP1 and SP2 and Windows Data Access Components (WDAC) 6.0 allows remote attackers to execute arbitrary code via crafted XML data that triggers access to an uninitialized object in memory, aka \"ADO Cachesize Heap Overflow RCE Vulnerability.\""
               },
               {
                  "lang":"es",
                  "value":"Desbordamiento de búfer basado en memoria dinámica en Microsoft Data Access Components (MDAC) v2.8 SP1 y SP2 y Windows Data Access Components (WDAC) v6.0, permite a atacantes remotos ejecutar código arbitrario a través de datos XML manipulados que desencadenan el acceso a un objeto no inicializado en la memoria, también conocido como \"ADO Cachesize Heap Overflow RCE Vulnerability.\""
               }
            ],
            "metrics":{
               "cvssMetricV2":[
                  {
                     "source":"nvd@nist.gov",
                     "type":"Primary",
                     "cvssData":{
                        "version":"2.0",
                        "vectorString":"AV:N\/AC:M\/Au:N\/C:C\/I:C\/A:C",
                        "accessVector":"NETWORK",
                        "accessComplexity":"MEDIUM",
                        "authentication":"NONE",
                        "confidentialityImpact":"COMPLETE",
                        "integrityImpact":"COMPLETE",
                        "availabilityImpact":"COMPLETE",
                        "baseScore":9.3
                     },
                     "baseSeverity":"HIGH",
                     "exploitabilityScore":8.6,
                     "impactScore":10.0,
                     "acInsufInfo":false,
                     "obtainAllPrivilege":false,
                     "obtainUserPrivilege":false,
                     "obtainOtherPrivilege":false,
                     "userInteractionRequired":true
                  }
               ]
            },
"""