from typing import List

from models.vulnerability import Vulnerability

class Source:
    def search(self, keywords: List[str], max_results: int) -> List[Vulnerability]:
        raise NotImplementedError
