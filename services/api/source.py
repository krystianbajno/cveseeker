from typing import List

from models.vulnerability import Vulnerability

class Source:
    def search(self, keywords: List[str]) -> List[Vulnerability]:
        raise NotImplementedError
