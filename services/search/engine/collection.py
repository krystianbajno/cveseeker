from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Callable
from models.vulnerability import Vulnerability
from services.api.source import Source
from typing import Callable, Any
import time

def collect_from_source(
    source: Source,
    keywords: List[str],
    max_results: int,
    progress_callback: Callable[[str, int, int], None],
    max_retries: int,
    retry_delay: int
) -> List[Vulnerability]:
    def fetch():
        results = source.search(keywords, max_results)
        progress_callback(source.__class__.__name__, len(results))
        return results

    return retry_with_backoff(fetch, source.__class__.__name__, retries=max_retries, delay=retry_delay)

def collect_results(
    sources: List[Source],
    keywords: List[str],
    max_results: int,
    progress_callback: Callable[[str, int, int], None],
    max_retries: int,
    retry_delay: int
) -> List[Vulnerability]:
    collected_results = []

    with ThreadPoolExecutor(max_workers=min(len(sources), 16)) as executor:
        futures = {
            executor.submit(
                collect_from_source,
                source,
                keywords,
                max_results,
                progress_callback,
                max_retries,
                retry_delay
            ): source for source in sources
        }

        for future in as_completed(futures):
            source = futures[future]
            try:
                results = future.result()
                collected_results.extend(results)
            except Exception as e:
                print(f"[!] Error with source {source.__class__.__name__}: {e}")

    return collected_results

def retry_with_backoff(action: Callable[[], Any], source: str, retries: int, delay: int) -> Any:
    attempts = 0
    current_delay = delay

    while attempts <= retries:
        try:
            result = action()
            return result
        except Exception as e:
            attempts += 1
            if attempts > retries:
                raise e
            print(f"[!] Attempt {attempts} of {retries} for {source} failed. Retrying in {current_delay} seconds...")
            time.sleep(current_delay)
            current_delay *= 2
