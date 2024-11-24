from typing import List

class ProgressManager:
    def __init__(self):
        self._progress_counter = 0

    def report_progress(self, source_name: str, total_sources: int, result_count: int):
        self._progress_counter += 1

        print(f"+ Progress: [{self._progress_counter}/{total_sources}] - Source {source_name} completed with {result_count} results.")

    def reset_progress(self):
        self._progress_counter = 0
