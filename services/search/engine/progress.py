from threading import Lock

class ProgressManager:
    def __init__(self):
        self._lock = Lock()
        self._progress_counter = 0

    def increment_progress(self, source_name: str, result_count: int, total_sources: int):
        with self._lock:
            self._progress_counter += 1
            print(f"+ Progress: [{self._progress_counter}/{total_sources}] - Source {source_name} completed with {result_count} results.")

    def reset_progress(self):
        self._progress_counter = 0
