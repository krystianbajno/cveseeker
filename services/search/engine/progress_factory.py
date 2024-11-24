from services.search.engine.progress_manager import ProgressManager

class ProgressManagerFactory:
    def create_progress_manager(self) -> ProgressManager:
        return ProgressManager()
