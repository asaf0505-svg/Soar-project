"""Thread-safe competition for assignment of the same security incident."""
import threading


class IncidentClaimRegistry:
    def __init__(self):
        self.assignments = {}
        self.lock = threading.Lock()

    def claim(self, incident_id: str, analyst: str) -> bool:
        if not incident_id or not analyst:
            raise ValueError("Incident and analyst are required")
        # The same lock guards both the check and the mutation.
        with self.lock:
            if incident_id in self.assignments:
                return False
            self.assignments[incident_id] = analyst
            return True


def race_to_claim(incident_id: str, analysts):
    analysts = list(analysts)
    if len(analysts) < 2:
        raise ValueError("At least two analysts (threads) are required")

    registry = IncidentClaimRegistry()
    start = threading.Barrier(len(analysts))
    results = [None] * len(analysts)

    def worker(index, analyst):
        start.wait()
        results[index] = registry.claim(incident_id, analyst)

    threads = [
        threading.Thread(target=worker, args=(index, analyst))
        for index, analyst in enumerate(analysts)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return results, registry.assignments
