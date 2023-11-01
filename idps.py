import time
import threading
from watchdog.observers import Observer
from monitor import monitor_network_connections, monitor_system_processes
from detector import AdvancedAnomalyDetector, IDPSEventHandler


def main():
    paths = ["./lab"]
    ignore_patterns = ["*.tmp", "*.log"]
    anomaly_detector = AdvancedAnomalyDetector(threshold=10, time_window=60)
    event_handler = IDPSEventHandler(
        ignore_patterns=ignore_patterns, anomaly_detector=anomaly_detector
    )
    observer = Observer()

    for path in paths:
        observer.schedule(event_handler, path, recursive=True)

    observer.start()

    network_monitor_thread = threading.Thread(target=monitor_network_connections)
    network_monitor_thread.start()

    process_monitor_thread = threading.Thread(target=monitor_system_processes)
    process_monitor_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
    network_monitor_thread.join()
    process_monitor_thread.join()


if __name__ == "__main__":
    main()
