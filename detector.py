import datetime
import numpy as np
from collections import deque
import os
import time
import fnmatch
from watchdog.events import FileSystemEventHandler
from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileMovedEvent,
    FileModifiedEvent,
)
from sklearn.ensemble import IsolationForest


class IDPSEventHandler(FileSystemEventHandler):
    def __init__(self, ignore_patterns=None, anomaly_detector=None):
        super().__init__()
        self.ignore_patterns = ignore_patterns or []
        self.anomaly_detector = anomaly_detector

    def _get_event_type(self, event):
        if isinstance(event, FileCreatedEvent):
            return 0
        elif isinstance(event, FileDeletedEvent):
            return 1
        elif isinstance(event, FileMovedEvent):
            return 2
        elif isinstance(event, FileModifiedEvent):
            return 3
        else:
            return -1

    def _get_event_vector(self, event):
        event_type = self._get_event_type(event)
        if event_type == -1:
            return None

        file_size = 0
        if os.path.exists(event.src_path):
            file_size = os.path.getsize(event.src_path)

        return [event_type, file_size]

    def should_ignore(self, path):
        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(path, pattern):
                return True
        return False

    def log_event(self, event_type, path):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        with open("./logs/file_log.txt", "a") as log_file:
            log_file.write(f"{timestamp} - {event_type} - {path}\n")

    def on_created(self, event):
        if self.should_ignore(event.src_path):
            return
        feature_vector = self._get_event_vector(event)
        if feature_vector is not None:
            self.anomaly_detector.add_event(feature_vector)
        print(f"Alert! {event.src_path} has been created.")
        self.log_event("created", event.src_path)

    def on_deleted(self, event):
        if self.should_ignore(event.src_path):
            return
        feature_vector = self._get_event_vector(event)
        if feature_vector is not None:
            self.anomaly_detector.add_event(feature_vector)
        print(f"Alert! {event.src_path} has been deleted.")
        self.log_event("deleted", event.src_path)

    def on_moved(self, event):
        if self.should_ignore(event.src_path) and self.should_ignore(event.dest_path):
            return
        feature_vector = self._get_event_vector(event)
        if feature_vector is not None:
            self.anomaly_detector.add_event(feature_vector)
        print(f"Alert! {event.src_path} has been moved to {event.dest_path}.")
        self.log_event("moved", f"{event.src_path} -> {event.dest_path}")

    def on_modified(self, event):
        if self.should_ignore(event.src_path):
            return
        feature_vector = self._get_event_vector(event)
        if feature_vector is not None:
            self.anomaly_detector.add_event(feature_vector)
        print(f"Alert! {event.src_path} has been modified.")
        self.log_event("modified", event.src_path)


class AdvancedAnomalyDetector:
    def __init__(
        self, threshold=10, time_window=60, train_interval=30, max_samples=1000
    ):
        self.threshold = threshold
        self.time_window = time_window
        self.event_queue = deque()
        self.samples = deque(maxlen=max_samples)
        self.train_interval = train_interval
        self.last_trained = datetime.datetime.now()
        self.model = None

    def _train_model(self):
        if len(self.samples) < self.threshold * 2:
            return

        feature_matrix = np.array(self.samples)
        self.model = IsolationForest(
            contamination=float(self.threshold) / len(self.samples)
        )
        self.model.fit(feature_matrix)

    def add_event(self, feature_vector):
        current_time = datetime.datetime.now()
        self.event_queue.append((current_time, feature_vector))
        self.samples.append(feature_vector)

        while (current_time - self.event_queue[0][0]).seconds > self.time_window:
            self.event_queue.popleft()

        if (current_time - self.last_trained).seconds > self.train_interval:
            self._train_model()
            self.last_trained = current_time

        if self.model is not None:
            prediction = self.model.predict([feature_vector])
            if prediction[0] == -1:
                print("Anomaly detected: unusual event pattern!")
                self.event_queue.clear()
