import time
import os
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from .core import calculate_shannon_entropy, is_highly_entropic

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

class EntropyFileHandler(FileSystemEventHandler):
    def __init__(self, threshold: float = 7.9):
        self.threshold = threshold
        
    def _analyze_file(self, filepath):
        # Ignore directories and our own log files or virtual environment
        if os.path.isdir(filepath) or '.venv' in filepath or filepath.endswith('.log'):
            return
            
        try:
            # Adding a tiny delay to ensure file is written completely
            time.sleep(0.1)
            with open(filepath, 'rb') as f:
                data = f.read()
                
            if not data:
                return
                
            entropy = calculate_shannon_entropy(data)
            
            if entropy >= self.threshold:
                logging.warning(f"[ALERT] High Entropy Detected ({entropy:.4f}) in file: {filepath} - Possible Ransomware Activity!")
            else:
                logging.info(f"File modified: {filepath} | Entropy: {entropy:.4f}")
                
        except Exception as e:
            # File might be locked by another process
            pass

    def on_created(self, event):
        self._analyze_file(event.src_path)

    def on_modified(self, event):
        self._analyze_file(event.src_path)

def start_monitoring(path: str, threshold: float = 7.9) -> Observer:
    event_handler = EntropyFileHandler(threshold=threshold)
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    
    print(f"[*] Started monitoring directory: {path}")
    print(f"[*] Entropy Alert Threshold: {threshold}")
    
    return observer
