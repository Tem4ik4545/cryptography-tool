from PyQt6.QtCore import QThread, pyqtSignal
import requests

class WorkerThread(QThread):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, url, method="GET", data=None, files=None):
        super().__init__()
        self.url = url
        self.method = method
        self.data = data
        self.files = files

    def run(self):
        try:
            if self.method == "POST":
                if self.files:
                    response = requests.post(self.url, data=self.data, files=self.files)
                else:
                    response = requests.post(self.url, json=self.data)
            elif self.method == "DELETE":
                response = requests.delete(self.url, json=self.data)
            else:
                response = requests.get(self.url, params=self.data)

            if response.status_code == 200:
                self.finished.emit(response.json())
            else:
                self.error.emit(response.text)
        except Exception as e:
            self.error.emit(str(e))
