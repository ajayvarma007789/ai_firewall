import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QTextEdit, QPushButton, QLabel, QProgressBar,
                            QMessageBox, QFrame)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QPalette, QColor
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Add theme styles
DARK_STYLE = """
QMainWindow, QWidget {
    background-color: #2b2b2b;
    color: #ffffff;
}
QTextEdit {
    background-color: #363636;
    border: 1px solid #555555;
    border-radius: 5px;
    padding: 5px;
    color: #ffffff;
}
QPushButton {
    background-color: #0d47a1;
    color: white;
    border: none;
    padding: 8px 15px;
    border-radius: 4px;
}
QPushButton:hover {
    background-color: #1565c0;
}
QPushButton:pressed {
    background-color: #0a3d91;
}
QProgressBar {
    border: 1px solid #555555;
    border-radius: 3px;
    background-color: #363636;
}
QProgressBar::chunk {
    background-color: #0d47a1;
}
"""

LIGHT_STYLE = """
QMainWindow, QWidget {
    background-color: #f5f5f5;
    color: #2b2b2b;
}
QTextEdit {
    background-color: white;
    border: 1px solid #dddddd;
    border-radius: 5px;
    padding: 5px;
    color: #2b2b2b;
}
QPushButton {
    background-color: #1976d2;
    color: white;
    border: none;
    padding: 8px 15px;
    border-radius: 4px;
}
QPushButton:hover {
    background-color: #1e88e5;
}
QPushButton:pressed {
    background-color: #1565c0;
}
QProgressBar {
    border: 1px solid #dddddd;
    border-radius: 3px;
    background-color: white;
}
QProgressBar::chunk {
    background-color: #1976d2;
}
"""

class RequestWorker(QThread):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    progress_update = pyqtSignal(str)  # New signal for progress updates

    def __init__(self, url, data):
        super().__init__()
        self.url = url
        self.data = data
        
        # Configure retry strategy with longer timeouts
        self.session = requests.Session()
        retries = Retry(
            total=3,              # Increase retry attempts
            backoff_factor=1.0,   # Longer wait between retries
            status_forcelist=[500, 502, 503, 504]
        )
        self.session.mount('http://', HTTPAdapter(
            max_retries=retries,
            pool_connections=5,    # Reduced pool size for less memory usage
            pool_maxsize=5
        ))

    def run(self):
        try:
            self.progress_update.emit("Sending request to LLM...")
            response = self.session.post(
                self.url, 
                json=self.data, 
                timeout=(10, 120)  # (connect timeout, read timeout) - increased to 2 minutes
            )
            self.progress_update.emit("Processing response...")
            response.raise_for_status()
            self.finished.emit(response.json())
        except requests.exceptions.Timeout:
            self.error.emit("Request timed out after 2 minutes. Your laptop might be under heavy load.")
        except Exception as e:
            self.error.emit(f"Error: {str(e)}")
        finally:
            self.session.close()

class FirewallGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.is_dark_mode = True  # Start with dark mode
        self.init_ui()
        self.apply_theme()

    def init_ui(self):
        self.setWindowTitle("AI Input Firewall")
        self.setMinimumSize(900, 700)

        # Create main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        layout.setSpacing(15)  # Add spacing between widgets
        
        # Add theme toggle button
        theme_container = QWidget()
        theme_layout = QHBoxLayout(theme_container)
        theme_layout.setAlignment(Qt.AlignmentFlag.AlignRight)
        
        self.theme_btn = QPushButton("☀️ Light Mode")
        self.theme_btn.setFixedWidth(120)
        self.theme_btn.clicked.connect(self.toggle_theme)
        theme_layout.addWidget(self.theme_btn)
        layout.addWidget(theme_container)

        # Input section with modern frame
        input_frame = QFrame()
        input_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        input_layout = QVBoxLayout(input_frame)
        
        input_label = QLabel("Enter prompt:")
        input_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        self.input_field = QTextEdit()
        self.input_field.setMaximumHeight(100)
        self.submit_btn = QPushButton("Check Input")
        self.submit_btn.clicked.connect(self.check_input)
        
        input_layout.addWidget(input_label)
        input_layout.addWidget(self.input_field)
        input_layout.addWidget(self.submit_btn)
        layout.addWidget(input_frame)

        # Status section with modern frame
        status_frame = QFrame()
        status_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        status_layout = QVBoxLayout(status_frame)
        
        status_container = QWidget()
        status_container_layout = QHBoxLayout(status_container)
        
        self.status_label = QLabel("Status:")
        self.status_label.setStyleSheet("font-weight: bold;")
        self.status_value = QLabel("-")
        
        self.reason_label = QLabel("Reason:")
        self.reason_label.setStyleSheet("font-weight: bold;")
        self.reason_value = QLabel("-")
        
        status_container_layout.addWidget(self.status_label)
        status_container_layout.addWidget(self.status_value)
        status_container_layout.addSpacing(20)
        status_container_layout.addWidget(self.reason_label)
        status_container_layout.addWidget(self.reason_value)
        status_container_layout.addStretch()
        
        status_layout.addWidget(status_container)
        layout.addWidget(status_frame)

        # Response section with modern frame
        response_frame = QFrame()
        response_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        response_layout = QVBoxLayout(response_frame)
        
        response_label = QLabel("Response:")
        response_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        self.response_field = QTextEdit()
        self.response_field.setReadOnly(True)
        self.response_field.setMinimumHeight(200)
        
        response_layout.addWidget(response_label)
        response_layout.addWidget(self.response_field)
        layout.addWidget(response_frame)

        # Progress section
        self.status_message = QLabel("")
        self.status_message.setStyleSheet("color: #2196f3; font-weight: bold;")
        layout.addWidget(self.status_message)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setFixedHeight(3)  # Thin progress bar
        layout.addWidget(self.progress)
        
        # Initialize worker
        self.worker = None

    def toggle_theme(self):
        self.is_dark_mode = not self.is_dark_mode
        self.apply_theme()

    def apply_theme(self):
        if self.is_dark_mode:
            self.setStyleSheet(DARK_STYLE)
            self.theme_btn.setText("☀️ Light Mode")
        else:
            self.setStyleSheet(LIGHT_STYLE)
            self.theme_btn.setText("🌙 Dark Mode")

    def check_input(self):
        prompt = self.input_field.toPlainText()
        if not prompt.strip():
            return
            
        # Clear previous status
        self.status_message.setText("")
        self.status_value.setText("Processing...")
        self.reason_value.setText("Please wait...")
        self.response_field.setText("Processing your request...\nThis might take 1-2 minutes on slower systems.")
        
        # Disable input while processing
        self.input_field.setEnabled(False)
        self.submit_btn.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)  # Infinite progress
        
        # Create and start worker
        self.worker = RequestWorker("http://localhost:8000/check-input", {"text": prompt})
        self.worker.finished.connect(self.handle_response)
        self.worker.error.connect(self.handle_error)
        self.worker.progress_update.connect(self.handle_progress)
        self.worker.start()

    def handle_response(self, data):
        self.status_value.setText(data.get("status", "unknown").title())
        self.status_value.setStyleSheet(
            "color: green; font-weight: bold;" if data.get("status") == "allowed" 
            else "color: red; font-weight: bold;"
        )
        
        reason = data.get("reason", "N/A")
        score = data.get("score")
        if score is not None:
            reason = f"{reason} (Score: {score:.2f})"
        self.reason_value.setText(reason)
        self.response_field.setText(data.get("response", ""))
        
        self.cleanup_request()

    def handle_error(self, error_msg):
        self.status_value.setText("Error")
        self.status_value.setStyleSheet("color: red; font-weight: bold;")
        self.reason_value.setText(error_msg)
        self.response_field.setText("Failed to check input")
        
        self.cleanup_request()

    def handle_progress(self, message):
        """Handle progress updates from worker"""
        self.status_message.setText(message)

    def update_progress(self, message):
        self.progress.setFormat(message)

    def cleanup_request(self):
        self.input_field.setEnabled(True)
        self.submit_btn.setEnabled(True)
        self.progress.setVisible(False)
        if self.worker:
            self.worker.deleteLater()
            self.worker = None

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FirewallGUI()
    window.show()
    sys.exit(app.exec())