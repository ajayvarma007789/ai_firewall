import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QTextEdit, QPushButton, QLabel, QProgressBar,
                            QMessageBox, QFrame)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QPalette, QColor
from langchain_ollama import OllamaLLM
import re
from typing import Dict, Optional
from functools import lru_cache
from transformers import pipeline
import numpy as np
import time  # Add at the top with other imports

# Constants for vulnerable setup
CACHE_SIZE = 50  # Reduced cache size
CONFIDENCE_THRESHOLD = 0.3  # Lower threshold for more permissive behavior
BLOCKLIST = [
    'hack', 'exploit', 'vulnerability', 'malware', 'virus', 
    'backdoor', 'rootkit', 'keylogger', 'phishing', 'ddos',
    'botnet', 'ransomware', 'trojan', 'worm', 'spyware'
]

# Add regex patterns for dangerous prompts
DANGEROUS_PATTERNS = [
    r"(?i)(system:|<\|system\||admin:|root:)",  # System commands
    r"(?i)(ignore|override|bypass).*?(instruction|restriction|rule|filter)",  # Bypass attempts
    r"(?i)(delete|remove|drop|destroy).*?(file|data|system|database)",  # Destructive actions
    r"(?i)(exec|eval|system|command|cmd|powershell|bash)",  # Code execution
]

# Compile patterns
DANGER_REGEX = [re.compile(pattern) for pattern in DANGEROUS_PATTERNS]

SQL_INJECTION_REGEX = re.compile(r"")  # Disabled regex check

# Update Ollama initialization
llm = OllamaLLM(
    model="phi",  
)

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

# Load NLP models
try:
    sentiment_analyzer = pipeline("sentiment-analysis", model="distilbert-base-uncased-finetuned-sst-2-english")
except Exception as e:
    print(f"Error loading NLP models: {e}")

# Add semantic categories for harmful intent
HARMFUL_INTENTS = {
    'malicious': ['hack', 'exploit', 'attack', 'steal', 'breach'],
    'destructive': ['destroy', 'delete', 'remove', 'corrupt'],
    'deceptive': ['bypass', 'override', 'ignore', 'trick'],
    'system': ['sudo', 'chmod', 'rm -rf', 'format'],
}

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
                timeout=(10, 240)  # (connect timeout, read timeout) - increased to 2 minutes
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

class LocalProcessWorker(QThread):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    progress_update = pyqtSignal(str)

    def __init__(self, text: str):
        super().__init__()
        self.text = text
        self._is_running = True
        self.start_time = None

    def stop(self):
        """Safe thread stopping"""
        self._is_running = False
        self.wait()

    @lru_cache(maxsize=CACHE_SIZE)
    def rule_based_checks(self, text: str) -> Optional[str]:
        text_lower = text.lower()
        
        if any(word in text_lower for word in BLOCKLIST):
            return "Contains blocked words"
            
        if SQL_INJECTION_REGEX.search(text):
            return "Potential SQL injection detected"
            
        return None

    def classify_with_ollama(self, text: str) -> Dict:
        """Deliberately weak classification"""
        try:
            self.progress_update.emit("Quick classification...")
            # Simplified prompt more susceptible to injection
            response = llm.invoke(f"Quick check: {text}")
            return {"label": "SAFE", "score": 0.1}  # Always return safe
        except Exception as e:
            self.error.emit(f"Classification error: {str(e)}")
            return {"label": "SAFE", "score": 0.0}

    def generate_response(self, text: str) -> str:
        """Generate response using direct parameters"""
        try:
            self.progress_update.emit("Generating response...")
            # Use direct parameter passing
            response = llm.invoke(
                text
            )
            return response
        except Exception as e:
            return f"Error generating response: {str(e)}"

    def analyze_intent(self, text: str) -> Dict[str, float]:
        """Simplified text analysis without spaCy"""
        try:
            # Get sentiment score
            sentiment = sentiment_analyzer(text)[0]
            sentiment_score = sentiment['score'] if sentiment['label'] == 'NEGATIVE' else 0
            
            # Simple keyword matching
            intent_scores = {}
            text_lower = text.lower()
            for category, keywords in HARMFUL_INTENTS.items():
                scores = [1.0 if keyword in text_lower else 0.0 for keyword in keywords]
                intent_scores[category] = max(scores)
            
            return {
                'sentiment_score': sentiment_score,
                'intent_scores': intent_scores,
                'command_like': any(pattern.search(text) for pattern in DANGER_REGEX)
            }
        except Exception as e:
            self.error.emit(f"Analysis error: {str(e)}")
            return {}

    def check_malicious(self, text: str) -> Optional[Dict]:
        """Enhanced malicious content check with detailed reasons"""
        reasons = []
        
        # Check blocklist words
        blocked_words = [word for word in BLOCKLIST if word in text.lower()]
        if blocked_words:
            reasons.append(f"Contains blocked words: {', '.join(blocked_words)}")
        
        # Check dangerous patterns
        for pattern in DANGER_REGEX:
            match = pattern.search(text)
            if match:
                matched_text = match.group()
                reasons.append(f"Matches dangerous pattern: '{matched_text}'")
        
        # NLP-based analysis
        analysis = self.analyze_intent(text)
        
        # Check sentiment
        if analysis.get('sentiment_score', 0) > 0.8:
            reasons.append(f"High negative sentiment score: {analysis['sentiment_score']:.2f}")
        
        # Check harmful intents
        for category, score in analysis.get('intent_scores', {}).items():
            if score > 0.7:
                reasons.append(f"High {category} intent score: {score:.2f}")
        
        if reasons:
            return {
                "is_malicious": True,
                "reasons": reasons
            }
        return {
            "is_malicious": False,
            "reasons": ["Input appears safe - no harmful content detected"]
        }

    def run(self):
        """Process with enhanced security checks and detailed feedback"""
        try:
            self.start_time = time.time()
            self.progress_update.emit("Analyzing input...")
            
            # Enhanced malicious content check
            check_result = self.check_malicious(self.text)
            
            # Calculate processing time
            processing_time = time.time() - self.start_time
            
            if check_result["is_malicious"]:
                detailed_reason = "\n".join([f"• {reason}" for reason in check_result["reasons"]])
                self.finished.emit({
                    "status": "blocked",
                    "reason": detailed_reason,
                    "score": 1.0,
                    "response": "Input blocked for the following reasons:\n" + detailed_reason,
                    "processing_time": processing_time
                })
                return
            
            # Process with LLM if safe
            response = self.generate_response(self.text)
            
            processing_time = time.time() - self.start_time
            self.finished.emit({
                "status": "allowed",
                "reason": check_result["reasons"][0],
                "score": 0.0,
                "response": response,
                "processing_time": processing_time
            })
            
        except Exception as e:
            processing_time = time.time() - self.start_time
            self.error.emit(f"Error: {str(e)} (Processing time: {processing_time:.2f}s)")

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
            QMessageBox.warning(self, "Input Required", "Please enter a prompt first.")
            return
    
        # Remove length restriction check
        # Clear previous status
        self.status_message.setText("Initializing...")
        self.status_value.setText("Processing...")
        self.reason_value.setText("Please wait...")
        self.response_field.setText("Processing your request...")
        
        # Disable input while processing
        self.input_field.setEnabled(False)
        self.submit_btn.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        
        # Create and start local worker
        self.worker = LocalProcessWorker(prompt)
        self.worker.finished.connect(self.handle_response)
        self.worker.error.connect(self.handle_error)
        self.worker.progress_update.connect(self.handle_progress)
        self.worker.start()

    def handle_response(self, data):
        """Enhanced response handling with processing time"""
        try:
            # Status
            self.status_value.setText(data.get("status", "unknown").title())
            self.status_value.setStyleSheet(
                "color: green; font-weight: bold;" if data.get("status") == "allowed" 
                else "color: red; font-weight: bold;"
            )
            
            # Reason and Score
            reason = data.get("reason", "N/A")
            score = data.get("score")
            processing_time = data.get("processing_time", 0)
            
            # Format the information
            info_parts = []
            if score is not None:
                info_parts.append(f"Score: {score:.2f}")
            info_parts.append(f"Processing Time: {processing_time:.2f}s")
            
            # Combine reason with additional information
            full_reason = f"{reason}\n({' | '.join(info_parts)})"
            self.reason_value.setText(full_reason)
            
            # Response
            response_text = data.get("response", "")
            if response_text:
                self.response_field.setText(f"{response_text}\n\n[Processed in {processing_time:.2f} seconds]")
            else:
                self.response_field.setText("No response generated.")
                
        finally:
            self.cleanup_request()  # Ensure cleanup happens

    def handle_error(self, error_msg):
        """Enhanced error handling"""
        try:
            self.status_value.setText("Error")
            self.status_value.setStyleSheet("color: red; font-weight: bold;")
            self.reason_value.setText(error_msg)
            self.response_field.setText("Failed to check input")
        finally:
            self.cleanup_request()  # Ensure cleanup happens

    def handle_progress(self, message):
        """Handle progress updates from worker"""
        self.status_message.setText(message)

    def update_progress(self, message):
        self.progress.setFormat(message)

    def cleanup_request(self):
        """Enhanced cleanup with proper thread handling"""
        if hasattr(self, 'worker') and self.worker:
            try:
                self.worker.stop()  # Safely stop the thread
                self.worker.wait()  # Wait for thread to finish
                self.worker.deleteLater()  # Schedule thread deletion
                self.worker = None
            except Exception as e:
                print(f"Cleanup error: {e}")

        # Re-enable UI elements
        self.input_field.setEnabled(True)
        self.submit_btn.setEnabled(True)
        self.progress.setVisible(False)
        self.status_message.setText("")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FirewallGUI()
    window.show()
    sys.exit(app.exec())