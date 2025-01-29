import re
from typing import Dict, Optional
from fastapi import FastAPI
from pydantic import BaseModel
from langchain.llms import Ollama  # Use LangChain's Ollama integration
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
from functools import lru_cache

# ----------------------------
# Configuration
# ----------------------------
BLOCKLIST = {"hack", "exploit", "malicious", "inject", "root"}
SQL_INJECTION_REGEX = re.compile(r"\b(DROP\s+TABLE|UNION\s+SELECT|INSERT\s+INTO|DELETE\s+FROM)\b", re.IGNORECASE)
CACHE_SIZE = 1000  # Maximum cache size for recent queries
CONFIDENCE_THRESHOLD = 0.8  # Minimum confidence for blocking inputs

# ----------------------------
# FastAPI Setup
# ----------------------------
app = FastAPI(title="AI Input Firewall with Responses", version="2.1")

class UserRequest(BaseModel):
    text: str
    user_id: Optional[str] = None

class FirewallResponse(BaseModel):
    status: str  # "allowed" or "blocked"
    reason: Optional[str] = None
    score: Optional[float] = None
    response: Optional[str] = None  # Response if the input is safe

# ----------------------------
# LangChain Setup
# ----------------------------
# Initialize Ollama via LangChain
llm = Ollama(model="llama2")

# Define a prompt template for classification
classification_prompt = PromptTemplate(
    input_variables=["text"],
    template=(
        "Classify the following input as 'SAFE' or 'UNSAFE' based on whether it contains malicious, harmful, "
        "or suspicious content. Respond with only 'SAFE' or 'UNSAFE'.\n\n"
        "Input: {text}\n\nClassification:"
    )
)

# Define a prompt template for generating responses
response_prompt = PromptTemplate(
    input_variables=["text"],
    template="Respond to the following input:\n\n{text}\n\nResponse:"
)

# Create LangChain chains
classification_chain = LLMChain(llm=llm, prompt=classification_prompt)
response_chain = LLMChain(llm=llm, prompt=response_prompt)

# ----------------------------
# Core Firewall Logic
# ----------------------------
@lru_cache(maxsize=CACHE_SIZE)
def classify_input_with_ollama(text: str) -> Dict:
    """Classify input using LangChain and Ollama."""
    try:
        result = classification_chain.run(text=text)
        classification = result.strip().upper()
        return {"label": classification, "score": 1.0 if classification == "UNSAFE" else 0.0}
    except Exception as e:
        print(f"[ERROR] LangChain/Ollama classification failed: {e}")
        return {"label": "UNSAFE", "score": 1.0}  # Default to UNSAFE if API fails

def rule_based_checks(text: str) -> Optional[str]:
    """Apply blocklist and regex rules. Returns the reason if blocked."""
    text_lower = text.lower()

    if any(word in text_lower for word in BLOCKLIST):
        return "Blocked due to prohibited keyword."

    if SQL_INJECTION_REGEX.search(text):
        return "SQL injection attempt detected."

    return None

def generate_ollama_response(text: str) -> str:
    """Generate a response for safe input using LangChain and Ollama."""
    try:
        response = response_chain.run(text=text)
        return response.strip() or "No response generated."
    except Exception as e:
        print(f"[ERROR] Failed to generate response from LangChain/Ollama: {e}")
        return "Error generating response."

def is_input_safe(text: str) -> Dict:
    """Aggregate safety checks (rule-based and AI-based)."""
    # Perform rule-based checks
    rule_based_reason = rule_based_checks(text)
    if rule_based_reason:
        return {
            "status": "blocked",
            "reason": rule_based_reason,
            "score": None,
            "response": "This prompt is unsafe, can't answer."
        }

    # Perform AI-based classification
    ai_result = classify_input_with_ollama(text)
    if ai_result["label"] == "UNSAFE" and ai_result["score"] > CONFIDENCE_THRESHOLD:
        return {
            "status": "blocked",
            "reason": "Ollama classified as unsafe",
            "score": ai_result["score"],
            "response": "This prompt is unsafe, can't answer."
        }

    # Generate response for safe input
    response = generate_ollama_response(text)
    return {
        "status": "allowed",
        "score": ai_result["score"],
        "response": response
    }

# ----------------------------
# API Endpoints
# ----------------------------
@app.post("/check-input", response_model=FirewallResponse)
async def check_input(request: UserRequest):
    """Check the safety of user-provided input and generate a response if safe."""
    result = is_input_safe(request.text)
    print(f"[LOG] User: {request.user_id or 'Anonymous'} | Text: {request.text[:50]}... | Status: {result['status']}")
    return FirewallResponse(**result)

# ----------------------------
# Run the Server
# ----------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)