# Deconvolute SDK - Detector Usage Guide

This guide is for user and provides standard patterns and examples for using the Security Detectors in your AI pipeline.

## Installation & Extras

The core of Deconvolute is lightweight. Some detectors require additional dependencies (Extras) to function.

| Detector | Required Install | Description |
| :--- | :--- | :--- |
| `CanaryDetector` | `pip install deconvolute` | Included in base. No extra dependencies. |
| `LanguageDetector` | `pip install deconvolute[language]` | Requires heavy NLP libraries (Lingua). |

---

## Core Concepts

All detectors in Deconvolute follow a standard interface. They provide both synchronous and asynchronous methods to fit any pipeline architecture (e.g. standard Flask/Django apps or Async FastAPI/LangChain agents).

### 1. The `BaseDetector` Interface

Every detector implements these core methods:

* `check(content: str, **kwargs) -> DetectionResult`: Analyzes text for threats.
* `a_check(content: str, **kwargs) -> DetectionResult`: Async version of check.

### 2. Result Models

Detectors return structured objects, not just booleans. This allows for rich telemetry and debugging.

**`DetectionResult` (Base Class)**
The common ancestor for all results.
* `threat_detected` (bool): `True` if a threat was found.
* `component` (str): Name of the detector (e.g. `CanaryDetector`).
* `timestamp` (datetime): UTC time of the check.
* `metadata` (dict): Arbitrary context (e.g. latency, scores).

**`CanaryResult`**
* `token_found (str | None)`: The specific token string found in the output (if the check passed).

**`LanguageResult`**
* `detected_language (str)`: The ISO code of the language detected (e.g. `en`, `fr`).
* `confidence (float)`: The statistical confidence of the detection (0.0 to 1.0).

---

## Detectors

Available Detectors:
- `CanaryDetector`
- `LanguageDetector`


### CanaryDetector

**Requirement:** Base Install

Detects if the LLM followed your System Prompt instructions (Instructional Adherence). It works by injecting a random token and verifying its presence in the output.

#### Example

```python
from deconvolute.detectors import CanaryDetector, CanaryResult, ThreatDetectedError

# Initialize
# You can customize the token length if needed.
canary = CanaryDetector(token_length=16)

# Inject (Pre-LLM)
# This modifies your system prompt to include the mandatory token instruction.
# Returns the new prompt string and the secret token.
system_prompt = "You are a helpful assistant."
secure_system_prompt, token = canary.inject(system_prompt)

# Run LLM (Pseudo-code)
# Response should look like: "Sure, here is the info... [dcv-8f7a...]"
llm_response: str = llm.invoke(
    messages=[
        {"role": "system", "content": secure_system_prompt},
        {"role": "user", "content": user_message_with_context}
    ]
)

# Check (Post-LLM)
# Verify if the token is present.
result: CanaryResult = canary.check(llm_response, token)

if result.threat_detected:
    print(f"Alert! Jailbreak detected via {result.component}")
    # Handle the threat (block response, log incident, etc.)
    raise ThreatDetectedError("Response blocked: Instructional adherence failed.")
else:
    print("Response is safe.")

# Clean (Optional)
# Remove the token from the final string before showing it to the user.
final_output: str = canary.clean(llm_response, token)
```

#### Asynchronous Usage

```python
import asyncio
from deconvolute.detectors import CanaryDetector

async def run_pipeline():
    canary = CanaryDetector()
    secure_prompt, token = canary.inject("System Prompt...")
    
    # ... await llm.ainvoke(...) ...
    llm_response = "..."

    # Async Check (Non-blocking)
    result = await canary.a_check(llm_response, token=token)
    
    if not result.threat_detected:
        final_output = await canary.a_clean(llm_response, token)

asyncio.run(run_pipeline())
```

**Why it works:** This implements a synthetic integrity check to enforce Instruction Hierarchy (Wallace et al. 2024). In a successful RAG jailbreak, the model suffers from Context Overwrite where untrusted retrieved data (e.g. a malicious PDF) overrides the priority of the system prompt. By making the canary token a mandatory instruction, a quantifiable test of executive control is created because if the token is missing, the model has prioritized the untrusted context over your system instructions.

### LanguageDetector

**Requirement:** `pip install deconvolute[language]`

Ensures the LLM output matches expected languages. This defends against *Payload Splitting* attacks where an attacker forces the model to output malicious content in a different language (e.g. Latin, Base64, or unexpected German) to bypass keyword filters.

You can configure the detector with a static list of allowed languages.

```python
from deconvolute.detectors import LanguageDetector, LanguageResult, ThreatDetectedError

# Allow English and Spanish.
# 'strategy' can be 'strict' (default) or 'lenient' (for short text).
detector = LanguageDetector(allowed_languages=["en", "es"])
```

#### Mode A: Static Policy Check

Checks if the output belongs to the allowed list, regardless of input.

```python
response_text = "Bonjour le monde" # French (Not in allowed list)

# 1. Check
result = detector.check(response_text)

if result.threat_detected:
    # metadata contains details: {'detected_language': 'fr', 'allowed': ['en', 'es']}
    print(f"Language Violation: {result.metadata['detected_language']}")
    raise ThreatDetectedError("Response blocked: Instructional adherence failed.")
```

#### Mode B: Input-Output Correspondence

Checks if the Output language matches the Input language. This is useful for multi-lingual bots where you don't know the user's language in advance, but you want to ensure the bot doesn't switch languages unexpectedly.

```python
user_input = "Tell me a joke." # Detected as English
model_output = "Aquí hay una broma..." # Spanish

# Pass 'reference_text' (the user input) to enforce matching.
# Even if Spanish is in 'allowed_languages', you might want to enforce 
# that an English question gets an English answer.
result = detector.check(
    content=model_output, 
    reference_text=user_input
)

if result.threat_detected:
    print("Language Mismatch detected!")
```

#### Asynchronous Usage

```python
async def check_lang():
    detector = LanguageDetector(allowed_languages=["en"])
    
    # Non-blocking language detection (runs in thread pool)
    result = await detector.a_check(llm_output)
    
    if result.threat_detected:
        raise SecurityError("Wrong language detected")
```

