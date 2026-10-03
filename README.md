```markdown
#  SentinelAgent: Autonomous Security & Compliance Gateway for LLMs

**SentinelAgent** is an autonomous AI Security Gateway and Compliance Firewall designed to sit between users and Large Language Model (LLM) endpoints. It intercepts prompts in real time to evaluate threat levels, prevent Prompt Injections and Jailbreaks, dynamically anonymize Personally Identifiable Information (PII), and enforce safety guardrails before returning sanitized model outputs.

Built using the **Pak Angels AI Application Development Methodology** (Cohort 11), this project demonstrates how to turn complex security requirements into a fully deployed, production-grade AI agent using natural language development ("Vibe Coding") and a 3-platform open-source stack[cite: 5, 6].

---

##  Table of Contents
- [Key Features](#-key-features)
- [Architecture & 5-Step Agentic Loop](#-architecture--5-step-agentic-loop)
- [Lectures & Course Concepts Applied](#-lectures--course-concepts-applied)
- [Technology Stack](#-technology-stack)
- [Project Structure](#-project-structure)
- [Installation & Local Setup](#-installation--local-setup)
- [Deployment Guide](#-deployment-guide)
- [Example Input/Output Schema](#-example-inputoutput-schema)
- [License & Acknowledgments](#-license--acknowledgments)

---

##  Key Features

* **Real-Time Threat Scoring (0–100):** Intercepts raw prompts and checks for prompt injections, system prompt overrides, role escalation, and jailbreaks[cite: 6].
* **Dynamic PII Masking & Anonymization:** Scans inputs using Regex and NLP pattern matching to auto-redact sensitive tokens (Names, Credit Cards, Government IDs, API Keys, Passports)[cite: 6].
* **Automated Decision Engine:**
  * **Threat Score $\ge$ 75:** Blocks the request immediately, logs a security alert, and returns a sanitized error payload[cite: 6].
  * **Threat Score < 75:** Redacts sensitive data, injects system guardrails, and forwards the safe prompt to the model[cite: 6].
* **Dual Output Sanitization:** Inspects downstream LLM responses to ensure proprietary context, internal keys, or leaked PII never exit the firewall[cite: 6].
* **Structured JSON Audit Logging:** Generates strict, standardized JSON payloads for security tracking and compliance review[cite: 6].
* **Interactive Streamlit Dashboard:** Provides metric badges, risk threshold sliders, side-by-side prompt comparisons, and raw log viewers[cite: 5, 6].

---

##  Architecture & 5-Step Agentic Loop

SentinelAgent operates using the 5-step autonomous agent control loop[cite: 6]:

1. **Understand (Input Interception):** Intercepts the raw user prompt before it reaches any LLM endpoint[cite: 6].
2. **Plan (Threat Scoring):** Evaluates risk vectors and dynamically computes a threat score between 0 and 100[cite: 6].
3. **Use Tools (PII Anonymization):** Triggers automated pattern-matching tools to replace sensitive data with structured placeholders (e.g., `[PERSON_1]`, `[API_KEY_HIDDEN]`)[cite: 6].
4. **Take Action (Decision Engine):** Evaluates threat scores against pre-configured policy thresholds to ALLOW, REDACT, or BLOCK the request[cite: 6].
5. **Check & Adjust (Output Verification):** Inspects downstream model outputs to prevent hallucinated leakages or context exfiltration before delivering the response[cite: 6].

---

##  Lectures & Course Concepts Applied

This project applies core concepts taught throughout the **Pak Angels GenAI & Agentic AI Training Program (Cohort 11)**[cite: 5, 6]:

* **RCTC Prompt Engineering Framework (Week 1):** Internal safety checks are structured explicitly using **Role**, **Context**, **Task**, and **Constraints** to keep evaluation outputs deterministic[cite: 1, 3, 5].
* **Vibe Coding Methodology (Week 2):** Designed and developed through iterative natural language prompting using ChatGPT Free, bypassing traditional manual coding bottlenecks[cite: 5, 6].
* **Pak Angels 3-Platform Stack (Week 2 & 3):** Developed using ChatGPT Free, hosted on GitHub Online, and deployed on Streamlit Community Cloud[cite: 5, 6].
* **RAG & Policy Grounding (Weeks 3 & 4):** Evaluates user prompts against uploaded enterprise compliance rules and corporate safety policies[cite: 3, 5, 6].
* **Agentic AI & Tool Integration (Week 5):** Replaces static chatbot interactions with an autonomous decision-making engine equipped with PII maskers and threshold triggers[cite: 6].
* **Risk & Guardrail Management (Product Management Lectures):** Implements output controls, rate-limiting considerations, non-deterministic failure handling, and user transparency dashboards as outlined in PRD best practices[cite: 4, 6].

---

##  Technology Stack

* **Development Engine:** ChatGPT Free (Vibe Coding)[cite: 5, 6]
* **Frontend / UI:** Streamlit[cite: 5, 6]
* **Core Language:** Python 3.10+[cite: 5, 6]
* **Version Control:** GitHub Online[cite: 5, 6]
* **Deployment Cloud:** Streamlit Community Cloud[cite: 5, 6]
* **Libraries Used:** `streamlit`, `re` (Regex), `json`[cite: 5, 6]

---

##  Project Structure

```text
├── app.py              # Main Streamlit application with Gateway logic
├── requirements.txt    # Python dependencies for deployment
├── .gitignore          # Files ignored by version control
└── README.md           # Project documentation and architecture guide

```

---

##  Installation & Local Setup

To run SentinelAgent locally on your computer:

### **1. Clone the Repository**

```bash
git clone [https://github.com/YOUR_USERNAME/SentinelAgent.git](https://github.com/YOUR_USERNAME/SentinelAgent.git)
cd SentinelAgent

```

### **2. Create a Virtual Environment (Optional but Recommended)**

```bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate

```

### **3. Install Dependencies**

```bash
pip install -r requirements.txt

```

### **4. Launch the Streamlit App**

```bash
streamlit run app.py

```

### **5. Access the App**

Open your browser at `http://localhost:8501`.

---

##  Deployment Guide

SentinelAgent is deployed using the Pak Angels zero-cost deployment pipeline:

1. **GitHub Upload:** Push `app.py`, `requirements.txt`, and `README.md` to your public GitHub repository.


2. **Connect Streamlit Cloud:**
* Log into [share.streamlit.io](https://share.streamlit.io/).


* Click **New app** and select your GitHub repository and branch (`main`).


* Set Main file path to `app.py`.




3. **Deploy:** Click **Deploy!** Your app will be live with a public URL in under 2 minutes.



---

##  Example Input/Output Schema

When an incoming prompt is evaluated, SentinelAgent generates a structured compliance log:

### **Sample Blocked Payload (Threat Score $\ge$ 75)**

```json
{
  "action": "BLOCK",
  "threat_score": 90,
  "detected_threats": [
    "Jailbreak Attempt",
    "System Prompt Override"
  ],
  "sanitized_prompt": "REDACTED_DUE_TO_SECURITY_POLICY",
  "masked_entities": [],
  "reasoning": "Prompt contained explicit instructions to bypass system guardrails and extract hidden instructions."
}

```

### **Sample Redacted Payload (Threat Score < 75)**

```json
{
  "action": "REDACT",
  "threat_score": 15,
  "detected_threats": [],
  "sanitized_prompt": "Please transfer $500 to [PERSON_1] using card [CREDIT_CARD_HIDDEN].",
  "masked_entities": [
    "Person Name",
    "Credit Card Number"
  ],
  "reasoning": "Prompt is safe. Sensitive PII entities were successfully identified and anonymized."
}

```

---

##  License & Acknowledgments

* **Training Program:** Pak Angels Generative & Agentic AI Training (Cohort 11 - 2026)


* **Partners:** PEC, NCEAC-HEC, iCodeGuru, and Aspire Pakistan


* **Methodology Founder:** Mohammad Anwar Khan (Pak Angels, Silicon Valley, USA)


* **License:** MIT License

##  Team Members
1.Maryam Khan(Leader)
2.Muhammad Zain Khan
3.Muhammad Zaid Khan
4.Muhammad ShahZeb Khan
```

```
