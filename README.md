# 🛡️ AppShield  
### An AI-Driven Privacy and Security Inspection Framework for Android Applications

AppShield is a research-oriented framework designed to analyze Android applications for privacy and security risks by combining static APK analysis, third-party tracker detection, and AI/NLP-based privacy policy interpretation.

---

## 📌 Project Overview

With the rapid growth of mobile applications, users often remain unaware of how their personal data is accessed, shared, or transmitted. AppShield aims to bridge this gap by providing an automated, explainable, and extensible privacy inspection framework for Android apps.

---

## 🎯 Objectives

- To analyze Android application permissions and identify sensitive data access.
- To detect embedded third-party trackers and external communication endpoints.
- To interpret privacy policies using AI/NLP techniques and correlate them with app behavior.
- To generate an explainable privacy risk score for end users and researchers.

---

## 🧠 Methodology

1. **APK Upload & Extraction**  
   Supports `.apk`, `.apkm`, `.xapk`, and `.zip` formats.

2. **Static APK Analysis**  
   - Extracts package metadata  
   - Identifies requested permissions  
   - Extracts embedded domains and strings  

3. **Third-Party Tracker Analysis**  
   - Matches domains against known tracker databases  
   - Categorizes trackers (ads, analytics, social, CDN, backend)

4. **Privacy Policy Retrieval & NLP Analysis**  
   - Automatically fetches privacy policies  
   - Applies transformer-based zero-shot NLP (BART-MNLI) with rule-based fallback  

5. **AI-Based Risk Scoring**  
   - Correlates permissions, trackers, and policy claims  
   - Produces an explainable privacy risk score (LOW / MEDIUM / HIGH)

6. **Dashboard Visualization**  
   - Interactive metrics, tabs, and summaries for analysis

---

## 🧩 NLP Model Used

- **Primary Model:** Transformer-based Zero-Shot Classification (facebook/bart-large-mnli)  
- **Fallback:** Rule-based and lexicon-driven NLP analysis  
- **Reason:** No labeled data required, high explainability, lightweight deployment

---

## 🛠️ Tech Stack

- **Language:** Python  
- **Frontend:** Streamlit  
- **APK Analysis:** apkutils / androguard  
- **NLP:** Hugging Face Transformers, Rule-based NLP  
- **Web Parsing:** BeautifulSoup  
- **Visualization:** Streamlit Dashboard Components  

---

## 🚀 How to Run

```bash
# Activate virtual environment
source medsecure-venv/bin/activate

# Run the application
streamlit run app.py
