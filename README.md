# AI Security Threat Intelligence RAG System

An AI system that answers cybersecurity questions grounded in real CVE and MITRE ATT&CK data, with measured hallucination reduction.

🚀 [Live Demo](https://ai-security-rag.streamlit.app)

**The Problem**: Ask any LLM "What's the CVSS score for CVE-2023-20198?" and it'll confidently say 7.5. The real score is 10.0 — the highest possible. Security teams making decisions based on wrong severity scores patch the wrong things first. That's not a minor error.

**The Solution**: A 6-stage RAG pipeline that retrieves real vulnerability data before the model says anything:

1️⃣ Fetch → Pull live CVEs from NVD API + 50 MITRE ATT&CK techniques  
2️⃣ Chunk → Split into semantic chunks with LangChain  
3️⃣ Embed → Convert to vectors with OpenAI embeddings  
4️⃣ Store → Index in ChromaDB for similarity search  
5️⃣ Retrieve → Find the 3 most relevant chunks per question  
6️⃣ Answer → GPT-3.5 responds using only retrieved context  

**Current Progress**: ✅ CVE data pipeline ✅ Vector database (ChromaDB) ✅ RAG chatbot UI ✅ Hallucination evaluation ✅ Live deployment 🔜 RAGAS evaluation framework 🔜 Multi-agent expansion

**Tech Stack**: Python | LangChain | ChromaDB | OpenAI | Streamlit | NVD API | MITRE ATT&CK

**Why This Matters**: I'm building toward AI Engineer roles in security, and the thing that kept bothering me was how confidently LLMs get vulnerability details wrong. CVSS scores, affected versions, patch names — models hallucinate all of it. This project is my answer to that: can you actually measure how much RAG reduces those errors? Turns out yes, and the number is 60%.

**Output: Hallucination Evaluation Results**
Without RAG — Hallucination rate: 100%
With RAG    — Hallucination rate: 40%
RAG reduces hallucinations by: 60%
Tested on: CVE-2023-20198 (Cisco IOS XE), CVE-2023-22515 (Confluence),
CVE-2024-3400 (PAN-OS), CVE-2023-44487 (HTTP/2), CVE-2023-23397 (Outlook)

GPT alone gave wrong CVSS scores every single time. With RAG, it pulled exact scores directly from the knowledge base for 3 out of 5.

Run it yourself:
```bash
git clone https://github.com/jahnavi-reddy03/ai-security-rag
cd ai-security-rag
pip install -r requirements.txt
echo "OPENAI_API_KEY=your-key" > .env
python create_cve_data.py
python ingest.py
streamlit run app.py
```
