from openai import OpenAI
from langchain_community.vectorstores import Chroma
from langchain_openai import OpenAIEmbeddings
from dotenv import load_dotenv
import json
import re

load_dotenv()
client = OpenAI()

def parse_cves_with_scores():
    """Extract CVE IDs and their CVSS scores from our NVD data"""
    cves = []
    with open("data/real_security_data.txt", "r", encoding="utf-8") as f:
        content = f.read()
    
    blocks = content.split("CVE ID: ")
    for block in blocks[1:]:
        lines = block.strip().split("\n")
        cve_id = lines[0].strip()
        cvss_score = None
        description = ""
        for line in lines:
            if "CVSS" in line and any(c.isdigit() for c in line):
                nums = re.findall(r'\d+\.\d+', line)
                if nums:
                    cvss_score = nums[0]
            if line.startswith("Description:"):
                description = line.replace("Description:", "").strip()[:150]
        if cve_id and cvss_score:
            cves.append({"id": cve_id, "score": cvss_score, "description": description})
        if len(cves) >= 5:
            break
    return cves

def answer_without_rag(question):
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are a cybersecurity expert. Always provide specific exact answers with real numbers and version details. Never say you don't know — give your best specific answer."},
            {"role": "user", "content": question}
        ],
        temperature=0.7
    )
    return response.choices[0].message.content

def answer_with_rag(question, vectorstore):
    docs = vectorstore.similarity_search(question, k=4)
    context = "\n\n".join([doc.page_content for doc in docs])
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "Answer using ONLY the provided context. Extract exact numbers and facts directly from it."},
            {"role": "user", "content": f"Context:\n{context}\n\nQuestion: {question}"}
        ],
        temperature=0
    )
    return response.choices[0].message.content, context

def check_score_accuracy(answer, correct_score):
    """Simple check: does the answer contain the correct CVSS score?"""
    scores_mentioned = re.findall(r'\d+\.\d+', answer)
    if correct_score in scores_mentioned:
        return "ACCURATE"
    if not scores_mentioned:
        return "HALLUCINATION"  # gave no score
    return "HALLUCINATION"  # gave wrong score

def run_evaluation():
    print("Parsing CVE data with CVSS scores...")
    cves = parse_cves_with_scores()
    
    if not cves:
        print("No CVEs with CVSS scores found. Check real_security_data.txt format.")
        return
    
    print(f"Found {len(cves)} CVEs with CVSS scores for testing")
    for c in cves:
        print(f"  {c['id']} → CVSS {c['score']}")
    
    print("\nLoading vector database...")
    embeddings = OpenAIEmbeddings()
    vectorstore = Chroma(persist_directory="./chroma_db", embedding_function=embeddings)
    
    without_rag_hallucinations = 0
    with_rag_hallucinations = 0
    results = []
    
    print("\n" + "="*60)
    print("HALLUCINATION EVALUATION: CVSS Score Accuracy Test")
    print("="*60)
    
    for i, cve in enumerate(cves, 1):
        question = f"What is the CVSS base score for {cve['id']}?"
        correct_score = cve['score']
        
        print(f"\nQuestion {i}: {question}")
        print(f"Ground Truth CVSS Score: {correct_score}")
        print("-" * 40)
        
        answer_no_rag = answer_without_rag(question)
        rating_no_rag = check_score_accuracy(answer_no_rag, correct_score)
        scores_found = re.findall(r'\d+\.\d+', answer_no_rag)
        print(f"WITHOUT RAG: {rating_no_rag}  (said: {scores_found if scores_found else 'no score'})")
        
        answer_rag, context = answer_with_rag(question, vectorstore)
        rating_rag = check_score_accuracy(answer_rag, correct_score)
        scores_found_rag = re.findall(r'\d+\.\d+', answer_rag)
        print(f"WITH RAG:    {rating_rag}  (said: {scores_found_rag if scores_found_rag else 'no score'})")
        
        if "HALLUCINATION" in rating_no_rag:
            without_rag_hallucinations += 1
        if "HALLUCINATION" in rating_rag:
            with_rag_hallucinations += 1
        
        results.append({
            "cve_id": cve['id'],
            "correct_cvss": correct_score,
            "without_rag_verdict": rating_no_rag,
            "with_rag_verdict": rating_rag
        })
    
    total = len(cves)
    without_rate = (without_rag_hallucinations / total) * 100
    with_rate = (with_rag_hallucinations / total) * 100
    improvement = without_rate - with_rate
    
    print("\n" + "="*60)
    print("FINAL RESULTS")
    print("="*60)
    print(f"Without RAG — Hallucination rate: {without_rate:.0f}%")
    print(f"With RAG    — Hallucination rate: {with_rate:.0f}%")
    print(f"RAG reduces hallucinations by:   {improvement:.0f}%")
    
    with open("hallucination_results.json", "w") as f:
        json.dump({
            "summary": {
                "without_rag_hallucination_rate": f"{without_rate:.0f}%",
                "with_rag_hallucination_rate": f"{with_rate:.0f}%",
                "hallucination_reduction": f"{improvement:.0f}%",
                "total_questions": total
            },
            "methodology": "CVSS score accuracy test — exact score must appear in answer",
            "results": results
        }, f, indent=2)
    print("\nResults saved to hallucination_results.json")

if __name__ == "__main__":
    run_evaluation()