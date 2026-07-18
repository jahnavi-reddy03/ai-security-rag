import os
import streamlit as st
from langchain_community.vectorstores import Chroma
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from langchain_community.document_loaders import TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from dotenv import load_dotenv

load_dotenv()

st.set_page_config(page_title="Security Threat Intelligence", page_icon="🔒")
st.title("🔒 Security Threat Intelligence Assistant")
st.write("Ask me about CVEs, MITRE ATT&CK techniques, and security threats.")

def build_database():
    """Build ChromaDB from real_security_data.txt if it doesn't exist"""
    loader = TextLoader("data/real_security_data.txt", encoding="utf-8")
    documents = loader.load()
    splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
    chunks = splitter.split_documents(documents)
    embeddings = OpenAIEmbeddings()
    vectorstore = Chroma.from_documents(
        documents=chunks,
        embedding=embeddings,
        persist_directory="./chroma_db"
    )
    return vectorstore

@st.cache_resource
def load_resources():
    embeddings = OpenAIEmbeddings()
    if not os.path.exists("./chroma_db") or not os.listdir("./chroma_db"):
        st.info("Building security database for the first time... this takes ~30 seconds.")
        vectorstore = build_database()
    else:
        vectorstore = Chroma(
            persist_directory="./chroma_db",
            embedding_function=embeddings
        )
    llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0)
    return vectorstore, llm

vectorstore, llm = load_resources()

if "messages" not in st.session_state:
    st.session_state.messages = []

for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.write(message["content"])

if prompt := st.chat_input("Ask about security threats..."):
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.write(prompt)

    with st.chat_message("assistant"):
        with st.spinner("Searching threat database..."):
            docs = vectorstore.similarity_search(prompt, k=3)
            context = "\n\n".join([doc.page_content for doc in docs])
            full_prompt = f"""You are a cybersecurity expert. Use the following security knowledge to answer the question.

Context:
{context}

Question: {prompt}

Answer:"""
            response = llm.invoke(full_prompt)
            answer = response.content
            st.write(answer)
            st.session_state.messages.append({"role": "assistant", "content": answer})