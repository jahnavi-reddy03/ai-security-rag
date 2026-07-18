from langchain_community.document_loaders import TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores import Chroma
from dotenv import load_dotenv
import os

load_dotenv()

# Load the security document
print("Loading documents...")
loader = TextLoader("data/real_security_data.txt", encoding="utf-8")
documents = loader.load()

# Split into chunks
print("Splitting into chunks...")
text_splitter = RecursiveCharacterTextSplitter(
    chunk_size=500,
    chunk_overlap=50
)
chunks = text_splitter.split_documents(documents)
print(f"Created {len(chunks)} chunks")

# Create embeddings and store in ChromaDB
print("Creating embeddings and storing in ChromaDB...")
embeddings = OpenAIEmbeddings()
vectorstore = Chroma.from_documents(
    documents=chunks,
    embedding=embeddings,
    persist_directory="./chroma_db"
)

print("Done! Vector database created successfully.")
print(f"Total chunks stored: {len(chunks)}")
