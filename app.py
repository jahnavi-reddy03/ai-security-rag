import streamlit as st
from langchain_openai import ChatOpenAI
from langchain.schema import HumanMessage, SystemMessage
from dotenv import load_dotenv

load_dotenv()

st.set_page_config(page_title="Security Threat Intelligence", page_icon="🔒")
st.title("🔒 Security Threat Intelligence Assistant")
st.write("Ask me about CVEs, MITRE ATT&CK techniques, and security threats.")

@st.cache_resource
def load_resources():
    with open("data/real_security_data.txt", "r", encoding="utf-8") as f:
        security_data = f.read()
    llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0)
    return security_data, llm

security_data, llm = load_resources()

if "messages" not in st.session_state:
    st.session_state.messages = []

for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

if prompt := st.chat_input("Ask about security threats..."):
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        response = llm.invoke([
            SystemMessage(content=f"You are a cybersecurity expert. Use ONLY this security database to answer questions accurately:\n\n{security_data}"),
            HumanMessage(content=prompt)
        ])
        st.markdown(response.content)

    st.session_state.messages.append({"role": "assistant", "content": response.content})