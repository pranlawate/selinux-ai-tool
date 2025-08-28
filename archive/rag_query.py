import sys
from langchain_community.document_loaders import PyPDFLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_ollama import OllamaEmbeddings
from langchain_community.vectorstores import Chroma
from langchain_ollama import OllamaLLM  # <-- Renamed import
from langchain.prompts import ChatPromptTemplate
from langchain.schema.runnable import RunnablePassthrough
from langchain.schema.output_parser import StrOutputParser

# --- 1. Load the Document ---
print("Loading PDF document...")
try:
    loader = PyPDFLoader("SELinux_Notebook.pdf")
    docs = loader.load()
except Exception as e:
    print(f"Error loading PDF: {e}")
    sys.exit(1)

# --- 2. Chunk the Text ---
print("Splitting document into text chunks...")
text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
splits = text_splitter.split_documents(docs)

# --- 3. Create Embeddings and Vector Store ---
print("Creating embeddings and building the vector store...")
embeddings = OllamaEmbeddings(model="nomic-embed-text")
vectorstore = Chroma.from_documents(documents=splits, embedding=embeddings)

# --- 4. Create the RAG Chain ---
print("Creating the RAG chain...")

retriever = vectorstore.as_retriever()

template = """
You are a helpful assistant. Use the following context to answer the question.
If you don't know the answer, simply state that you don't know.

Context: {context}

Question: {question}

Answer:
"""
prompt = ChatPromptTemplate.from_template(template)

# Use the new class name here as well
llm = OllamaLLM(model="llama3")  # <-- Renamed class

rag_chain = (
    {"context": retriever, "question": RunnablePassthrough()}
    | prompt
    | llm
    | StrOutputParser()
)

# --- 5. Ask a Question ---
print("RAG pipeline is ready. Asking a question...")

question = "What is the main purpose of this document?"
answer = rag_chain.invoke(question)

print("\n" + "="*50)
print(f"Question: {question}")
print(f"Answer: {answer}")
print("="*50)
