from langchain_community.document_loaders import DirectoryLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_ollama import OllamaEmbeddings
from langchain_chroma import Chroma
import sys

# Define the directory to save the vector store
PERSIST_DIRECTORY = "./chroma_db"
# A directory to load documents from
SOURCE_DIRECTORY = "./knowledge_base"

print("Loading documents from {SOURCE_DIRECTORY}...")
try:
    # This loader will automatically load all supported file types from the directory
    loader = DirectoryLoader(SOURCE_DIRECTORY, glob="**/*",show_progress=True)
    docs = loader.load()
except Exception as e:
    print(f"Error loading PDF: {e}")
    sys.exit(1)

print(f"Loaded {len(docs)} documents.")

print("Splitting document into text chunks...")
text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
splits = text_splitter.split_documents(docs)
print(f"Split into {len(splits)} chunks.")

print("Creating embeddings and building the persistent vector store...")
embeddings = OllamaEmbeddings(model="nomic-embed-text")

# Create the vector store and persist it to disk
vectorstore = Chroma.from_documents(
    documents=splits, 
    embedding=embeddings,
    persist_directory=PERSIST_DIRECTORY
)

print(f"Successfully created and saved the vector store in '{PERSIST_DIRECTORY}'")
