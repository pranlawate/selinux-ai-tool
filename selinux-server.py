import re
import traceback 
from flask import Flask, request, jsonify
from langchain_ollama import OllamaLLM,OllamaEmbeddings
from langchain_chroma import Chroma
from langchain.prompts import ChatPromptTemplate
from langchain_community.document_loaders import PyPDFLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.schema.document import Document

# --- App Configuration ---
app = Flask(__name__)

print("Loading static knowledge from PDF...")
# Load the base knowledge from the PDF only once at startup
try:
    pdf_loader = PyPDFLoader("./knowledge_base/document.pdf")
    static_docs = pdf_loader.load()
except Exception as e:
    print(f"Warning: Could not load static PDF knowledge base. {e}")
    static_docs = []

# --- Initialize LLM and Embeddings once ---
llm = OllamaLLM(model="llama3")
embeddings = OllamaEmbeddings(model="nomic-embed-text")

# Define the RAG prompt template
template = """
You are an expert SELinux system administrator. Use the provided context from the SELinux documentation, which includes file context rules and system booleans, to help analyze the user's AVC denial log.
Your final response MUST BE ONLY a single, valid JSON object with two keys: "explanation" and "commands".

Your troubleshooting priority should be:
1. First, check if a simple file context change (`restorecon`, `semanage fcontext`) can fix the issue.
2. If not, check if changing an SELinux boolean (`setsebool`) would be the correct solution.
3. Only suggest creating a custom policy module (`audit2allow`) as a last resort if no other solution fits.

The "explanation" should clearly explain the denial and justify your suggested solution.
The "commands" should be an array of shell commands to fix the issue.

Context from documentation:
{context}

User's AVC denial log:
{question}

JSON Response:
"""
prompt = ChatPromptTemplate.from_template(template)

# Create the RAG chain
# Note: The chain logic is now simplified inside the endpoint
print("SELinux AI backend is ready.")


# --- API Endpoint ---
@app.route('/analyze-avc', methods=['POST'])
def analyze_avc():
    """Receives an AVC log, gets a RAG-informed analysis, and returns it."""
    data = request.json
    avc_log = data.get('log')
    booleans_text = data.get('booleans')

    if not avc_log:
        return jsonify({"error": "No log provided"}), 400

    try:
        # Combine static docs with the live booleans provided by the client
        live_docs = [Document(page_content=booleans_text)] if booleans_text else []
        all_docs = static_docs + live_docs

        # Create a temporary, in-memory vector store for this specific request
        text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
        splits = text_splitter.split_documents(all_docs)

        vectorstore = Chroma.from_documents(documents=splits, embedding=embeddings)
        retriever = vectorstore.as_retriever()

        # RAG invocation
        retrieved_docs = retriever.invoke(avc_log)
        formatted_prompt = prompt.format(context=retrieved_docs, question=avc_log)
        response_text = llm.invoke(formatted_prompt)

        ## --- ADDED: Print the raw response for debugging ---
        # print("--- RAW LLM RESPONSE ---")
        # print(response_text)
        # print("--- END RAW LLM RESPONSE ---")
        ## ---------------------------------------------------
        
        # Find the JSON block using a regular expression
        match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if match:
            json_str = match.group(0)
            # Return the cleaned JSON string to the client
            return jsonify(json_str)
        else:
            # If no JSON is found, return an error
            return jsonify({"error": "No valid JSON found in the AI response."}), 500
        
    except Exception as e:
        # --- ADDED: This will print the full error to your terminal ---
        traceback.print_exc()
        # -----------------------------------------------------------
        return jsonify({"error": f"Failed to communicate with AI model: {e}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
