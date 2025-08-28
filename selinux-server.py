import re
import traceback 
#import json
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
    pdf_loader = PyPDFLoader("./knowledge_base/SELinux_Notebook.pdf")
    static_docs = pdf_loader.load()
except Exception as e:
    print(f"Warning: Could not load static PDF knowledge base. {e}")
    static_docs = []

# --- Initialize LLM and Embeddings once ---
llm = OllamaLLM(model="llama3")
embeddings = OllamaEmbeddings(model="nomic-embed-text")

# Define the RAG prompt template

template = """
You are an expert SELinux system administrator. Your final response MUST BE ONLY a single, valid JSON object with three keys: "explanation", "commands", and "alternatives".
Use the provided context, which includes a snapshot of the user's live SELinux policy (booleans, types, classes, etc.), to analyze the AVC denial log.

Follow these rules precisely:
1.  **Analyze Denial Type**: First, inspect the `tclass` in the log.
2.  **Network Denials**: If `tclass` is `tcp_socket` or `udp_socket`, it is a network denial. For these, prioritize suggesting a boolean change or a `semanage port` command. **You MUST NOT suggest `semanage fcontext` or `restorecon` for network denials.**
3.  **File Denials**: If `tclass` is `file`, `dir`, etc., it is a file denial. For these, prioritize suggesting `semanage fcontext` and `restorecon`.
4.  **Best vs. Alternative**: The "commands" key MUST contain the BEST solution. The "alternatives" key can contain other valid solutions. If no alternatives exist, return an empty array `[]`.
5.  **File Path Rule**: When generating `semanage fcontext` or `restorecon` commands for a file path (e.g., `/path/to/a/file.txt`), you MUST generalize the command to the parent directory (e.g., `/path/to/a/`).
6.  **`restorecon` Rule**: After every `semanage fcontext` command, you MUST include the corresponding `restorecon` command.
7.  **Boolean Rule**: You MUST only suggest a boolean that is explicitly listed in the provided context. Do NOT invent booleans.

Context from documentation and live system state:
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
    # For troubleshooting incoming request data
    # print(f"DEBUG: Received request data: {request.json}")
    data = request.json
    avc_log = data.get('avc_log')
    selinux_context = data.get('selinux_context')

    if not avc_log:
        return jsonify({"error": "No log provided"}), 400

    try:
        # Combine static docs with the live booleans provided by the client
        live_context_docs = [Document(page_content=selinux_context)] if selinux_context else []
        all_docs = static_docs + live_context_docs # + live_fcontexts_docs

        # Create a temporary, in-memory vector store for this specific request
        text_splitter = RecursiveCharacterTextSplitter(chunk_size=1500, chunk_overlap=200)
        splits = text_splitter.split_documents(all_docs)

        vectorstore = Chroma.from_documents(documents=splits, embedding=embeddings)
        retriever = vectorstore.as_retriever()

        # RAG invocation
        retrieved_docs = retriever.invoke(avc_log)
        formatted_prompt = prompt.format(context=retrieved_docs, question=avc_log)
        response_text = llm.invoke(formatted_prompt)

        # --- ADDED: Print the raw response for debugging ---
#        print("--- RAW LLM RESPONSE ---")
#        print(response_text)
#        print("--- END RAW LLM RESPONSE ---")
        # ---------------------------------------------------
        
        # Find the JSON block using a regular expression
        match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if match:
            json_str = match.group(0)
#            print(f"--- DEBUG: EXTRACTED JSON STRING ---\n{json_str}\n--------------------------------")
#            # Validate the JSON on the server
#            try:
#                json.loads(json_str)
#                 print("--- DEBUG: Extracted string is valid JSON. ---")
#            except json.JSONDecodeError as e:
#                print(f"--- DEBUG: EXTRACTED STRING IS INVALID JSON ---\nError: {e}\n-----------------------------------------")
#            # Return the cleaned JSON string to the client
            return jsonify(json_str)
        else:
            # If no JSON is found, return an error
            print(f"DEBUG: AI response did not contain a JSON block.")
            return jsonify({"error": "No valid JSON found in the AI response."}), 500
        
    except Exception as e:
        # --- ADDED: This will print the full error to your terminal ---
        traceback.print_exc()
        # -----------------------------------------------------------
        return jsonify({"error": f"Failed to communicate with AI model: {e}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
