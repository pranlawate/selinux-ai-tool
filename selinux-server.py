import re
import traceback 
import json
from flask import Flask, request, jsonify
from langchain_ollama import OllamaLLM,OllamaEmbeddings
from langchain_chroma import Chroma
from langchain.prompts import ChatPromptTemplate
from langchain_community.document_loaders import PyPDFLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.schema.document import Document
from langchain.schema.output_parser import StrOutputParser

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
You are an expert SELinux system administrator. Your task is to analyze an AVC denial log and provide the key components for a solution.
Your final response MUST BE ONLY a single, valid JSON object.

Based on the denial log and the provided context, determine the root cause.
- If it is a file context issue, return a JSON object with: `{{"analysis_type": "CONTEXT", "target_path": "<path>", "required_context": "<context_type>", "explanation": "<explanation>"}}`. Generalize the path to the parent directory.
- If it is a boolean issue, return a JSON object with: `{{"analysis_type": "BOOLEAN", "required_boolean": "<boolean_name>", "explanation": "<explanation>"}}`. You MUST use a boolean from the provided context.
- The "explanation" should be a brief, one-sentence summary.

Context from documentation and live system state:
{context}

User's AVC denial log:
{question}

JSON Analysis:
"""

prompt = ChatPromptTemplate.from_template(template)

# Create the RAG chain
# Note: The chain logic is now simplified inside the endpoint
print("SELinux AI backend is ready.")

rag_chain = (
        prompt
        | llm
        | StrOutputParser()
)

# --- API Endpoint ---
@app.route('/analyze-avc', methods=['POST'])
def analyze_avc():
    """Receives an AVC log, gets a RAG-informed analysis, and returns it."""
    ## For troubleshooting incoming request data
    #print(f"DEBUG: Received request data: {request.json}")
    data = request.json
    avc_log = data.get('avc_log')
    selinux_context = data.get('selinux_context')

    if not avc_log:
        return jsonify({"error": "No log provided"}), 400

    try:
        # PERFORMANCE OPTIMIZATION: We pass the live context directly to the LLM
        # without vectorizing it every time. This is much faster.
        # The PDF is still vectorized for efficient searching.
  
#        # Combine static docs with the live booleans provided by the client
#        live_context_docs = [Document(page_content=selinux_context)] if selinux_context else []
#        all_docs = static_docs + live_context_docs # + live_fcontexts_docs

        text_splitter = RecursiveCharacterTextSplitter(chunk_size=1500, chunk_overlap=200)
        splits = text_splitter.split_documents(static_docs)
        vectorstore = Chroma.from_documents(documents=splits, embedding=embeddings)
        retriever = vectorstore.as_retriever()

        # RAG invocation
        retrieved_docs = retriever.invoke(avc_log)

        #Combine retrieved docs with the full live context for the prompt
        full_context = f"{retrieved_docs}\n\n{selinux_context}"
#        formatted_prompt = prompt.format(context=full_context, question=avc_log)
#        response_text = llm.invoke(formatted_prompt)
        response_text = rag_chain.invoke({
            "context": full_context,
            "question": avc_log
        })

        # --- ADDED: Print the raw response for debugging ---
        print("---DEBUG: RAW LLM RESPONSE ---")
        print(response_text)
        print("--- END RAW LLM RESPONSE ---")
        # ---------------------------------------------------
        
        # Find the JSON block using a regular expression
        match = re.search(r'\{.*\}', response_text, re.DOTALL)
#        if match:
#            json_str = match.group(0)
#            print(f"--- DEBUG: EXTRACTED JSON STRING ---\n{json_str}\n--------------------------------")
#            # Validate the JSON on the server
#            try:
#                json.loads(json_str)
#                 print("--- DEBUG: Extracted string is valid JSON. ---")
#            except json.JSONDecodeError as e:
#                print(f"--- DEBUG: EXTRACTED STRING IS INVALID JSON ---\nError: {e}\n-----------------------------------------")
#            # Return the cleaned JSON string to the client
#            return jsonify(json_str)
#        else:
        if not match:
            # If no JSON is found, return an error
            print(f"DEBUG: AI response did not contain a JSON block.")
            return jsonify({"error": "No valid JSON found in the AI response."}), 500
        
        analysis_json = json.loads(match.group(0))

        # --- NEW: Python code builds the final commands ---
        final_response = {
            "explanation": analysis_json.get("explanation", "No explanation provided."),
            "commands": [],
            "alternatives": []
        }

        analysis_type = analysis_json.get("analysis_type")
        if analysis_type == "CONTEXT":
            path = analysis_json.get("target_path")
            context = analysis_json.get("required_context")
            if path and context:
                final_response["commands"].append(f"semanage fcontext -a -t {context} '{path}(/.*)?'")
                final_response["commands"].append(f"restorecon -Rv {path}")
        
        elif analysis_type == "BOOLEAN":
            boolean = analysis_json.get("required_boolean")
            if boolean:
                final_response["commands"].append(f"setsebool -P {boolean} on")

        return jsonify(final_response)

    except Exception as e:
        # --- ADDED: This will print the full error to your terminal ---
        traceback.print_exc()
        # -----------------------------------------------------------
        return jsonify({"error": f"Failed to communicate with AI model: {e}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
