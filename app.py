import re
import traceback 
from flask import Flask, request, jsonify
from langchain_ollama import OllamaLLM
from langchain_ollama import OllamaEmbeddings
from langchain_chroma import Chroma
from langchain.prompts import ChatPromptTemplate

# --- App Configuration ---
app = Flask(__name__)
PERSIST_DIRECTORY = "./chroma_db"

# --- Load the RAG components at startup ---
print("Loading persistent vector store...")
embeddings = OllamaEmbeddings(model="nomic-embed-text")
vectorstore = Chroma(persist_directory=PERSIST_DIRECTORY, embedding_function=embeddings)
retriever = vectorstore.as_retriever()
llm = OllamaLLM(model="llama3")

# Define the RAG prompt template
template = """
You are an expert SELinux system administrator. Use the provided context from the SELinux documentation to help analyze the user's AVC denial log.
Your final response MUST BE ONLY a single, valid JSON object with two keys: "explanation" and "commands".
The "explanation" should clearly explain the denial, referencing the documentation context if relevant.
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

    if not avc_log:
        return jsonify({"error": "No log provided"}), 400

    try:
        # Simplified RAG invocation
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
