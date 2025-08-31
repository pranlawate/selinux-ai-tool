# SELinux AI Tool - Project Roadmap

This document outlines the development history and future priorities for the SELinux AI Troubleshooting Tool.

---
## ✅ Completed Tasks

* **Task 1: Initial Prototype (Python & Local AI)**
    * **Goal**: Built the first version of the client and server using a pure Python stack, integrating a local Llama3 model via Ollama with a RAG pipeline.

* **Task 2: Local Log Parser Development**
    * **Goal**: Developed a sophisticated local log parser and merged its functionality into the main client, making it a self-contained, informative tool.

* **Task 3: Project Setup & Version Control**
    * **Goal**: Established a professional workflow by setting up the project in a Git repository on GitHub, configuring a robust `.gitignore`, and using feature branches.

* **Task 4: Professional Development Environment Setup**
    * **Goal**: Configured an efficient development environment using VSCodium with Remote-SSH, a Python virtual environment, and shell aliases.

* **Task 5: Architectural Shift to Perplexity API**
    * **Goal**: Replaced the Python/Ollama backend with a more powerful Node.js server (`perplexity-server.js`) to leverage the web-connected Perplexity API.

* **Task 6: Advanced Client Diagnostics & Prompt Engineering**
    * **Goal**: Evolved the client into an advanced diagnostic tool by adding `sesearch` and other live data collection, and iteratively refined the server's prompt to handle complex scenarios.

* **Task 7: Final Code Stabilization**
    * **Goal**: Performed a full code review, fixed all identified bugs and inconsistencies, and synchronized the client and server into a final, stable baseline.

---
## 📝 Remaining Priorities

* **Priority 1: Implement Agentic Workflow (Self-Correction)**
    * **Goal**: Upgrade the server to be more resilient by automatically re-prompting the AI to fix malformed JSON responses.

* **Priority 2: Integrate `sesearch` for Precise Analysis**
    * **Goal**: Enhance the client to use `sesearch` to directly query the local policy, providing the AI with definitive evidence.

* **Priority 3: Implement "Expert" Diagnostic Workflow (`matchpathcon`)**
    * **Goal**: Upgrade the client to use `matchpathcon` and enhance the server's AI prompt to mimic an expert's workflow.

* **Priority 4: Create Test Automation**
    * **Goal**: Build an automated testing script that feeds a file of test AVC logs to the client and verifies the AI's suggestions.

* **Priority 5: Create a Standalone Client**
    * **Goal**: Package the feature-complete and tested client into a single, dependency-free executable.
    * **Subtask**: Handle `Ctrl+C` interruptions gracefully.

* **Priority 6: Implement Batch Log Processing**
    * **Goal**: Modify the standalone client to parse and analyze multiple `----` separated denial logs in a single run.

* **Priority 7: Enable Network Operation**
    * **Goal**: Modify the client and server to communicate over a network using IP addresses.

* **Priority 8: Add Offline/Air-Gapped Mode**
    * **Goal**: Create the feature for the client to save a data file for manual transfer and ingestion by the server.
