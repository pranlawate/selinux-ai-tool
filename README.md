# SELinux AI Troubleshooter

An AI-powered command-line tool to diagnose and provide solutions for SELinux AVC denials on RHEL-based systems.

## Features

* **AI-Powered Analysis**: Leverages the Perplexity API to provide expert-level explanations for complex SELinux denials.
* **Local Diagnostics**: The client parses audit logs locally to provide an immediate, human-readable summary.
* **Actionable Commands**: Suggests the exact shell commands needed to fix issues, including file context changes and boolean adjustments.

## Architecture

This tool uses a client-server architecture:
* **Client (`selinux-cli.py`)**: A Python-based CLI for user interaction and log parsing.
* **Server (`perplexity-server.js`)**: A Node.js/Express server that processes requests and communicates with the Perplexity API.

## Installation and Setup

### Prerequisites
* Git
* Python 3.10+
* Node.js 18+
* A Perplexity Pro account and an active **API Key**.

### Steps

1.  **Clone the Repository**:
    ```shell
    git clone [https://github.com/pranlawate/selinux-ai-tool.git](https://github.com/pranlawate/selinux-ai-tool.git)
    cd selinux-ai-tool
    ```

2.  **Set up the Server**:
    * Install Node.js dependencies:
        ```shell
        npm install
        ```
    * Create a `.env` file and add your Perplexity API key:
        ```
        PERPLEXITY_API_KEY="pplx-YourSecretApiKeyHere"
        ```

3.  **Set up the Client**:
    * Create and activate a Python virtual environment:
        ```shell
        python3 -m venv venv
        source venv/bin/activate
        ```
    * Install the required Python packages:
        ```shell
        pip install requests rich
        ```

## How to Run

The application requires two terminals running simultaneously.

1.  **Start the Server**:
    In your first terminal, start the Node.js server.
    ```shell
    node perplexity-server.js
    ```
    *Expected Output:* `Server is running on port 5000`

2.  **Run the Client**:
    In your second terminal, run the Python client. `sudo` is recommended if you re-introduce the live context collection feature in the future.
    ```shell
    venv/bin/python selinux-cli.py
    ```

## Example Usage

1.  When the client runs, it will prompt you to paste an SELinux log.
2.  Paste a log, for example:
    ```
    type=AVC msg=audit(08/31/2025 15:35:01.101:301): avc: denied  { read } for  pid=1234 comm="httpd" path="/var/www/html/index.html" dev="vda1" ino=12345 scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0
    ```
3.  Press **`Ctrl+D`** to submit.
4.  The tool will display a parsed summary of the log, followed by the AI's explanation and suggested commands.
