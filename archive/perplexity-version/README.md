# SELinux AI Troubleshooter - Perplexity Version

This is the working server-client pair that uses the Perplexity API for AI analysis.

## Architecture
- **Client-Server Model**: Python client communicates with Node.js server
- **AI-Powered**: Uses Perplexity API for intelligent SELinux analysis
- **Web-Connected**: Leverages real-time AI knowledge

## Files:
- `perplexity_server.js` - Node.js Express server that connects to Perplexity API
- `selinux-cli.py` - Python client with rich formatting and log parsing
- `package.json` - Node.js dependencies (express, axios, dotenv)
- `package-lock.json` - Locked dependency versions

## Setup:

### Prerequisites
- Node.js 18+
- Python 3.10+
- Perplexity API key

### Installation
1. Install Node.js dependencies:
   ```bash
   cd archive/perplexity-version
   npm install
   ```

2. Create `.env` file with your API key:
   ```bash
   echo "PERPLEXITY_API_KEY=pplx-your-api-key-here" > .env
   ```

3. Install Python dependencies:
   ```bash
   pip install requests rich
   ```

## Usage:

### Start the server (Terminal 1):
```bash
node perplexity_server.js
```
Expected output: `Server is running on port 5000`

### Run the client (Terminal 2):
```bash
python selinux-cli.py
```

## Features:
- **Real-time AI Analysis**: Connects to Perplexity API for current SELinux knowledge
- **Professional Output**: Rich formatting with tables and colors
- **Complete Log Parsing**: Extracts all relevant fields from AVC denials
- **Actionable Commands**: Provides specific `semanage` and `restorecon` commands
- **Error Handling**: Graceful fallback and error reporting

## Example Usage:
Paste an AVC denial log like:
```
type=AVC msg=audit(1625097901.234:567): avc: denied { read } for pid=1234 comm="httpd" path="/var/www/html/index.html" dev="vda1" ino=12345 scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0
```

The tool will provide intelligent analysis and specific remediation steps.

---
*Archived on: $(date)*
*This version represents the stable Perplexity API integration*
