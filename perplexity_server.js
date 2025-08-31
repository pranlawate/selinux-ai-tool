const express = require('express');
require('dotenv').config();

const app = express();
app.use(express.json({ limit: '50mb' }));

const PPLX_API_KEY = process.env.PERPLEXITY_API_KEY;

const createPrompt = (avc_log) => { 
	const system_prompt =`You are an expert SELinux system administrator. Your task is to analyze the provided AVC denial log using the live system context.
Your final response MUST BE ONLY a single, valid JSON object with three keys: "explanation", "commands", and "alternatives".

**TASK:**
1.  Analyze the scontext, tcontext, tclass, and permission from the AVC LOG.
2.  Identify the process executable from the exe= or comm= field.
3.  For a TCONTEXT_MISMATCH: Cross-reference the process executable with the semanage fcontext -l list in the CONTEXT to find the correct file context.
4.  For an SCONTEXT_MISMATCH: Verify if the 'scontext' is correct for the given process executable.
5.  If contexts appear correct, check for a "BOOLEAN" issue.

**GENERAL RULES:**
- Generalize file paths to the parent directory for the final commands.
- Do NOT invent booleans or contexts not found in the CONTEXT.
- After every semanage fcontext command, you MUST include the corresponding restorecon command.
- DO NOT include escaped backslash in the output

Base your answer ONLY on information from official Red Hat documentation (redhat.com or access.redhat.com).`
	const user_prompt = `### AVC Denial Log to Analyze ###
${avc_log}`;
	return {
		model: "sonar-reasoning",
		messages: [
			{ role: "system", content: system_prompt },
			{ role: "user", content: user_prompt }
		]
	};
};

app.post("/analyze-avc", async (req,res)=>{
	if (!PPLX_API_KEY) {
		return res.status(500).json({ error: "PERPLEXITY_API_KEY is not set on the server."});

	}

	const {avc_log, parsed_log} = req.body;
	const requestBody = createPrompt(avc_log);

	console.log("--- Preparing to send this body to Perplexity API ---");
	console.log(JSON.stringify(requestBody, null, 2));
	console.log("--- Sending to Perplexity API ---");

	try {
		const responseRaw = await fetch("https://api.perplexity.ai/chat/completions", {
			headers: {
				'Content-Type': "application/json",
				'Accept': "application/json",
				'Authorization': `Bearer ${PPLX_API_KEY}`
			},
			method: "POST",
			body: JSON.stringify(requestBody)
		});

		if (!responseRaw.ok) {
			const errorBody = await responseRaw.text();
			console.error("Perplexity API Error:", errorBody);
			throw new Error(`API request failed with the status ${responseRaw.status}`);
		}

		const jsonResponse = await responseRaw.json();
		const aiResponseString = jsonResponse.choices[0].message.content;

//		console.log("--- RAW AI RESPONSE ---")
//		console.log(aiResponseString);
//		console.log("--- END RAW AI RESPONSE ---")

		// --- ADDED: Extract and log the "thinking" part ---
	        const thinkMatch = aiResponseString.match(/<think>([\s\S]*)<\/think>/);
       		if (thinkMatch && thinkMatch[1]) {
        		console.log("--- AI Reasoning (from <think> block) ---");
            		console.log(thinkMatch[1].trim());
            		console.log("------------------------------------------");
        	}
		

        	// 1. Find the JSON block within the AI's response string
	        let jsonString = null;
		let jsonMatch = aiResponseString.match(/```json\s*(\{[\s\S]*\})\s*```/);
		
		// 2. Parse the extracted JSON string into a JavaScript object
        	if (jsonMatch && jsonMatch[1]) {
			jsonString = jsonMatch[1];
		} else {
			jsonMatch = aiResponseString.match(/\{[\s\S]*\}/);
			if (jsonMatch && jsonMatch[0]) {
				jsonString = jsonMatch[0];
			}
		}

	        if (jsonString) {
			const jsonObject = JSON.parse(jsonString);
        		// 3. Send the object as a proper JSON response to the client
            		res.json(jsonObject);
        	} else {
            		// Log the raw response if parsing fails, for debugging
            		console.error("--- RAW AI RESPONSE (Failed to find JSON) ---");
            		console.error(aiResponseString);
            		console.error("---------------------------------------------");
			throw new Error("No valid JSON object found in the AI response.");
        	}

	} catch (error) {
		console.error("An error occurred:", error);
	        res.status(500).json({ error: "Failed to process the request." });
	}
});

app.listen(5000, (err)=>{
	console.error("Server is runnning on port 5000");
});
