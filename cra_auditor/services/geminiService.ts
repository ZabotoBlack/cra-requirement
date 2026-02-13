import { GoogleGenAI } from "@google/genai";
import { Device } from "../types";

export const getRemediationAdvice = async (device: Device): Promise<string> => {
  // NOTE: API Key must be obtained exclusively from process.env.API_KEY.
  
  try {
    const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
    
    const prompt = `
      You are a Cyber Resilience Act (CRA) Compliance Expert.
      Analyze the following IoT device audit report and provide specific, technical remediation steps to bring the device into compliance with EU CRA Annex I requirements.
      
      Device Context:
      - Vendor: ${device.vendor}
      - IP: ${device.ip}
      - Compliance Status: ${device.status}

      Audit Findings:
      1. Secure by Default (No Default Passwords): ${device.checks.secureByDefault.passed ? 'PASSED' : 'FAILED - ' + device.checks.secureByDefault.details}
      2. Data Confidentiality (Encryption): ${device.checks.dataConfidentiality.passed ? 'PASSED' : 'FAILED - ' + device.checks.dataConfidentiality.details}
      3. Known Vulnerabilities: ${device.checks.vulnerabilities.passed ? 'PASSED' : 'FAILED - ' + device.checks.vulnerabilities.cves.map(c => c.id).join(', ')}
      4. Security.txt Disclosure Policy (CRA §2(5), §2(6)): ${device.checks.securityTxt?.passed ? 'PASSED' : 'FAILED - ' + (device.checks.securityTxt?.details || 'No security.txt found')}

      Provide the response in Markdown format. Focus on actionable CLI commands (like ssh config changes), network segmentation advice, or firmware update procedures relevant to this vendor.
    `;

    const response = await ai.models.generateContent({
      model: 'gemini-3-flash-preview',
      contents: prompt,
    });

    return response.text || "No advice generated.";
  } catch (error) {
    console.error("Gemini API Error:", error);
    return "Failed to retrieve AI advice. Please check your API key and connection.";
  }
};