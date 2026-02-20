import { GoogleGenAI } from "@google/genai";
import { Device } from "../types";

interface GeminiErrorMessages {
  noApiKey?: string;
  requestFailed?: string;
  noAdvice?: string;
  localizedStatus?: string;
  responseLanguage?: 'en' | 'de';
}

/**
 * Generate AI remediation guidance for a scanned device.
 * Returns a user-facing message for both success and error paths.
 */
export const getRemediationAdvice = async (device: Device, messages?: GeminiErrorMessages): Promise<string> => {
  // NOTE: API Key must be obtained exclusively from process.env.API_KEY.
  const apiKey = process.env.API_KEY;

  if (!apiKey) {
    return messages?.noApiKey || "Gemini API key is not configured. Add GEMINI_API_KEY to use AI remediation advice.";
  }
  
  try {
    const ai = new GoogleGenAI({ apiKey });
    const complianceStatus = messages?.localizedStatus || device.status;
    const responseLanguageInstruction = messages?.responseLanguage === 'de'
      ? 'Respond in German.'
      : 'Respond in English.';
    
    const prompt = `
      You are a Cyber Resilience Act (CRA) Compliance Expert.
      Analyze the following IoT device audit report and provide specific, technical remediation steps to bring the device into compliance with EU CRA Annex I requirements.
      
      Device Context:
      - Vendor: ${device.vendor}
      - IP: ${device.ip}
      - Compliance Status: ${complianceStatus}

      Audit Findings:
      1. Secure by Default (No Default Passwords): ${device.checks.secureByDefault.passed ? 'PASSED' : 'FAILED - ' + device.checks.secureByDefault.details}
      2. Data Confidentiality (Encryption): ${device.checks.dataConfidentiality.passed ? 'PASSED' : 'FAILED - ' + device.checks.dataConfidentiality.details}
      3. Known Vulnerabilities: ${device.checks.vulnerabilities.passed ? 'PASSED' : 'FAILED - ' + device.checks.vulnerabilities.cves.map(c => c.id).join(', ')}
      4. Security.txt Disclosure Policy (CRA §2(5), §2(6)): ${device.checks.securityTxt?.passed ? 'PASSED' : 'FAILED - ' + (device.checks.securityTxt?.details || 'No security.txt found')}
      5. Security Logging Capability (CRA Annex I §1(3)(j)): ${device.checks.securityLogging?.passed ? 'PASSED' : 'WARNING - ' + (device.checks.securityLogging?.details || 'No logging capability verified')}

      Provide the response in Markdown format. ${responseLanguageInstruction}
      Focus on actionable CLI commands (like ssh config changes), network segmentation advice, or firmware update procedures relevant to this vendor.
    `;

    const response = await ai.models.generateContent({
      model: 'gemini-3-flash-preview',
      contents: prompt,
    });

    return response.text || messages?.noAdvice || "No advice generated.";
  } catch (error) {
    console.error("Gemini API Error:", error);
    return messages?.requestFailed || "Failed to retrieve AI advice. Please check your API key and connection.";
  }
};