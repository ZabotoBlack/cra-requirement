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
  try {
    const response = await fetch('api/gemini/advice', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        device,
        messages,
      }),
    });

    if (!response.ok) {
      let fallback = messages?.requestFailed || "Failed to retrieve AI advice. Please check your API key and connection.";
      try {
        const errorData = await response.json();
        if (errorData?.error) {
          fallback = String(errorData.error);
        }
      } catch (e) {
      }
      return fallback;
    }

    const data = await response.json();
    return data?.advice || messages?.noAdvice || "No advice generated.";
  } catch (error) {
    console.error("Gemini API Error:", error);
    return messages?.requestFailed || "Failed to retrieve AI advice. Please check your API key and connection.";
  }
};