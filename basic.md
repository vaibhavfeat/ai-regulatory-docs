1.  **PII must being Isolated, protected, and anonymized before entering in model including Prompts**
2.  **PII must be masked, PII Must be encrypted and Tokenized**
3.	Encryption at rest and in transit implemented for all PII data including Field Level PII Encyption even for Api's , AI Prompts and Logs etc
4.  **Field Level PII Encyption and PII Masking at all stages even for Api's and Logs and Prompts etc**
5.	How Data minimization (only required PII fields) handled in AI Model
6.	How are you ensuring protection of PII data privacy and security throughout the entire AI lifecycle. ensure and Document each purpose for using personal data at each stage of the AI lifecycle, assess whether they are compatible with the originally defined purpose mentioned in data processing scope/PII Inventory template, and schedule reviews to reassess your purposes and whether they remain compatible.
7.	How are you Ensuring that LLMs are not trained on or do not have access to any of sensitive data or PII data without appropriate anonymization, and pseudonymization or tokenization.
8.	How are you  Ensuring mechanisms to detect and possibly redact personally identifiable information (PII) that users might inadvertently include in their prompts.
9.	share controls list to ensure no PII data entering in AI model without Anonymization


1.	PII must being Isolated, protected, and anonymized before entering in model including Prompts

Identify PII information
| **Category**                    | **Description**                                                                                                                                                                                                               | **Examples in Indian Financial Context**                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Highly Sensitive PII**        | This data, if compromised, can lead to severe financial fraud, identity theft, or significant reputational damage. It is a top priority for filtration and must be handled with the highest level of security and encryption. | **Financial IDs:** <br>• Bank Account Numbers, IFSC codes <br>• Credit/Debit Card Numbers, CVV <br>• UPI IDs <br>• Demat and Trading Account Numbers <br><br> **Government IDs:** <br>• Aadhaar Number <br>• PAN (Permanent Account Number) <br>• Passport Number <br>• Voter ID, Driving License Number <br><br> **Authentication Data:** <br>• Biometric data (fingerprints, facial scans) <br>• Usernames and passwords <br>• Digital signatures <br>• Health data (for insurance products) |
| **Sensitive PII**               | This information is crucial for identification and, if combined with other data, can pose a risk. It should be protected through strict access controls and data masking.                                                     | **Personal Information:** <br>• Full name, date of birth <br>• Mother’s maiden name <br>• Father’s/Spouse’s name <br>• Permanent and correspondence addresses <br><br> **Financial Documents:** <br>• Tax returns, salary slips <br>• Financial statements, loan application forms                                                                                                                                                                                                             |
| **Non-Sensitive PII**           | This data is generally public but is still considered personal. While less critical, it must be protected to prevent correlation and profiling.                                                                               | **Contact Information:** <br>• Mobile number <br>• Email address <br><br> **Online Identifiers:** <br>• IP addresses <br>• Cookies <br>• Device identifiers <br>• Location data (GPS)                                                                                                                                                                                                                                                                                                          |
| **Other Data (to be filtered)** | Information that is not PII but is still confidential and related to the financial sector.                                                                                                                                    | **Proprietary Information:** <br>• Customer transaction histories <br>• Loan repayment schedules <br>• Credit scores <br>• Investment portfolio details <br>• Call recordings                                                                                                                                                                                                                                                                                                                  |


### PII Regex Patterns

| **PII Type**            | **Regex Pattern**                                                                 | **Notes**                                                                                     |
|--------------------------|-----------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
| Aadhaar Number           | `\b\d{4}\s\d{4}\s\d{4}\b`                                                         | Standard Aadhaar format (xxxx xxxx xxxx).                                                     |
| PAN (Permanent Account)  | `\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b`                                                    | 5 letters + 4 digits + 1 letter (e.g., ABCDE1234F).                                           |
| Passport Number          | `\b[A-PR-WYa-pr-wy][1-9]\d{6}\b`                                                  | Starts with a letter, followed by 7 digits (India-specific).                                  |
| Voter ID                 | `\b[A-Z]{3}\d{7}\b`                                                               | 3 letters + 7 digits.                                                                         |
| Driving License (India)  | `\b[ A-Z]{2}\d{2}\s?\d{11}\b`                                                     | Format varies by state; example: MH12 20202020202.                                            |
| Bank Account Numbers     | `\b\d{9,18}\b`                                                                    | Usually 9–18 digits (bank-specific).                                                          |
| IFSC Code                | `\b[A-Z]{4}0[A-Z0-9]{6}\b`                                                        | Example: SBIN0001234.                                                                         |
| Credit/Debit Card Nos.   | `\b(?:\d[ -]*?){13,16}\b`                                                         | Matches 13–16 digit card numbers (with or without spaces/dashes).                             |
| CVV                      | `\b\d{3,4}\b`                                                                     | 3 digits (Visa/Mastercard), 4 digits (Amex).                                                  |
| UPI ID                   | `\b[\w.-]+@[a-zA-Z]+\b`                                                           | Example: username@okaxis.                                                                     |
| Demat/Trading Account    | `\b\d{8}\b`                                                                       | Usually 8-digit client ID.                                                                    |
| Username/Password        | `[A-Za-z0-9!@#$%^&*()_+=-{}:;"'<>,.?]{6,}`                                        | Generic; needs stronger policies.                                                             |
| Biometric/Digital Sign   | ❌                                                                                 | Not regex-detectable. Requires different detection methods.                                   |

---

| **PII Type**      | **Regex Pattern**                                                 | **Notes**                                              |
|--------------------|-------------------------------------------------------------------|--------------------------------------------------------|
| Full Name (approx) | `\b([A-Z][a-z]+(?:\s[A-Z][a-z]+)+)\b`                             | Detects 2+ capitalized words (not fully reliable).     |
| Date of Birth      | `\b(0[1-9]|[12][0-9]|3[01])[- /.](0[1-9]|1[0-2])[- /.](19|20)\d\d\b` | dd-mm-yyyy (basic format).                             |
| Address (approx)   | `\d{1,4}\s[A-Za-z0-9\s,.-]+`                                      | Needs NLP for better accuracy.                        |
| Tax Return Numbers | `\b\d{10,15}\b`                                                   | Indian TINs usually 11 digits.                        |
| Salary Docs        | `(?i)(salary slip|ctc)`                                          | Case-insensitive detection of salary/CTC references.  |

---

| **PII Type**    | **Regex Pattern**                                            | **Notes**                      |
|------------------|--------------------------------------------------------------|--------------------------------|
| Mobile Number    | `\b(?:\+91[-\s]?)?[6-9]\d{9}\b`                              | Indian mobile numbers.         |
| Email Address    | `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`             | Generic email regex.           |
| IP Address (v4)  | `\b(?:\d{1,3}\.){3}\d{1,3}\b`                                | Matches IPv4.                  |
| Cookies/Session  | `\b[A-Za-z0-9+/]{20,}\b`                                     | Approx. session/cookie tokens. |
| GPS Coordinates  | `\b-?\d{1,2}\.\d+,\s?-?\d{1,3}\.\d+\b`                       | Latitude, Longitude format.    |

---

| **PII Type**        | **Regex Pattern**             | **Notes**                                 |
|----------------------|-------------------------------|-------------------------------------------|
| Loan Account Number  | `\b\d{12,16}\b`              | 12–16 digit account IDs.                  |
| Credit Scores        | `\b[3-8]\d{2}\b`             | 300–899 (CIBIL-like).                     |
| Transaction IDs      | `\b[0-9A-Z]{12,18}\b`        | 12–18 chars alphanumeric.                 |
| Portfolio Codes      | `\b[A-Z]{2,5}\d{3,6}\b`      | 2–5 letters + 3–6 digits.                 |


----
```javascript

/**
 * Redacts PII from a string and creates a map of the redacted data.
 * @param {string} text The input string to redact.
 * @returns {object} An object containing the redacted text and a mapping.
 */
function redactPIIWithMapping(text) {
/**
	Patterns to be stored in configuration file.
**/
  const patterns = {
    EMAIL: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    PHONE: /\b(\d{3}[-.\s]??\d{3}[-.\s]??\d{4}|\(\d{3}\)\s*\d{3}[-.\s]??\d{4}|\d{10})\b/g,
    SSN: /\b\d{3}[-.\s]??\d{2}[-.\s]??\d{4}\b/g,
    IP_ADDRESS: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,
  };

  let redactedText = text;
  const piiMap = {};
  let counter = 0;

  for (const piiType in patterns) {
    redactedText = redactedText.replace(patterns[piiType], (match) => {
      const placeholder = `[PII:${piiType}:${counter}]`;
      piiMap[placeholder] = match;
      counter++;
      return placeholder;
    });
  }

  return {
    redactedText: redactedText,
    piiMap: piiMap,
  };
}

// Example usage
const sampleText = "My email is john.doe@example.com, my phone number is 555-123-4567, and my SSN is 123-45-6789.";
const result = redactPIIWithMapping(sampleText);

console.log("Original Text:");
console.log(sampleText);
console.log("\nResult Object:");
console.log(JSON.stringify(result, null, 2));

```
#### Output

```json
Original Text:
My email is john.doe@example.com, my phone number is 555-123-4567, and my SSN is 123-45-6789.

Result Object:
{
  "redactedText": "My email is [PII:EMAIL:0], my phone number is [PII:PHONE:1], and my SSN is [PII:SSN:2].",
  "piiMap": {
    "[PII:EMAIL:0]": "john.doe@example.com",
    "[PII:PHONE:1]": "555-123-4567",
    "[PII:SSN:2]": "123-45-6789"
  }
}
```



## Encryption Points Solution:
1.	SSL Certificate
2.	Actionbl --> Encrypt Request Payload ---> API Server --> Decrypt Payload --> AI Model --> AI Output --> Api Server --> Encrypt Output --> Actionbl --> Decrypt

