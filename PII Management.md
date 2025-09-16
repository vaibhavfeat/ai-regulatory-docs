# Data Privacy and Security in AI Models

1.  **PII must being Isolated, protected, and anonymized before entering in model including Prompts**
2.  **PII must be masked, PII Must be encrypted and Tokenized**
3.	Encryption at rest and in transit implemented for all PII data including Field Level PII Encyption even for Api's , AI Prompts and Logs etc
4.  **Field Level PII Encyption and PII Masking at all stages even for Api's and Logs and Prompts etc.**
5.	How Data minimization (only required PII fields) handled in AI Model
6.	How are you ensuring protection of PII data privacy and security throughout the entire AI lifecycle. ensure and Document each purpose for using personal data at each stage of the AI lifecycle, assess whether they are compatible with the originally defined purpose mentioned in data processing scope/PII Inventory template, and schedule reviews to reassess your purposes and whether they remain compatible.
7.	How are you Ensuring that LLMs are not trained on or do not have access to any of sensitive data or PII data without appropriate anonymization, and pseudonymization or tokenization.
8.	How are you  Ensuring mechanisms to detect and possibly redact personally identifiable information (PII) that users might inadvertently include in their prompts.
9.	share controls list to ensure no PII data entering in AI model without Anonymization


## 1. PII Isolation, Protection, and Anonymization
Before any data, including prompts, enters an AI model, **Personally Identifiable Information (PII)** must be identified, isolated, protected, and anonymized. This is the first critical step to ensure data privacy.


### Identifying PII Information
The following table categorizes different types of PII, with specific examples relevant to the Indian financial context.

| **Category** | **Description** | **Examples in Indian Financial Context** |
| :--- | :--- | :--- |
| **Highly Sensitive PII** | Data that, if compromised, can lead to severe financial fraud, identity theft, or significant reputational damage. | **Financial IDs:** Bank Account Numbers, IFSC codes, Credit/Debit Card Numbers, CVV, UPI IDs, Demat and Trading Account Numbers <br><br> **Government IDs:** Aadhaar Number, PAN, Passport Number, Voter ID, Driving License Number <br><br> **Authentication Data:** Biometric data (fingerprints, facial scans), Usernames and passwords, Digital signatures, Health data (for insurance products) |
| **Sensitive PII** | Information crucial for identification that, if combined with other data, can pose a risk. | **Personal Information:** Full name, date of birth, Mother’s maiden name, Father’s/Spouse’s name, Permanent and correspondence addresses <br><br> **Financial Documents:** Tax returns, salary slips, Financial statements, loan application forms |
| **Non-Sensitive PII** | Generally public data still considered personal. | **Contact Information:** Mobile number, Email address <br><br> **Online Identifiers:** IP addresses, Cookies, Device identifiers, Location data (GPS) |
| **Other Confidential Data** | Information not classified as PII but is still confidential and related to the financial sector. | **Proprietary Information:** Customer transaction histories, Loan repayment schedules, Credit scores, Investment portfolio details, Call recordings |

### Regex Patterns for PII Detection
Regular expressions (**Regex**) are a key tool for automatically detecting PII within text. Below are common regex patterns for various PII types:


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


| **PII Type**      | **Regex Pattern**                                                 | **Notes**                                              |
|--------------------|-------------------------------------------------------------------|--------------------------------------------------------|
| Full Name (approx) | `\b([A-Z][a-z]+(?:\s[A-Z][a-z]+)+)\b`                             | Detects 2+ capitalized words (not fully reliable).     |
| Date of Birth      | `\b(0[1-9]|[12][0-9]|3[01])[- /.](0[1-9]|1[0-2])[- /.](19|20)\d\d\b` | dd-mm-yyyy (basic format).                             |
| Address (approx)   | `\d{1,4}\s[A-Za-z0-9\s,.-]+`                                      | Needs NLP for better accuracy.                        |
| Tax Return Numbers | `\b\d{10,15}\b`                                                   | Indian TINs usually 11 digits.                        |
| Salary Docs        | `(?i)(salary slip|ctc)`                                          | Case-insensitive detection of salary/CTC references.  |


| **PII Type**    | **Regex Pattern**                                            | **Notes**                      |
|------------------|--------------------------------------------------------------|--------------------------------|
| Mobile Number    | `\b(?:\+91[-\s]?)?[6-9]\d{9}\b`                              | Indian mobile numbers.         |
| Email Address    | `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`             | Generic email regex.           |
| IP Address (v4)  | `\b(?:\d{1,3}\.){3}\d{1,3}\b`                                | Matches IPv4.                  |
| Cookies/Session  | `\b[A-Za-z0-9+/]{20,}\b`                                     | Approx. session/cookie tokens. |
| GPS Coordinates  | `\b-?\d{1,2}\.\d+,\s?-?\d{1,3}\.\d+\b`                       | Latitude, Longitude format.    |


| **PII Type**        | **Regex Pattern**             | **Notes**                                 |
|----------------------|-------------------------------|-------------------------------------------|
| Loan Account Number  | `\b\d{12,16}\b`              | 12–16 digit account IDs.                  |
| Credit Scores        | `\b[3-8]\d{2}\b`             | 300–899 (CIBIL-like).                     |
| Transaction IDs      | `\b[0-9A-Z]{12,18}\b`        | 12–18 chars alphanumeric.                 |
| Portfolio Codes      | `\b[A-Z]{2,5}\d{3,6}\b`      | 2–5 letters + 3–6 digits.                 |


> **Note:** Some data, like biometrics and digital signatures, cannot be detected by regex and requires alternative methods.

***
## 2. PII Masking, Encryption, and Tokenization 🛡️
Once identified, PII is protected using a combination of techniques:
* **Masking:** PII is obscured or replaced with characters like `*` or `X` in logs and displays, making it unreadable.
* **Encryption:** Data is transformed into an unreadable format using a key. This is a crucial defense against unauthorized access.
* **Tokenization:** PII is replaced with a non-sensitive surrogate value (a "token") that holds no meaning or value on its own. This token can then be used in the AI model, while the original PII is stored securely and separately.

***
## 3. Encryption at Rest and in Transit
**Encryption** must be implemented for all PII data at every stage.
* **Encryption at Rest:** Data stored in databases, logs, and file systems must be encrypted.
* **Encryption in Transit:** Data moving between systems, such as from a user's device to an API server or from an API server to the AI model, must be secured using protocols like **SSL/TLS**. This includes API payloads, logs, and prompts.
* **Field-Level Encryption:** Sensitive PII fields should be individually encrypted, providing an extra layer of security.

***
## 4. Field-Level PII Encryption and Masking
This control is applied across the entire data flow, including API calls, logs, and AI prompts. It ensures that even if a part of the system is compromised, the sensitive data within it remains protected. The `redactPIIWithMapping` function provided in the prompt is an excellent example of how to implement **masking** and **tokenization** programmatically. It replaces PII with a placeholder token, creating a map to de-identify the original data, thus preventing sensitive information from ever reaching the model.

```javascript
// Function to redact PII and create a mapping
function redactPIIWithMapping(text) {
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
  return { redactedText, piiMap };
}

// Example usage
const sampleText = "My email is john.doe@example.com, my phone number is 555-123-4567, and my SSN is 123-45-6789.";
const result = redactPIIWithMapping(sampleText);

console.log(JSON.stringify(result, null, 2));
```
## Output
```json
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

1.  SSL Certificate
2.  Actionbl --> Encrypt Request Payload ---> API Server --> Decrypt Payload --> AI Model --> AI Output --> Api Server --> Encrypt Output --> Actionbl --> Decrypt

