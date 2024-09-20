# Analyze a suspicious file with VirusTotal and document the incident using incident handler's journal

## Project Overview

This project involves using VirusTotal to analyze a suspicious file associated with a potential malware attack. The objective is to determine if the file is malicious by identifying Indicators of Compromise (IoCs) and documenting the findings using the Pyramid of Pain framework. VirusTotal provides threat intelligence by analyzing files, URLs, and domains to help identify malicious artifacts. In this project, the focus is on uncovering different types of IoCs and assessing the file’s threat level using the Pyramid of Pain.

## Objectives

- **Analyze Suspicious File:** Use VirusTotal to investigate a file hash and assess whether it is malicious based on detection reports.
- **Identify IoCs:** Determine three indicators of compromise (IoCs) related to the suspicious file.
- **Use Pyramid of Pain:** Document and categorize IoCs using the Pyramid of Pain framework to understand their impact on threat actors.
- **Document Incident:** Record the findings and explain the process in a clear, structured format.

### Skills Learned
- Gained experience in analyzing file hashes using VirusTotal and identifying indicators of compromise.
- Learned how to categorize IoCs (hash values, IP addresses, domain names, etc.) and understand their impact on the Pyramid of Pain.
- Developed skills in evaluating threat intelligence reports from VirusTotal, including analyzing vendor verdicts, sandbox behavior, and IoC relations.
- Improved understanding of tactics, techniques, and procedures (TTPs) used by attackers to exploit vulnerabilities.
  
### Tools Used
- VirusTotal
- Pyramid of Pain
- Incident Handler’s Journal

## Steps

### Step 1: Review the Details of the Alert

- An employee received a phishing email containing a malicious attachment that executed a payload after the file was opened.
- Retrieved the file's SHA256 hash: 54e6ea47eb04634d3e87fd7787e2136ccfbcc80ade34f246a12cf93bab527f6b.
- Analyzed the timeline of events, from email receipt to the triggering of the security alert.

### Step 2: Use VirusTotal to Analyze the File Hash

- Entered the file hash into VirusTotal to retrieve the analysis report.
- Examined the Detection tab to check how many vendors flagged the file as malicious.
- Explored the Details tab to extract additional IoCs such as MD5, SHA-1, and file metadata.
- Checked the Relations tab to identify any domain names or IP addresses contacted by the malware.
- Looked at the Behavior tab to see sandbox reports on the file's behavior, including tactics, techniques, and procedures (TTPs).

### Step 3: Document the Findings in the Pyramid of Pain

- Determined that the file was malicious based on VirusTotal’s high vendors' ratio and negative community score.
- Identified three IoCs from the VirusTotal report:
- Additional SHA-1 hash related to the malware.
- The malware contacted a known malicious IP address.
- Found tactics and techniques related to the malware using MITRE ATT&CK.
- Documented the three IoCs in their respective sections in the Pyramid of Pain template.

### Step 4: Finalize and Review

- Assessed the overall maliciousness of the file based on the consistency of VirusTotal findings.
- Logged the analysis, findings, and conclusions in the incident handler’s journal for reference.
