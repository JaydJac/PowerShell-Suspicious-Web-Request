
# Detecting Suspicious PowerShell Web Requests in Microsoft Sentinel

## Explanation
Sometimes when a bad actor has access to a system, they will attempt to download malicious payloads or tools directly from the internet to expand their control or establish persistence. This is often achieved using legitimate system utilities like PowerShell to blend in with normal activity. By leveraging commands such as `Invoke-WebRequest`, they can download files or scripts from an external server and immediately execute them, bypassing traditional defenses or detection mechanisms. 

This tactic is a hallmark of post-exploitation activity, enabling attackers to deploy malware, exfiltrate data, or establish communication channels with a command-and-control (C2) server. Detecting this behavior is critical to identifying and disrupting an ongoing attack.

When processes are executed on the local VM, logs will be forwarded to Microsoft Defender for Endpoint under the `DeviceProcessEvents` table. These logs are then sent to the Log Analytics Workspace used by Microsoft Sentinel, our SIEM. Within Sentinel, we will define an alert to trigger when PowerShell is used to download a remote file from the internet.

---

## Part 1: Create Alert Rule (PowerShell Suspicious Web Request)
I designed a Sentinel Scheduled Query Rule within Log Analytics to detect when PowerShell is used to download content using `Invoke-WebRequest`. Before creating the alert rule, I ensured the appropriate logs were available.

### KQL Query
```kql
let TargetHostname = "windows-target-1"; // Replace with the name of your VM as it shows up in the logs
DeviceProcessEvents
| where DeviceName == TargetHostname // Comment this line out for MORE results
| where FileName == "powershell.exe"
| where InitiatingProcessCommandLine contains "Invoke-WebRequest"
| order by TimeGenerated
```

Once the query was validated, I created the Scheduled Query Rule in:
- **Sentinel → Analytics → Scheduled Query Rule**

### Analytics Rule Settings:
- **Name:** PowerShell Suspicious Web Request
- **Description:** Detects when PowerShell is used to download files from the internet
- ✅ Enable the Rule
- **MITRE ATT&CK Framework Categories:** Use ChatGPT to map appropriate categories
- **Run query every:** 4 hours
- **Lookup data for the last:** 24 hours
- **Stop running query after alert is generated:** Yes
- **Entity Mappings:**
  - **Account:** Identifier → Name, Value → AccountName  
  - **Host:** Identifier → HostName, Value → DeviceName  
  - **Process:** Identifier → CommandLine, Value → ProcessCommandLine  
- ✅ Automatically create an Incident if the rule is triggered
- **Group all alerts into a single Incident per 24 hours**
- **Stop running query after alert is generated (24 hours)**

---

## Part 2: Trigger Alert to Create Incident
I ensured that my VM was onboarded to MDE and had been running for several hours. If logs were missing, I manually executed the following commands on my VM to simulate malicious behavior and generate logs:

```powershell
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1' -OutFile 'C:\programdata\eicar.ps1';
powershell.exe -ExecutionPolicy Bypass -File 'C:\programdata\eicar.ps1';
```

---

## Part 3: Work Incident
Following the **NIST 800-161: Incident Response Lifecycle**, I worked through the incident to completion.

### **Preparation**
- Ensured roles, responsibilities, and procedures were documented.
- Verified that necessary tools, systems, and training were in place.

### **Detection and Analysis**
- Identified and validated the incident.
- Assigned the incident to myself and set the status to Active.
- Investigated the Incident via **Actions → Investigate**.
- Gathered relevant evidence, such as logs and PowerShell script downloads.
- Simulated contacting the user, who claimed they installed free software at the time of the suspicious activity (for lab purposes).

#### **Findings:**
- The **PowerShell Suspicious Web Request** incident was triggered on _X_ devices by _Y_ users.
- PowerShell downloaded _Z_ different scripts from the internet:
  - URL to Script 1
  - URL to Script 2

To verify whether the scripts were executed, I ran:

```kql
let TargetHostname = "windows-target-1";
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```

---

### **Containment, Eradication, and Recovery**
- Isolated the affected system using Microsoft Defender for Endpoint.
- Performed an antimalware scan in MDE.
- If any scripts were executed, I analyzed their content using ChatGPT and recorded my findings:
  - Script **X.ps1** was observed to **[describe action]**.
  - Script **Y.ps1** was observed to **[describe action]**.
- Removed the threat and restored the system to normal.

---

## **Post-Incident Activities**
- Documented findings and lessons learned.
- Updated policies to prevent recurrence, such as restricting PowerShell usage.
- Closed out the incident within Sentinel as a **True Positive**.

### **Closure**
- Reviewed and confirmed incident resolution.
- Finalized reporting and closed the case.

---

## **Conclusion**
By implementing this alert rule and working through the incident, I successfully detected and responded to a potential security threat using Microsoft Sentinel and Microsoft Defender for Endpoint. This process reinforced best practices for threat hunting and security operations while highlighting how attackers can leverage legitimate tools like PowerShell for malicious activity. Moving forward, refining detection rules and implementing additional controls will further enhance security posture and threat mitigation efforts.
