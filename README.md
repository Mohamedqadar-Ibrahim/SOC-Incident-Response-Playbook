# SOC Incident Response Playbook 📒

## Purpose
This playbook provides a structured approach for responding to cybersecurity incidents within an organisation. It guides analysts through detecting, analysing, and responding to potential threats, ensuring consistency, thoroughness, and alignment with best practices.

---

## 1. Initial Detection and Triage 🔍

**Objective**: Quickly assess incoming alerts to determine the threat level.

### Steps:

1. **Gather Context**:
   - 🔗 Review the alert’s source (e.g., SIEM, IDS/IPS).
   - 🔍 Verify the authenticity of the alert by cross-referencing log data.
   - 📊 Identify the severity of the alert based on pre-established criteria (e.g., critical, high, medium, low).

2. **Key Tools**:
   - **Splunk**: Review alerts, correlate logs, and search for additional indicators.
   - **ElasticSIEM**: Visualise data related to the source IP, destination IP, and activity timeline.

3. **Triage Checklist**:
   - ❓ Is this an isolated event or part of a recurring pattern?
   - 🚩 Has the source IP been flagged before?
   - 🔐 Does the alert contain any known Indicators of Compromise (IOCs)?

**Example Use Case: Failed Login Attempts**  
- Review alerts for failed login attempts from a single IP.
- Correlate logs to determine if attempts escalate (e.g., attempts spread across accounts).
- If attempts exceed the threshold (e.g., 5 within 1 minute), escalate to Incident Analysis.

---

## 2. Incident Analysis 🧩

**Objective**: Analyse confirmed alerts to determine the root cause, scope, and impact.

### Steps:

1. **Correlate Events**:
   - 📜 Gather additional logs related to the IP address, user accounts, or processes involved.
   - 🔍 Check recent activities from the compromised system to identify lateral movement or privilege escalation.

2. **Threat Intelligence**:
   - 🌐 Look up IOCs (e.g., IP addresses, hash values) in threat intelligence sources (e.g., VirusTotal, AlienVault OTX).
   - 🛡️ Map observed behaviors to tactics and techniques in the MITRE ATT&CK framework, if applicable.

3. **Documentation**:
   - 📝 Document all findings, including actions taken, IOCs identified, and evidence collected.
   - 🕵️ Record any gaps in detection or containment.

**Example Use Case: Suspicious File Detection**  
- Check for recent downloads or file changes.
- Use threat intelligence to verify if the file has a malicious hash.
- Analyse other recent logs from the same endpoint or IP for connections to known C2 servers.

---

## 3. Containment and Eradication 🚫

**Objective**: Stop the threat from spreading and eliminate its presence.

### Steps:

1. **Containment Strategies**:
   - 🛑 Temporarily disable compromised user accounts.
   - 🔌 Isolate affected systems from the network for further analysis.

2. **Eradication Steps**:
   - 🧹 Remove malicious files or programs from affected systems.
   - 🛠️ Apply patches or update vulnerable applications to prevent further exploitation.

3. **Tools**:
   - **Endpoint Detection and Response (EDR)** tools for containment.
   - **Wazuh**: Monitor and ensure successful containment and remediation.

**Example Use Case: Ransomware Detection**  
- Disconnect affected machine(s) from the network.
- Check for additional signs of ransomware spread.
- Run antivirus or EDR tools to remove any remnants of the malware.

---

## 4. Recovery and Restoration 🔄

**Objective**: Restore systems to operational status and verify that no threats remain.

### Steps:

1. **System Restoration**:
   - 🔄 Restore from a clean backup if available.
   - 🔍 Reconnect affected systems to the network and monitor closely for unusual activity.

2. **Validation**:
   - 🔎 Run integrity checks and vulnerability scans to ensure systems are clean.
   - ✅ Confirm that no further alerts are triggered post-recovery.

**Example Use Case: Post-Ransomware Recovery**  
- Restore encrypted files from backup.
- Scan endpoints thoroughly to ensure no ransomware indicators remain.
- Reintroduce systems to the network under enhanced monitoring.

---

## 5. Post-Incident Review and Reporting 📝

**Objective**: Analyse and document the incident to improve future responses.

### Steps:

1. **Incident Summary**:
   - 📄 Summarise key findings, including the root cause, timeline of events, and response actions.

2. **Lessons Learned**:
   - 🧩 Identify gaps in detection, triage, or response processes.
   - 🔄 Update relevant policies or playbooks to reflect new insights.

3. **Reporting**:
   - 📨 Share the incident report with relevant stakeholders.
   - 📈 Recommend additional training or resources if needed to prevent future incidents.

**Example Use Case: Failed Phishing Attack**  
- Identify why the phishing email bypassed detection.
- Document any required changes to email filtering rules.
- Recommend user awareness training if employees clicked on phishing links.

---

## Appendix: Playbook Enhancements 📌

- **Add MITRE ATT&CK Mappings**: Include mappings to tactics and techniques for each type of incident.
- **Create Custom Dashboards**: Develop real-time SOC dashboards in Splunk to visualise key metrics like failed logins, high-severity alerts, and endpoint alerts.
