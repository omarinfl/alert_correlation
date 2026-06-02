# Incident Report: Agent Flooding and Suspicious Process Enumeration

**Date:** 2025-09-22  
**Host:** `videoserver` (172.17.100.121)  
**Status:** Active Investigation  

---

### 1. Incident Summary
The Wazuh manager reported a recurring "Agent event queue is full" alert (Rule 203) on the host `videoserver`. This indicates that the agent is unable to process or transmit logs to the manager, effectively creating a blind spot in monitoring. Correlated logs show frequent execution of the `ps` command by the `www-data` user, suggesting that a web-based service or application on the server is likely being abused to perform process enumeration, which in turn is generating the excessive log volume that triggered the flooding.

### 2. MITRE ATT&CK Correlation
The observed activity maps to the following tactics and techniques:

*   **Discovery (TA0007):**
    *   **T1057 - Process Discovery:** The repeated execution of `ps auxwww` by the `www-data` user indicates an attempt to map running processes on the system.
*   **Defense Evasion (TA0005):**
    *   **T1070 - Indicator Removal on Host:** The "Agent event queue is full" condition, while potentially a DoS, is often used to mask malicious activity by overwhelming the logging infrastructure, preventing security teams from seeing the subsequent stages of an attack.

### 3. Assessment
*   **Severity:** **High**
*   **Priority:** **Critical**
*   **Reasoning:** The combination of unauthorized process enumeration by a web service user (`www-data`) and the subsequent flooding of the security agent suggests an active attempt to perform reconnaissance while simultaneously blinding the security monitoring system. This is a strong indicator of a potential compromise of a web application.

### 4. Recommended Response Actions

1.  **Immediate Containment:**
    *   Isolate the `videoserver` (172.17.100.121) from the network if possible, or restrict access to the web service running under the `www-data` user.
2.  **Investigation:**
    *   Inspect the web server logs (e.g., Apache/Nginx) on `videoserver` to identify the source of the `ps` command execution.
    *   Check for web shells or vulnerable web applications that may be allowing remote code execution (RCE).
    *   Review the `www-data` user's activity for any other unauthorized commands or network connections.
3.  **Remediation:**
    *   Kill the malicious processes identified via the `ps` audit logs.
    *   Patch the vulnerable web application or remove any identified web shells.
    *   Increase the `buffer` size in the Wazuh agent configuration (`ossec.conf`) if the volume is legitimate, though this should only be done after confirming the traffic is not malicious.
4.  **Recovery:**
    *   Verify that the agent queue has cleared and that the agent is successfully communicating with the manager.
    *   Monitor for further signs of reconnaissance or lateral movement.