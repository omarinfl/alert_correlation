# Incident Analysis Report: Unauthorized/Suspicious RDP Activity

## 1. Incident Summary
*   **Alert:** User `user1` initiated a Remote Desktop Protocol (RDP) connection from source host `fleatbottom` to destination host `sept` using the `mstsc.exe` client.
*   **Date/Time:** [Insert Timestamp]
*   **Source Host:** `fleatbottom`
*   **Destination Host:** `sept`
*   **User Account:** `user1`

## 2. MITRE ATT&CK Correlation
The activity has been mapped to the following MITRE ATT&CK framework technique:

*   **Technique ID:** [T1021.001](https://attack.mitre.org/techniques/T1021/001)
*   **Technique Name:** Remote Desktop Protocol
*   **Tactic:** Lateral Movement
*   **Analysis:** The use of `mstsc.exe` to connect between internal hosts is a standard method for lateral movement. While RDP is a legitimate administrative tool, its use should be validated against expected operational baselines for `user1` and the involved hosts.

## 3. CVE Vulnerability Assessment
*   **Status:** No specific CVEs were identified or associated with this alert. The activity is categorized as a behavioral event rather than an exploit of a known software vulnerability.

## 4. Assessment
*   **Severity:** **Medium**
*   **Priority:** **Medium**
*   **Rationale:** The activity represents a potential lateral movement vector. Without context regarding whether `user1` is authorized to access `sept` from `fleatbottom`, this must be treated as a security event requiring verification.

## 5. Recommended Response Actions
1.  **Verify Authorization:** Confirm with the system administrator or the owner of `user1` if this RDP session was a scheduled or authorized administrative task.
2.  **Review Logs:** Examine logs on host `sept` for concurrent activity, such as command execution, file modifications, or privilege escalation attempts following the RDP login.
3.  **Check Account Activity:** Investigate if `user1` has exhibited unusual behavior or if there have been multiple failed login attempts preceding this successful connection.
4.  **Containment (If Unauthorized):** If the activity is deemed unauthorized, immediately terminate the RDP session, disable the `user1` account, and isolate host `fleatbottom` for forensic analysis.
5.  **Policy Review:** Ensure that RDP access is restricted to authorized users and specific jump hosts via Group Policy or firewall rules to minimize the attack surface.