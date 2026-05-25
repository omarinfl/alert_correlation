# Incident Report: Web Application Reconnaissance Attempt

## 1. Incident Summary
*   **Timestamp:** 2022-01-18T12:28:56Z
*   **Source IP:** 172.17.130.196
*   **Target Agent:** wazuh-client (10.35.35.206)
*   **Alert Description:** Web server 400 error code (Rule 31101)
*   **Observed Activity:** The source IP performed a `GET` request for `/wp-includes/blocks/query/wsdl`. This path does not exist on the target, resulting in a 404 error. The request pattern is consistent with automated vulnerability scanning or an attempt to fingerprint the WordPress installation.

## 2. Threat Intelligence Correlation
*   **MITRE ATT&CK Tactics:**
    *   **Reconnaissance (TA0043):** The activity is indicative of automated scanning to identify the presence of specific WordPress files or potential misconfigurations.
    *   **Exploitation of Web Application (T1190):** The attacker is probing for known paths associated with WordPress vulnerabilities to determine if the target is susceptible to exploitation.
*   **CVE Context:**
    *   The request targets the `/wp-includes/` directory, a common target for attackers looking to exploit vulnerabilities in WordPress core files. While no specific CVE was triggered, this behavior is a precursor to exploiting known vulnerabilities related to WordPress file inclusion or information disclosure.

## 3. Assessment
*   **Severity:** **Medium**
*   **Priority:** **Low**
*   **Justification:** The high frequency of the rule firing (185,909 times) suggests a widespread automated scan rather than a targeted, manual attack. While the request was unsuccessful (404), it confirms that the host is being actively probed by external actors.

## 4. Recommended Response Actions
1.  **Block Source IP:** Implement a temporary block on the source IP `172.17.130.196` at the perimeter firewall or via `iptables` on the affected host to mitigate further scanning.
2.  **Verify WordPress Integrity:** Ensure the WordPress installation is updated to the latest version and that all plugins/themes are patched to mitigate potential exploitation of core files.
3.  **Review Access Logs:** Conduct a deeper analysis of `/var/log/apache2/intranet-access.log` to determine if the source IP attempted other malicious paths or successfully accessed any sensitive files.
4.  **Monitor:** Continue monitoring for similar patterns from this IP or other external sources. If the scanning persists from multiple IPs, consider implementing a Web Application Firewall (WAF) rule to drop requests containing common exploit path patterns.