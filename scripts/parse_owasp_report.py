import sys
import xml.etree.ElementTree as ET

# Define XML namespace for easier parsing. This must match the namespace in the XML report.
# The version in the namespace might change, so it's good practice to inspect the generated XML.
# For current OWASP Dependency Check versions, this is typical.
NAMESPACE = {'ns': 'https://jeremylong.github.io/DependencyCheck/dependency-check.2.7.xsd'}

def get_severity_score_and_category(vulnerability_node):
    """Extracts CVSS v3 base score if available, otherwise CVSS v2, and categorizes severity."""
    base_score = 0.0
    severity_text = "N/A"

    # Prioritize CVSSv3
    cvssv3 = vulnerability_node.find('ns:cvssv3', NAMESPACE)
    if cvssv3 is not None:
        score_node = cvssv3.find('ns:baseScore', NAMESPACE)
        severity_node = cvssv3.find('ns:baseSeverity', NAMESPACE)
        if score_node is not None and score_node.text:
            try:
                base_score = float(score_node.text)
            except ValueError:
                pass
        if severity_node is not None and severity_node.text:
            severity_text = severity_node.text.upper()

    # Fallback to CVSSv2 if v3 is not available or has no score
    if base_score == 0.0:
        cvssv2 = vulnerability_node.find('ns:cvssv2', NAMESPACE)
        if cvssv2 is not None:
            score_node = cvssv2.find('ns:baseScore', NAMESPACE)
            severity_node = cvssv2.find('ns:severity', NAMESPACE)
            if score_node is not None and score_node.text:
                try:
                    base_score = float(score_node.text)
                except ValueError:
                    pass
            if severity_node is not None and severity_node.text:
                severity_text = severity_node.text.upper()
    
    # Manual categorization based on CVSS score if text severity is not clear or missing
    if severity_text == "N/A" or severity_text == "UNKNOWN":
        if base_score >= 9.0:
            severity_text = "CRITICAL"
        elif base_score >= 7.0:
            severity_text = "HIGH"
        elif base_score >= 4.0:
            severity_text = "MEDIUM"
        elif base_score > 0.0:
            severity_text = "LOW"
        else:
            severity_text = "INFO"
            
    return base_score, severity_text

def get_remediation_suggestion(vulnerability_node):
    """Extracts remediation suggestion from the vulnerability node."""
    remediation_node = vulnerability_node.find('ns:remediation', NAMESPACE)
    if remediation_node is not None:
        recommendation = remediation_node.find('ns:recommendation', NAMESPACE)
        if recommendation is not None and recommendation.text:
            return recommendation.text.strip()
        
        fixes_node = remediation_node.find('ns:fixes', NAMESPACE)
        if fixes_node is not None:
            fix_versions = []
            for fix in fixes_node.findall('ns:fix', NAMESPACE):
                versions_node = fix.find('ns:versions', NAMESPACE)
                if versions_node is not None:
                    for version_node in versions_node.findall('ns:version', NAMESPACE):
                        if version_node.text:
                            fix_versions.append(version_node.text.strip())
            if fix_versions:
                return f"Upgrade to version(s): {', '.join(fix_versions)} or later."

    return "No specific remediation suggestion available. Consult CVE details."

def parse_report(xml_file_path):
    """Parses the OWASP Dependency-Check XML report and returns structured vulnerabilities."""
    try:
        tree = ET.parse(xml_file_path)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"Error parsing XML file {xml_file_path}: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print(f"Error: XML file not found at {xml_file_path}", file=sys.stderr)
        sys.exit(1)

    vulnerabilities = {
        "CRITICAL": [],
        "HIGH": [],
        "MEDIUM": [],
        "LOW": [],
        "INFO": []
    }

    dependencies = root.find('ns:dependencies', NAMESPACE)
    if dependencies is None:
        print("Warning: No 'dependencies' section found in the XML report.", file=sys.stderr)
        return vulnerabilities # No dependencies section found

    for dependency in dependencies.findall('ns:dependency', NAMESPACE):
        file_name_node = dependency.find('ns:fileName', NAMESPACE)
        # artifact_id_node = dependency.find('ns:identifiers/ns:identifier[@type="maven"]/ns:value', NAMESPACE) # More robust identifier
        
        artifact_name = file_name_node.text if file_name_node is not None else "Unknown artifact (filename missing)"

        vuln_nodes = dependency.find('ns:vulnerabilities', NAMESPACE)
        if vuln_nodes is not None:
            for vuln in vuln_nodes.findall('ns:vulnerability', NAMESPACE):
                cve_id_node = vuln.find('ns:name', NAMESPACE)
                cve_id = cve_id_node.text if cve_id_node is not None else "N/A"
                
                cvss_score, severity_category = get_severity_score_and_category(vuln)
                remediation = get_remediation_suggestion(vuln)
                
                # The full dependency path (e.g., A -> B -> C) is not directly in the OWASP XML for the vulnerable component.
                # It identifies the artifact itself. Users need to cross-reference dependency-tree.txt for full context.
                dependency_path_note = f"Vulnerable artifact: {artifact_name} (Refer to target/security-audit/dependency-tree.txt for full path)"

                # Direct analysis from pom.xml is not explicitly done here, but the artifact name is provided.
                # A more advanced solution would parse pom.xml or use Maven plugins to link pom entries to CVEs.

                vulnerabilities[severity_category].append({
                    "cve_id": cve_id,
                    "severity_score": cvss_score,
                    "dependency_path": dependency_path_note,
                    "remediation_suggestion": remediation
                })
    
    return vulnerabilities

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 scripts/parse_owasp_report.py <path_to_dependency-check-report.xml>", file=sys.stderr)
        sys.exit(1)

    xml_file = sys.argv[1]
    
    parsed_vulnerabilities = parse_report(xml_file)

    print("Secor Maven Dependency Security Audit Report\n")
    print("============================================\n")
    print("This report summarizes vulnerabilities found by OWASP Dependency-Check.\n")
    print("For a detailed visualization and full dependency tree context, please refer to:")
    print("  - HTML Report: target/security-audit/owasp-dependency-check/dependency-check-report.html")
    print("  - Maven Dependency Tree: target/security-audit/dependency-tree.txt\n")

    # Order by severity: Critical, High, Medium, Low (as per requirements)
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    has_vulnerabilities = False
    for severity in severity_order:
        if parsed_vulnerabilities[severity]:
            has_vulnerabilities = True
            print(f"--- {severity} VULNERABILITIES ({len(parsed_vulnerabilities[severity])}) ---
")
            for vuln in parsed_vulnerabilities[severity]:
                print(f"  CVE ID: {vuln['cve_id']}")
                print(f"  Severity Score (CVSS): {vuln['severity_score']:.1f} ({severity})")
                print(f"  Dependency Path: {vuln['dependency_path']}")
                print(f"  Remediation Suggestion: {vuln['remediation_suggestion']}\n")
            print("---" * 20 + "\n")
        else:
            print(f"--- No {severity} vulnerabilities found. ---
")

    # Include INFO findings if any, for completeness, but after the main categories
    if parsed_vulnerabilities.get("INFO") and parsed_vulnerabilities["INFO"]:
        has_vulnerabilities = True
        print(f"--- INFORMATIONAL FINDINGS ({len(parsed_vulnerabilities['INFO'])}) ---
")
        for vuln in parsed_vulnerabilities['INFO']:
            print(f"  CVE ID: {vuln['cve_id']}")
            print(f"  Severity Score (CVSS): {vuln['severity_score']:.1f} (INFO)")
            print(f"  Dependency Path: {vuln['dependency_path']}")
            print(f"  Remediation Suggestion: {vuln['remediation_suggestion']}\n")
        print("---" * 20 + "\n")

    if not has_vulnerabilities:
        print("No critical, high, medium, or low severity vulnerabilities found.")

if __name__ == "__main__":
    main()
