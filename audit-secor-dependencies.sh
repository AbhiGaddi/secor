#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# This script expects to be run from the root of the 'secor' Maven project.
# For example, if 'secor' is at ~/projects/secor, navigate there and then run this script.

echo "Starting Secor Maven Dependency Security Audit..."

# Ensure Maven is installed
if ! command -v mvn &> /dev/null
then
    echo "Maven is not installed. Please install Maven (e.g., via sdkman) to proceed with the audit." >&2
    exit 1
fi

# Ensure Python3 is installed for report parsing
if ! command -v python3 &> /dev/null
then
    echo "Python3 is not installed. Please install Python3 (version 3.6+) to parse the OWASP report." >&2
    exit 1
fi

# Define report directory
REPORT_DIR="target/security-audit"
mkdir -p "${REPORT_DIR}/owasp-dependency-check"

echo "Step 1/4: Running 'mvn clean verify' to ensure project integrity and resolve dependencies..."
# Run mvn clean verify (non-destructive)
# This builds the project and runs tests, ensuring dependencies are resolved locally.
mvn clean verify

echo "Step 2/4: Generating Maven dependency tree..."
# Generate dependency tree and save to a file
mvn dependency:tree > "${REPORT_DIR}/dependency-tree.txt" 2>&1
echo "Maven dependency tree saved to ${REPORT_DIR}/dependency-tree.txt"

echo "Step 3/4: Running OWASP Dependency-Check Maven plugin..."
# Run OWASP Dependency-Check.
# Using fully qualified goal name to avoid modifying pom.xml for this audit.
# Generates XML and HTML reports in the specified outputDirectory.
mvn org.owasp:dependency-check-maven:check \
    -Dformat=ALL \
    -DoutputDirectory="${REPORT_DIR}/owasp-dependency-check"

echo "OWASP Dependency-Check reports generated in ${REPORT_DIR}/owasp-dependency-check/"
echo "Check the HTML report for detailed visualization: ${REPORT_DIR}/owasp-dependency-check/dependency-check-report.html"

echo "Step 4/4: Parsing OWASP Dependency-Check XML report and generating structured vulnerability summary..."
# Call Python script to parse the XML report and generate a structured summary
# The Python script is expected to be in a 'scripts' subdirectory relative to the project root.
PYTHON_SCRIPT_PATH="scripts/parse_owasp_report.py"

if [ -f "${PYTHON_SCRIPT_PATH}" ]; then
    python3 "${PYTHON_SCRIPT_PATH}" \
        "${REPORT_DIR}/owasp-dependency-check/dependency-check-report.xml" \
        > "${REPORT_DIR}/vulnerability-summary.txt"
    echo "Structured vulnerability summary saved to ${REPORT_DIR}/vulnerability-summary.txt"
else
    echo "Error: Python script not found at '${PYTHON_SCRIPT_PATH}'. Skipping detailed report generation." >&2
    echo "Please manually review the OWASP Dependency-Check reports in ${REPORT_DIR}/owasp-dependency-check/" >&2
fi

echo "\nAudit complete. Review the generated reports in ${REPORT_DIR}/"
echo "  - Full Dependency Tree: ${REPORT_DIR}/dependency-tree.txt"
echo "  - OWASP HTML Report (detailed view): ${REPORT_DIR}/owasp-dependency-check/dependency-check-report.html"
echo "  - OWASP XML Report (raw data): ${REPORT_DIR}/owasp-dependency-check/dependency-check-report.xml"
echo "  - Structured Vulnerability Summary: ${REPORT_DIR}/vulnerability-summary.txt"
