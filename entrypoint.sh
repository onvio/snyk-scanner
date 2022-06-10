#!/bin/bash

cd /app/

export SNYK_TOKEN=$1

echo "Running snyk test"

snyk test --all-projects --skip-unresolved --detection-depth=6 --strict-out-of-sync=false --json-file-output=/var/reports/snyk-result.json

echo "Converting JSON report to HTML"

snyk-to-html -i /var/reports/snyk-result.json -o /var/reports/snyk_report.html

echo "Done"
