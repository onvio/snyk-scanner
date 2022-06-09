# Snyk Scanner with HTML and Json Report

This project runs a Snyk scan and outputs an HTML and JSON report.

Example run:
```
docker run --rm -v $(pwd):/app -v $(pwd):/var/reports -t snyktest <snyk-token>
```
