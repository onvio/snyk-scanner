# Monolith Snyk Scanner

This project automatically finds all manifest files and runs a Snyk scan for each manifest. It will merge all results into a single report.

Example run:
```
docker run -v /var/run/docker.sock:/var/run/docker.sock -v $(pwd):/var/src -v $(pwd):/var/reports --rm -t snyktest scan.py $(pwd) <snyk-token>
```

A shared socket is required because this Docker container will start new Snyk containers.
