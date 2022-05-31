#!/usr/bin/python

import os
import docker
import sys
import logging
import shutil
import subprocess


def main():
    if len(sys.argv) != 3:
        logging.error("Provide a snyk token")
        sys.exit(1)

    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s',
                        datefmt='[%Y-%m-%d %H:%M:%S]', level="INFO")

    # Because Snyk uses hardcoded mount in /app
    project_path = "/var/src/"
    report_path = "/var/reports/"
    host_project_path = sys.argv[1]
    snyk_token = sys.argv[2]
    masked_snyk_token = len(snyk_token[:-8])*"*"+snyk_token[-8:]

    logging.info(f"Starting Snyk scan")
    logging.info(f"project_path: {project_path}")
    logging.info(f"report_path: {report_path}")
    logging.info(f"snyk_token: {masked_snyk_token}")
    
    run_snyk_all_projects(host_project_path, snyk_token)

    logging.info("Creating Snyk HTML report from json")

    subprocess.call(["snyk-to-html", "-i", f"{project_path}/snyk-result.json", "-o", f"{project_path}/snyk_report.html"])

    logging.info("Moving results to report directory")
    
    move_report_file(project_path, report_path, 'snyk-result.json')
    move_report_file(project_path, report_path, 'snyk_report.html')

    logging.info("Finished")

def run_snyk_all_projects(source_path, snyk_token):
    try:
        docker_tag = "linux"
        repo = "snyk/snyk" # https://hub.docker.com/r/snyk/snyk
        image = f"{repo}:{docker_tag}"
        command = f"snyk test --all-projects --skip-unresolved --detection-depth=6 --strict-out-of-sync=false --json-file-output=/app/snyk-result.json"

        logging.info(
            f"Pulling image {image}")

        client = docker.from_env()
        client.images.pull(image)

        logging.info(
            f"Running Snyk docker scan: docker run {image} {command}")

        client.containers.run(image,
                              command=command,
                              detach=False,
                              user=os.getuid(),
                              tty=True,
                              volumes={
                                  source_path: {
                                    'bind': '/app', 
                                    'mode': 'rw'
                                  }
                              },
                              auto_remove=True,
                              environment=[f"SNYK_TOKEN={snyk_token}"])
    except docker.errors.ContainerError as ex:
        if ex.exit_status == 1:
            logging.warning(
                f"Container exit code {ex.exit_status}: vulnerabilities found")
        if ex.exit_status == 2:
            logging.error(f"Container exit code {ex.exit_status}: ERROR")
        if ex.exit_status == 3:
            logging.warning(
                f"Container exit code {ex.exit_status}: No supported manifests found")
    except docker.errors.ImageNotFound as ex:
        logging.error(f"Snyk image not found: {ex}")


def move_report_file(from_path, to_path, file):
    try:
        shutil.move(os.path.join(from_path, file), os.path.join(to_path, file))
    except shutil.SameFileError:
        pass
    except FileNotFoundError:
        pass


if __name__ == "__main__":
    main()
