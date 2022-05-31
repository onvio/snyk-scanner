#!/usr/bin/python

import os
import docker
import sys
import logging
import json
import shutil

# https://github.com/snyk/snyk/blob/master/src/lib/detect.ts
# for snyk/snyk-cli images (https://hub.docker.com/r/snyk/snyk-cli)
manifest_dict = {
    "yarn.lock": "npm",
    "package-lock.json": "npm",
    "package.json": "npm",
    "gemfile": "rubygems",
    "gemfile.lock": "rubygems",
    "pom.xml": "maven-3.5.4",
    "build.gradle": "gradle-5.4",
    "build.gradle.kts": "gradle-5.4",
    "build.sbt": "sbt-1.0.4",
    "requirements.txt": "python-3",
    "gopkg.lock": "npm",
    "go.mod": "npm",
    "vendor.json": "npm",
    "project.json": "nuget",
    "project.assets.json": "nuget",
    "packages.config": "nuget",
    "paket.dependencies": "nuget",
    "composer.lock": "npm",
    "podfile": "npm",
    "podfile.lock": "npm",
    "pipfile": "python-3",
    "pipfile.lock": "python-3",
    "pyproject.toml": "python-3",
    'poetry.lock': "python-3",
    # "dockerfile" : "docker",
}


def main():
    if len(sys.argv) != 3:
        logging.error("Provide a snyk token")
        sys.exit(1)

    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s',
                        datefmt='[%Y-%m-%d %H:%M:%S]', level="INFO")

    # Because Snyk uses hardcoded mount in /project
    project_path = "/var/src/"
    report_path = "/var/reports/"
    host_project_path = sys.argv[1]
    snyk_token = sys.argv[2]
    masked_snyk_token = len(snyk_token[:-8])*"*"+snyk_token[-8:]

    logging.info(f"Starting Snyk scan")
    logging.info(f"project_path: {project_path}")
    logging.info(f"report_path: {report_path}")
    logging.info(f"snyk_token: {masked_snyk_token}")

    logging.info("Trying to find manifest files")
    manifest_files = find_manifests(project_path)
    results = None
    snyk_result_path = os.path.join(project_path, 'snyk-result.json')
    for docker_tag, manifest_list in manifest_files.items():
        # We run a scan for each found manifest, because Snyk has issues with scanning all manifests at once.
        for manifest in manifest_list:
            run_snyk(host_project_path, snyk_token, docker_tag, manifest)
            results = append_results(snyk_result_path, results)

    logging.info("Writing results")
    with open(snyk_result_path, 'w') as snyk_result_file:
        json.dump(results, snyk_result_file)

    logging.info("Moving results to report directory")

    move_report_file(project_path, report_path, 'snyk-result.json')
    move_report_file(project_path, report_path, 'snyk-error.log')
    move_report_file(project_path, report_path, 'snyk_report.html')
    move_report_file(project_path, report_path, 'snyk_report.css')

    logging.info("Finished")

def run_snyk(source_path, snyk_token, docker_tag, manifest=None):
    try:
        repo = "snyk/snyk-cli" # https://hub.docker.com/r/snyk/snyk-cli
        # repo = "snyk/snyk" # https://hub.docker.com/r/snyk/snyk
        image = f"{repo}:{docker_tag}"
        manifest_file = manifest.replace("\\", "/").replace("./", "")
        command = f"test --file={manifest_file} --skip-unresolved"

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
                                    'bind': '/project', 
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


def append_results(snyk_result_path, results):
    try:
        with open(snyk_result_path) as snyk_result_file:
            snyk_result_json = json.load(snyk_result_file)
            if 'vulnerabilities' in snyk_result_json:
                nr_of_vulnerabilities = len(
                    snyk_result_json['vulnerabilities'])
                if not results:
                    results = snyk_result_json
                    logging.info(f'set {nr_of_vulnerabilities} vulns')
                elif nr_of_vulnerabilities > 0:
                    results['vulnerabilities'].extend(
                        snyk_result_json['vulnerabilities'])
                    logging.info(
                        f'appended {nr_of_vulnerabilities} vulns')
            else:
                logging.error(
                    f'No vulns in json: {snyk_result_json}')
    except Exception as ex:
        logging.error(
            f"Error reading results file {snyk_result_path} {ex}")

    return results

def find_manifests(project_path):
    manifest_files = dict()

    for manifest, docker_tag in manifest_dict.items():
        for p, d, f in os.walk(project_path):
            for file in f:
                if file.lower() == manifest and "node_modules" not in p and "vendor" not in p:
                    if docker_tag not in manifest_files:
                        manifest_files[docker_tag] = []
                    path = os.path.join(os.path.relpath(p, project_path), file)
                    manifest_files[docker_tag].append(path)
                    print(f"Found manifest: {path}")

    return manifest_files


if __name__ == "__main__":
    main()
