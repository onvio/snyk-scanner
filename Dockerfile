FROM python:3.8.6-slim-buster

ADD . /opt/snyk
WORKDIR /opt/snyk

RUN chmod +x scan.py && \
    python -m pip install -r requirements.txt

VOLUME /var/reports
VOLUME /var/src

ENTRYPOINT ["python"]