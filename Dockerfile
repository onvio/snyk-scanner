FROM nikolaik/python-nodejs

ADD . /opt/snyk
WORKDIR /opt/snyk

RUN chmod +x scan.py && \
    python -m pip install -r requirements.txt

# install snyk-to-html
RUN npm install snyk-to-html -g

VOLUME /var/reports
VOLUME /var/src

ENTRYPOINT ["python"]