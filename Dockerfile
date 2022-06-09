FROM snyk/snyk:node-14

ADD . /opt/snyk
WORKDIR /opt/snyk

# install snyk-to-html
RUN npm install snyk-to-html -g \
    && chmod +x /opt/snyk/entrypoint.sh

VOLUME /var/reports

ENTRYPOINT ["/opt/snyk/entrypoint.sh"]