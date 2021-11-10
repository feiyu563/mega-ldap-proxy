FROM centos:7

LABEL maintainer="jikun.zhang"

WORKDIR /app

COPY mega-ldap-proxy mega-ldap-proxy

COPY conf conf

COPY proxystatic proxystatic

COPY views views

CMD [ "./mega-ldap-proxy" ]
