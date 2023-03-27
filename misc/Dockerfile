FROM fedimint/fedimintd:master
WORKDIR /var/fedimint
COPY . .
RUN fedimintd /var/fedimint pass0 --listen-ui 0.0.0.0:8176
EXPOSE 8176
