FROM fedimint/fedimintd:f8717727bebabfcca4ebf4963d07f98e1d580742
EXPOSE 8176
CMD fedimintd /var/fedimint pass0 --listen-ui 0.0.0.0:8176
