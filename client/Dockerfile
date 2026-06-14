FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    wpasupplicant \
    iproute2 \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY wpa_supplicant.conf /etc/wpa_supplicant/wpa_supplicant.conf
COPY start_client.sh /start_client.sh
RUN chmod +x /start_client.sh

CMD ["/start_client.sh"]
