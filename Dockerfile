# Base image
FROM --platform=linux/amd64 ubuntu:22.04

SHELL ["/bin/bash", "-c"]
ENV DEBIAN_FRONTEND="noninteractive" \
  DATABASE="postgres"
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV GOROOT="/usr/local/go"
ENV GOPATH=$HOME/go
ENV PATH="${PATH}:${GOROOT}/bin:${GOPATH}/bin"

RUN apt update -y && \
  apt install -y \
  python3.10 \
  python3-dev \
  python3-pip

RUN alias python=python3

RUN apt install -y  --no-install-recommends \
  build-essential \
  cmake \
  geoip-bin \
  geoip-database \
  gcc \
  git \
  libpq-dev \
  libpango-1.0-0 \
  libpangoft2-1.0-0 \
  libpcap-dev \
  netcat \
  nmap \
  x11-utils \
  xvfb \
  wget \
  curl \
  python3-netaddr \
  software-properties-common

RUN wget https://golang.org/dl/go1.21.4.linux-amd64.tar.gz
RUN tar -xvf go1.21.4.linux-amd64.tar.gz
RUN rm go1.21.4.linux-amd64.tar.gz
RUN mv go /usr/local

ENV NGINE_HOME=/usr/src/app

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN go install github.com/tomnomnom/assetfinder@latest
RUN go install github.com/hakluke/hakrawler@latest
RUN go install github.com/dwisiswant0/cf-check@latest
RUN go install github.com/lc/gau@latest
RUN go install github.com/jaeles-project/jaeles@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@221eee8e0891c1bdae1228eb7068aa7b033d8483
RUN go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
RUN go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN go install github.com/ffuf/ffuf/v2@latest
RUN	go install github.com/dwisiswant0/cf-check@latest


RUN nuclei -update
RUN nuclei -update-templates

RUN httpx -up
RUN naabu -up

RUN pip install aiodnsbrute
COPY ./requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt


RUN echo 'alias httpx=/go/bin/httpx' >> ~/.bashrc
RUN echo 'alias python=python3' >> ~/.bashrc


RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app/
RUN apt-get install jq -y
RUN apt-get install chromium-browser -y
COPY . /usr/src/app
RUN mkdir -p /usr/src/app/tools/scan_results/dev_results

RUN chmod +x /usr/src/app/tools/get_subdomain.sh
RUN chmod +x /usr/src/app/tools/get_dirs.sh
RUN chmod +x /usr/src/app/tools/get_urls.sh
RUN chmod +x /usr/src/app/tools/takeover.sh
RUN chmod +x /usr/src/app/tools/do_masscan.sh
RUN chmod +x /usr/src/app/tools/do_scan.sh
RUN chmod +x /usr/src/app/tools/jaeles.sh
RUN chmod +x /usr/src/app/celery-entrypoint.sh

WORKDIR /usr/src/app/tools/massdns
RUN make all


WORKDIR /usr/src/app/tools/masscan
RUN make clean
RUN make all

WORKDIR /usr/src/app/
RUN apt install libpq-dev \
  libpango-1.0-0 \
  libpangoft2-1.0-0 \
  libpcap-dev
ENTRYPOINT ["/usr/src/app/docker-entrypoint.sh"]
