FROM ubuntu:24.10

COPY ansible_collections.yaml /
COPY ansible_roles.yaml /
COPY requirements.txt /

RUN mkdir /repo\
    && apt-get update\
    && apt-get install -y git python3 python3-pip jq\
    && pip3 install --break-system-packages -r requirements.txt

RUN ansible-galaxy collection install -r ansible_collections.yaml\
    && ansible-galaxy install -r ansible_roles.yaml

WORKDIR /repo

ENTRYPOINT ["/bin/bash", "-c"]
