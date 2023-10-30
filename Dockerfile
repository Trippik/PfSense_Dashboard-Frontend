FROM ubuntu:latest

RUN apt-get update -y && \
    apt-get install -y python3-dev && \
    apt-get install -y python3-pip

COPY ./requirements.txt /requirements.txt

COPY ./setup.py /setup.py

COPY . /

WORKDIR /

RUN pip3 install -r requirements.txt

RUN python3 setup.py install

CMD [ "PfSense_Dashboard-Frontend" ]