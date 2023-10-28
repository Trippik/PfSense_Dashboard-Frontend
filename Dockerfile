FROM python:latest

MAINTAINER Cameron Trippick "trippickc@gmail.com"

RUN apt-get update -y && \
    apt-get install -y python3-pip python3-dev


COPY ./requirements.txt /requirements.txt

COPY ./setup.py /setup.py

COPY . /

WORKDIR /

RUN pip install -r requirements.txt

RUN python3 setup.py install

CMD [ "PfSense_Dashboard-Frontend" ]