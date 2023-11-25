FROM alpine:latest

RUN apk update

RUN apk add python3

RUN apk add py-pip

COPY ./requirements.txt /requirements.txt

COPY ./setup.py /setup.py

COPY . /

WORKDIR /

RUN pip3 install -r requirements.txt

RUN python3 setup.py install

CMD [ "PfSense_Dashboard-Frontend" ]