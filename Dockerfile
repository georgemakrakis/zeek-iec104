FROM zeekurity/zeek:5.0.3
ARG DEBIAN_FRONTEND=noninteractive

RUN apt update
RUN apt install libpcap-dev g++ cmake -y
