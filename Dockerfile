#FROM zeekurity/zeek:5.0.3

# They have moved the new versions to the Dockerhub repo below
#FROM zeek/zeek:6.0.0

FROM zeek/zeek:8.0.0

#FROM zeek/zeek:7.2

# FROM zeek/zeek:6.1
# FROM zeek/zeek:latest
ARG DEBIAN_FRONTEND=noninteractive

RUN apt update
RUN apt install libpcap-dev g++ cmake -y
RUN apt install wget nano -y