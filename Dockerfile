FROM ubuntu:20.04
LABEL Description="Build environment"

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get -y install apt-utils

ENV HOME /home

COPY . /home

SHELL ["/bin/bash", "-c"]

RUN apt-get update && apt-get -y install \
    build-essential \
    binutils\
    perl\
    gcc \
    gcc-multilib\
    clang\
    cmake \
    gdb \
    wget \
    python3\
    python3-pip\
    portaudio19-dev\
    g++\
    g++-multilib\
    doxygen\
    git\
    zlib1g-dev\
    libunwind-dev\ 
    libsnappy-dev\ 
    liblz4-dev\
    libsndfile1-dev\
    ca-certificates\
    vim

# Let us add some heavy dependency
RUN cd /home/dynamorio && mkdir build && cd build; cmake ..; make -j

ENV DYANAMO /home/dynamorio/build

RUN cd /home && pip3 install -r ./requirements.txt
