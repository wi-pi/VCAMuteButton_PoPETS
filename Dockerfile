FROM ubuntu:20.04
LABEL Description="Build environment"

ENV HOME /home

ARG DEBIAN_FRONTEND=noninteractive

COPY . /home

SHELL ["/bin/bash", "-c"]

RUN apt-get update && apt-get -y install apt-utils

RUN apt-get update && apt-get -y install \
    build-essential \
    clang \
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
    ca-certificates\
    texlive-fonts-recommended\
    texlive-fonts-extra\
    vim

# Let us add some heavy dependency
RUN cd /home/dynamorio && mkdir build && cd build; cmake ..; make

ENV DYANAMO /home/dynamorio

RUN cd /home && pip3 install -r ./requirements.txt
