FROM ubuntu:18.04
LABEL Description="Build environment"

ENV HOME /root

SHELL ["/bin/bash", "-c"]

RUN apt-get update && apt-get -y --no-install-recommends install \
    build-essential \
    clang \
    cmake \
    gdb \
    wget \
    portaudio19-dev 

# Let us add some heavy dependency
RUN cd ${HOME}/scripts/data_collection/Linux/DyanamoRIO_Example_Files && make