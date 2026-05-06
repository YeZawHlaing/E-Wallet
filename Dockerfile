FROM ubuntu:latest
LABEL authors="kali"

ENTRYPOINT ["top", "-b"]