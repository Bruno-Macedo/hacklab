FROM python:latest

#ENV DEBIAN_FRONTEND=noninteractive
ENV TZ="Europe/Berlin" \
    FRONTEND=noninteractive

WORKDIR /app

RUN pip install requests

#CMD [ "python3", "firepwd.py", "/dev/null" ]

CMD [ "tail", "-f", "/dev/null" ]

#CMD [ "python3", -c, "50128.py", "http://10.10.83.162:8080/oscommerce-2.3.4/catalog"]
