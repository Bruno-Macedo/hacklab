FROM ubuntu:latest 

ARG DEBIAN_FRONTEND=noninteractive

#ENV DEBIAN_FRONTEND=noninteractive
ENV TZ="Europe/Berlin" \
    FRONTEND=noninteractive

# Set timezone
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update && apt-get install --no-install-recommends -y python3.9  
#RUN apt-get update && apt-get install --no-install-recommends -y python3.9-dev 
RUN apt-get update && apt-get install --no-install-recommends -y python3-pip 
RUN apt-get update && apt-get install --no-install-recommends -y python3-wheel 
RUN apt-get update && apt-get install --no-install-recommends -y build-essential
#RUN apt-get install -y python3 python3-pip sudo wget curl 
#RUN pip install virtualenv

RUN apt-get clean && rm -rf /var/lib/apt/lists/*
# create and activate virtual environment
# using final folder name to avoid path issues with packages
#RUN python3 -m venv /home/myuser/venv
#ENV PATH="/home/myuser/venv/bin:$PATH"

#RUN useradd --create-home myuser
RUN useradd --create-home myuser && echo "myuser:myuser" | chpasswd && adduser myuser sudo
#COPY --from=builder-image /home/myuser/venv /home/myuser/venv

USER myuser
#RUN pip install requests
WORKDIR /home/myuser/app

# python script to convert nmal result to markdonw
RUN git clone git@github.com:vdjagilev/nmap2md.git

# make sure all messages always reach console
ENV PYTHONUNBUFFERED=1

## activate virtual environment
#ENV VIRTUAL_ENV=/home/myuser/venv
#ENV PATH="/home/myuser/venv/bin:$PATH"

CMD [ "tail", "-f", "/dev/null" ]

# ====================== basic ======================
# docker compose build
# docker compose up
# docker exec -it PythonLearn bash


