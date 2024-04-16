FROM ubuntu:latest 

ARG DEBIAN_FRONTEND=noninteractive

#ENV DEBIAN_FRONTEND=noninteractive
ENV TZ="Europe/Berlin" \
    FRONTEND=noninteractive

# Set timezone
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update && apt-get install --no-install-recommends -y python3.9 \  
    build-essential \
    curl \
    git\
    libbz2-dev \
    libffi-dev \
    liblzma-dev \
    libncurses5-dev \
    libncursesw5-dev \
    libreadline-dev \
    libsqlite3-dev \
    libssl-dev \
    llvm \
    make \
    p7zip-full\
    p7zip-rar\ 
    python3-openssl \
    python3-pip \
    python3-wheel \
    sudo \
    tk-dev \
    unzip \
    wget \
    xz-utils \
    zip\
    zlib1g-dev 

RUN apt-get clean && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get upgrade

RUN pip install requests

#RUN curl https://pyenv.run | bash
#RUN echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.zshrc
#RUN echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.zshrc
#RUN echo -e 'if command -v pyenv 1>/dev/null 2>&1; then\n  eval "$(pyenv init --path)"\nfi' >> ~/.zshrc

#RUN pyenv install 2.7.18 
#RUN pyenv global 2.7.18

#RUN useradd --create-home myuser
RUN useradd --create-home myuser && echo "myuser:myuser" | chpasswd && adduser myuser sudo
#COPY --from=builder-image /home/myuser/venv /home/myuser/venv

USER myuser
#RUN pip install requests
WORKDIR /home/myuser/app



# python script to convert nmal result to markdonw
#RUN git clone git@github.com:vdjagilev/nmap2md.git

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


