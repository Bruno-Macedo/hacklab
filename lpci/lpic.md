# LPIC 1 - Cheat Sheet

- [Docker OpenSuse](https://github.com/alvistack/docker-opensuse)
```
docker run \
    -itd \
    --name opensuse \
    --publish 2222:22 \
    alvistack/opensuse-leap-15.5

ssh root@localhost -p 2222
```

- Docker CentOS
```
docker run -it --rm adevur/centos-8:latest /bin/bash


```