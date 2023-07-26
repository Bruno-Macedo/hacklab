FROM ubuntu

#ENV DEBIAN_FRONTEND=noninteractive
ENV TZ="Europe/Berlin"

# installing texlive and utils

RUN apt-get update
#RUN  apt-get -y install --no-install-recommends pandoc texlive texlive-latex-extra texlive-genzzperic-extra texlive-extra-utils texlive-fonts-extra texlive-bibtex-extra biber latexmk make git procps locales curl
RUN  apt-get -y install --no-install-recommends texlive texlive-lang-german texlive-latex-extra texlive-extra-utils

RUN groupadd -g 1000 latexuser
RUN useradd -u 1000 -g 1000 -s /bin/bash -m latexuser
USER latexuser

WORKDIR /app

CMD [ "tail", "-f", "/dev/null" ]

# docker compose build
# docker compose up
# docker exec f6362b753b0e ./latexcompile -g -r -b 0_bachelorarbeit.tex
# docker exec 7ec29e4e763d ./latexcompile -g -r -b 0_bachelorarbeit.tex

#  docker exec -it [ID]  /bin/bash

#cp Bachelorarbeit/0_bachelorarbeit.pdf /mnt/c/Users/bruno/Dropbox/Estudos_Avancados/Angewandte_Informatik/Praxissemester_Bachelorarbeit/Macedo_da_Silva_Bruno_Bacherlorarbeit.pdf

#7ec29e4e763d