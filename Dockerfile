FROM ubuntu

#ENV DEBIAN_FRONTEND=noninteractive
ENV TZ="Europe/Berlin"

# installing texlive and utils

RUN apt-get update

#RUN  apt-get -y install --no-install-recommends texlive texlive-lang-german  texlive-extra-utils texlive-latex-recommended texlive-fonts-extra texlive-latex-extra pandoc

RUN  apt-get -y install texlive-latex-base pandoc texlive-fonts-recommended

RUN groupadd -g 1000 pandoc
RUN useradd -u 1000 -g 1000 -s /bin/bash -m pandoc
USER pandoc

WORKDIR /app

CMD [ "tail", "-f", "/dev/null" ]

# docker compose build
# docker compose up

# md ==> tex
# docker exec b800e7fb2474 pandoc --from=markdown --output=my.tex aus.md --to=latex --standalone

# mx == > odt 
# docker exec b800e7fb2474 pandoc aus.md -f markdown -t odt -s -o MyFile.odt 

# mx == > docx 
# docker exec b800e7fb2474 pandoc -o output.docx -f markdown -t docx aus.md


#  docker exec -it [ID]  /bin/bash


