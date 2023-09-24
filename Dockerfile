FROM ubuntu:latest

#ENV DEBIAN_FRONTEND=noninteractive
ENV TZ="Europe/Berlin" \
    FRONTEND=noninteractive

# Set timezone
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# installing texlive and utils
RUN apt-get -y update && apt-get upgrade -y && apt-get install -y apt-transport-https

# Original
RUN apt-get install -y texlive-latex-recommended texlive-fonts-extra texlive-latex-extra pandoc p7zip

RUN groupadd -g 1000 pandoc
RUN useradd -u 1000 -g 1000 -s /bin/bash -m pandoc
USER pandoc

WORKDIR /app
CMD [ "tail", "-f", "/dev/null" ]

# ====================== basic ======================
# docker compose build
# docker compose up

# md ==> tex
# docker exec e9448ec1f35f pandoc --from=markdown --output=my.tex aus.md --to=latex --standalone

# mx == > odt 
# docker exec 7b4294cce723 pandoc OSCP_Report_Blaster_THM.md -f markdown -t odt -s -o OSCP_Report_Blaster_THM.odt

# mx == > docx 
# docker exec a2298eec75b0 pandoc -o OSCP_Wreath_THM.docx -f markdown -t docx OSCP_Wreath_THM.md

#docker exec a2298eec75b0 pandoc/extra example.md -o example.pdf --template eisvogel --listings
#sudo docker run -it 66541b82fa7e  /bin/bash

# docker cp /home/bruno/git/hacklab/Notes/Eisvogel/eisvogel.latex hacklab_latex_1:/usr/share/pandoc/data/templates/

# docker exec 7b4294cce723 pandoc FOLDER/OSCP_Report_REPORT_THM.md \
# -o OSCP_Report_REPORT_THM.pdf \
# --from markdown+yaml_metadata_block+raw_html \
# --template eisvogel \
# --table-of-contents \
# --toc-depth 6 \
# --number-sections \
# --top-level-division=chapter \
# --highlight-style pygments \
# --resource-path=.:src

# STYLE
# - pygments
# - tango
# - espresso -Header+Footnote (email number)
# - zenburn
# - kate
# - monochrome
# - breezedark -Header+Footnote (email number)
# - haddock
# docker exec 7b4294cce723 pandoc --list-highlight-styles



# ==================================================