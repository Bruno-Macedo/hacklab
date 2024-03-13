- [TMUX cheat sheet](#tmux-cheat-sheet)
- [Docker](#docker)
- [Python venv](#python-venv)
- [Cloud](#cloud)
  - [ScoutScuit](#scoutscuit)
  - [CloudFox](#cloudfox)

## TMUX cheat sheet
- tmux
- tmux new
  
- tmux new
  - -s SESSIONNAME
  - ctrl + b $ = rename

- Detach | reattach
  - -d
  - tmux attach 
  - tmux attach -d -t name

- tmux kill-ses -t session
- tmux kill-session -a = kil all

- ctrb +b $: new window

- Variables
	- tmux setenv VARIABLE value
	- export Variable=value
	- tmux showenv = display variables
	-  tmux show-environment VARIABLE
- show all
  - tmux a

- Split ctr+b
  - %: vertical
  - ": horizontal
  - x: kill pane

- set Mouse
  - ctr + b + :
    - setw -g mouse on

- New window
  - ctr+b +c
  - ctr+b +n = move to window
  - ctr*b 1,n = to window number
  - ctr+b +w = list windows
  
- 
## Docker
- Create and run
  - docker compose build
  - docker compose up -d
  - docker exec -it PythonLearn bash

- docker pandoc:
```
docker exec 7b4294cce723 pandoc FOLDER/OSCP_Report_REPORT_THM.md \
-o OSCP_Report_REPORT_THM.pdf \
--from markdown+yaml_metadata_block+raw_html \
--template eisvogel \
--table-of-contents \
--toc-depth 6 \
--number-sections \
--top-level-division=chapter \
--highlight-style pygments \
--resource-path=.:src

docker exec 7b4294cce723 pandoc OSCP_Report_Steel_Mountail_THM.md \
-o OSCP_Report_REPORT_THM.pdf \
--from markdown+yaml_metadata_block+raw_html \
--template eisvogel \
--table-of-contents \
--toc-depth 6 \
--number-sections \
--top-level-division=chapter \
--highlight-style pygments \
--resource-path=.:src
```

- docker remove
- Docker remove all images
  - docker rmi $(docker images --filter "dangling=true" -q --no-trunc)
  - docker rmi $(docker images -q) -f
  - docker rm $(docker ps -a -q)
  - docker system prune
    - docker system prune --all --force --volumes


## Python venv
- python -m venv /path
- source bin/activate
- deactivate
  
## Cloud
### ScoutScuit
- [Scoutsout](https://github.com/nccgroup/ScoutSuite)
- 
```
virtualenv -p python3 venv
source venv/bin/activate
pip install scoutsuite
scout --help

#GCP
gcloud auth login
gcloud auth application-default login


scout.py gcp --user-account
scout.py gcp --service-account </PATH/TO/KEY_FILE.JSON>
scout.py gcp --user-account --all-subscription
```

### CloudFox
- [CloudFox](https://github.com/BishopFox/cloudfox)
  - Limited to AWS and Azure