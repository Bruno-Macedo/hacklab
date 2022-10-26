- [Kubernetes](#kubernetes)
# Kubernetes

- binary:
  - https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/#install-kubectl-binary-with-curl-on-linux

- steps
  - check permisions: kubectl auth can-i --list
  - check configuration: kubectl get node/pods -o yaml
  - Check secrets
  - check folders
  - check git
  - create all allowed pod: https://github.com/BishopFox/badPods/tree/main/manifests/everything-allowed
  - go to host folder
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
    - kubectl auth can-i --list --token=${TOKEN}
    - --token=${TOKEN}
    - kubectl exec -it {NAME_POD} --token=${TOKEN} -- /bin/bash => get session

  
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
- 

