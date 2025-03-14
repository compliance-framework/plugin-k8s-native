# Compliance Framework K8s native plugin

## Prerequisites

* GoReleaser https://goreleaser.com/install/

## Building

Once you are ready to serve the plugin, you need to build the binaries which can be used by the agent.

```shell
goreleaser release --snapshot --clean
```

## Configure with minikube

Spin minikube using `minikube start`. If you want minikube to be accessible from other devices on your network use the `--network=bridged` flag.

Create an nginx deployment and apply the below YAML file to create an nginx deployment `kubectl apply -f nginx-deployment.yaml`

Example nginx deployment:

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: ubuntu:jammy
        command: ["/bin/bash", "-c", "sleep infinity"]
        tty: true
        ports:
        - containerPort: 80
```

Execute a shell session inside one of the Nginx pods using `kubectl exec -it <pod-name> -- bash`

Create a directory inside the pod `mkdir /app`

Copy the compiled agent and plugin into the the app directory, as well as the config.yaml and policies, for example `kubectl cp plugin default/<pod-name>:/app/`. This example assumes the default namespace. If using a different namespace, please specify.

Run the agent within the kubernetes pod using `./agent agent -c config.yaml`