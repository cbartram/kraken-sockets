# kraken-sockets
A TCP server for handling network traffic for the Socket Plugin.

## Deployment

Deployment is managed through helm there are a few things to handle manually:

- Add `--tcp-services-configmap=ingress-nginx/tcp-services` to the `ingress-nginx` controller deployment
- Add the following to the `ingress-nginx-controller` service 
```yaml
- name: socket
  port: 26388
  protocol: TCP
  targetPort: 26388
```

Finally build your docker image with: `./scripts/build.sh 0.0.1` and deploy with `./scripts/upgrade.sh` 