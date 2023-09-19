# Webhooks

This repo contains an example webhook server in Go compatible with [step-ca provisioner webhooks.](https://smallstep.com/docs/step-ca/webhooks)

## Requirements

1. [Install Go](https://go.dev/doc/install)
2. Generate a certificate for the server available at the paths `webhook.crt` and `webhook.key`: `step ca certificate localhost webhook.crt webhook.key`
3. Provide your authority's root cert at `root_ca.crt`: `step ca root > root_ca.crt`.
4. Update the [secrets](https://github.com/smallstep/webhooks/blob/f6a74c2e30dcb19b15d9903fdb6271a8358d26cd/main.go#L31) and [db](https://github.com/smallstep/webhooks/blob/f6a74c2e30dcb19b15d9903fdb6271a8358d26cd/main.go#L26) maps with your own webhook secret and entity.
5. Start the server with `go run main.go`.
 
This webhook server expects a request to `/<email>` and returns data containg a role that may be used in a provisioner template.

The following example commands show how to configure a provisioner to use this server.

```
cat <<EOF > prov.tmpl
{
  {
    "subject": {
      "organizationalUnit": {{ toJson .Webhooks.People.role }}
    }
  }
}
EOF

step ca provisioner add my_provisioner --create --x509-template prov.tmpl

step ca provisioner webhook add my_provisioner my_webhook --url 'https://localhost:9443/{{ .Token.sub }}'
```

The final command will print out the webhook ID and signing secret you will need to configure this webhook server:

```
Webhook ID: 7d3c64dc-ec0e-4a0f-a489-241650554bd7
Signing Secret: nN/sH6+72GvLTSxYejUDcp5Fd2hh/yq00S7ivU8wRwPF09Ne0B7HxBkBq5IaQIWkcKBBkSoXuQyj62N3wwcYPQ==
```

Then creating a certificate using this provisioner will result in the role supplied by the webhook server being used as the OU in the certificate's subject.
```
step ca certificate andrew@smallstep.com my.crt my.key

step certificate inspect me.crt --format json | jq .subject
# {
#   "organizational_unit": [
#       "eng"
#   ]
# }
```
