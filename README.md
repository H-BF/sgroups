# Security groups service V1

### build server
```bash
make sg-service
```

### build client
```bash
make to-nft
```

1) падение сервера вызывает падение клиента


ip link add veth0 type veth peer name veth1
ip netns add ns1
ip link set veth1 netns ns1

ip addr add 10.1.1.1/24 dev veth0
ip link set dev veth0 up

ip netns exec ns1 ip link add dummy0 type dummy
ip netns exec ns1 ip address add 192.168.20.16/32 dev dummy0
ip netns exec ns1 ip address add 100.0.0.1/24 dev dummy0

ACCEPT_FWINS=1 NFT_NETNS=ns1 /usr/bin/fraimhbf-client


mkdir -p ~/.terraform.d/plugins/registry.terraform.io/fraima/charlotte/1.0.0/linux_amd64

export tag=1.0.2
mkdir -p ~/.terraform.d/plugins/registry.terraform.io/fraima/charlotte/${tag}/linux_amd64
cp bin/terraform-provider-sgroups ~/.terraform.d/plugins/registry.terraform.io/fraima/charlotte/${tag}/linux_amd64/terraform-provider-charlotte_v${tag}

docker build -f Dockerfile.server -t fraima/hbf-server:v0.0.2 .
docker push fraima/hbf-server:v0.0.2
docker build -f Dockerfile.client -t fraima/hbf-client:v0.0.2 .
docker push fraima/hbf-client:v0.0.2