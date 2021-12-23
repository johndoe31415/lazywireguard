# lazywireguard
lazywireguard is a simple wrapper script that takes a simple JSON
representation of a network topology and creates configuration files (including
all keys) as well as a set of iptables routes for routing of traffic between
hosts. Note that generating all private keys on one server is not the most
secure way of doing this. This is merely intended to quickly get a Wireguard
VPN up and running the quick & dirty way.

## Example configuration
Take a look at `example_config.json`:

```json
{
    "network": {
        "address":      "172.16.0.0/24",
        "domainname":   "example-privlan.net"
    },
    "concentrator": {
        "name": "concentrator",
        "hostname": "my-host.example.com",
        "port": 51820
    },
    "clients": [
        {
            "name": "ds9"
        },
        {
            "name": "reliant",
            "fixed_ip": "172.16.0.1"
        },
        {
            "name": "deltaflyer",
            "ifname": "wg8"
        }
    ],
    "route": [
        "* -> ds9",
        "reliant <-> deltaflyer"
    ]
}
```

Creation of all files can be easily done by doing:

```
$ ./lazywg example_config.json
```

This creates all keys for all hosts, e.g., the server config file in
`example-privlan.net/concentrator/wg0.conf`:

```
$ cat example-privlan.net/concentrator/wg0.conf 
[Interface]
Address = 172.16.0.2/24
ListenPort = 51820
PrivateKey = WBVS8PQMzu9RaadKTiqbdod/9xrMBbRAkBl3t/N1yHI=

# ds9
[Peer]
PublicKey = GNYbsEP/8Dis3sLJLgQNpSJcYziodj/r/cjegRi4Xys=
AllowedIPs = 172.16.0.3/32

# reliant
[Peer]
PublicKey = qkQCo6MgGT0WON1/jBZSP8mfDkMh/W2k+7u2kG5rj0o=
AllowedIPs = 172.16.0.1/32

# deltaflyer
[Peer]
PublicKey = XJ6rH2Y0hkbdEToACuqW0M/+h8jU52Zgg5qTtlp/ilI=
AllowedIPs = 172.16.0.4/32
```

It also creates client config files, like `example-privlan.net/deltaflyer/wg8.conf`:

```
$ cat example-privlan.net/deltaflyer/wg8.conf
[Interface]
PrivateKey = aHV2bo5FJyMig9UPJp1VInPaDWFuv1nGTPusN6AM/nA=
Address = 172.16.0.4/24

[Peer]
PublicKey = dJRmSceGu8TEf2x9vCZX2LVpCEQAVb7XPe54ggf9QRQ=
AllowedIPs = 172.16.0.0/24
Endpoint = my-host.example.com:51820
PersistentKeepalive = 60
```

Furthermore, it takes the routing requirements and creates an iptable ruleset
in `example-privlan.net/concentrator/iptables.sh`:

```
$ cat example-privlan.net/concentrator/iptables.sh
#!/bin/bash
iptables -A FORWARD -i wg0 -o wg0 -d 172.16.0.3 -j ACCEPT -m comment --comment '* -> ds9'
iptables -A FORWARD -i wg0 -o wg0 -m state --state ESTABLISHED,RELATED -s 172.16.0.3 -j ACCEPT -m comment --comment 'only established: ds9 -> *'
iptables -A FORWARD -i wg0 -o wg0 -s 172.16.0.1 -d 172.16.0.4 -j ACCEPT -m comment --comment 'reliant -> deltaflyer'
iptables -A FORWARD -i wg0 -o wg0 -s 172.16.0.4 -d 172.16.0.1 -j ACCEPT -m comment --comment 'deltaflyer -> reliant'
```

Note that the single arrow (`->` or `<-`) indicates that the routing direction
needs to be initiated by the source party (and obviously related/established
responses are routed, too). The arrow with both sides (`<->`) means that either
party can establish a connection to the respective peer.

## License
GNU GPL-3.
