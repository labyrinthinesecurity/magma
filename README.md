# magma

![alt text](https://github.com/labyrinthinesecurity/magma/blob/master/magma.png?raw=true)


# setup

## install redis or valkey for Python

```
apt-get install redis-server python3-redis
```

## install the azure cli

```
apt-get install azure-cli
```

## set environment variables

### Management groups
Variable MGMT_GROUPS contains a comma separated list of Azure management groups to scope the NSGs you want to monitor

Example (exporting from bash): 
```
export MGMT_GROUPS="\"MY-PROD-GROUP\",\"MY-DEV-GROUP\""
```

### Azure SPN
By default, magma.sh uses ***azure login*** with a **read only** service principal name (SPN) to authenticate and query the Microsoft Azure Resources Explorer API.
You must set 3 variables for this to work:

- ARM_TENANT_ID: the UUID of your Tenant
- ARM_CLIENT_ID: the UUID of the SPN
- ARM_CLIENT_SECRET: the secret of the SPN

# initialize redis/valkey

Note that magma reserves db 0 to inbound NSGs and db 1 to outbound NSGs in redis

## fetch NSGs from Azure Resources Explorer and store them to redis

### Command

Adjust flows direction (Inbound/Outbound) to your liking

```
./magma.sh --init --direction Inbound
```

### ARG query

The ARG query is currently set to:
```
resources
| where type == "microsoft.network/networksecuritygroups"
| join kind=inner ( resourcecontainers
  | where type == "microsoft.resources/subscriptions"
  | mv-expand pp = properties.managementGroupAncestorsChain
  | extend mgname = pp.name | where mgname in ('$MGMT_GROUPS')
  | distinct subscriptionId) on subscriptionId
| mv-expand prules = properties.securityRules
| extend rule = extractjson("$.properties",tostring(prules))
| where prules.properties.access=="Allow"
| where prules.properties.direction=="'$direction'"
| extend destwild = extractjson("$.properties.destinationAddressPrefix",tostring(prules))
| extend srcwild = extractjson("$.properties.sourceAddressPrefix",tostring(prules))
| extend portwild = extractjson("$.properties.destinationPortRange",tostring(prules))
| where portwild!="*"
```

Feel free to adjust it.

# testing

```
./magma.sh --flush --direction Inbound

Inbound flushed
```

Add passing rule (/15 = 10.20.0.0 - 10.21.255.255):
```
./magma.sh --allow '{'protocol': 'TCP', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.20.0.0/15', 'destinationPort': '443'}' --direction Inbound

{protocol: TCP, sourceAddressPrefix: *, destinationAddressPrefix: 10.20.0.0/15, destinationPort: 443} added to closed in redis
```

Add blocking rule (/30 = 10.22.0.12 - 10.22.0.15):
```
./magma.sh --block '{'protocol': 'TCP', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.22.0.12/30', 'destinationPort': '443'}' --direction Inbound

{protocol: TCP, sourceAddressPrefix: *, destinationAddressPrefix: 10.22.0.12/30, destinationPort: 443} added to open in redis
```

Add proposition (/13 = 10.16.0.0 - 10.23.255.255)
```
./magma.sh --prove '{'protocol': 'TCP', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.16.0.0/13', 'destinationPort': '443'}' --direction Inbound

{protocol: *, sourceAddressPrefix: TCP, destinationAddressPrefix: 10.16.0.0/13, destinationPort: 443} added to unknown in redis
```

List propositions
```
./magma.sh --list --direction Inbound

the following propositions must be proved:
  PROPOSITION 1 {protocol: TCP, sourceAddressPrefix: *, destinationAddressPrefix: 10.16.0.0/13, destinationPort: 443}
```

Compile (calculate the passlet):
```
./magma.sh --compile --direction Inbound

  *** adding the following passlets
  --- {'protocol': '0', 'sourceAddressPrefix': '0.0.0.1-255.255.255.254', 'destinationAddressPrefix': '10.22.0.16-10.23.255.255', 'destinationPort': '443'}
  --- {'protocol': '0', 'sourceAddressPrefix': '0.0.0.1-255.255.255.254', 'destinationAddressPrefix': '10.22.0.0-10.22.0.11', 'destinationPort': '443'}
  --- {'protocol': '0', 'sourceAddressPrefix': '0.0.0.1-255.255.255.254', 'destinationAddressPrefix': '10.16.0.0-10.19.255.255', 'destinationPort': '443'}
```

# What-if scenario

```
./magma.sh --whatIf '{'protocol': '*', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.1.0.0/15', 'destinationPort': '443'}' --direction Inbound
```

# Drift scenario

```
./magma.sh --drift --direction Inbound
```
