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
./NSG.compiler.sh --init --direction Inbound
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

# What-if scenario

## testing

Add proposition
```
./magma.sh --prove '{'protocol': '*', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.1.0.0/16', 'destinationPort': '443'}' --direction Inbound

{protocol: *, sourceAddressPrefix: *, destinationAddressPrefix: 10.1.0.0/16, destinationPort: 443} added to unknown in redis
```

List propositions
```
./magma.sh --list --direction Inbound

the following propositions must be proved:
  PROPOSITION 1 {protocol: *, sourceAddressPrefix: *, destinationAddressPrefix: 10.1.0.0/16, destinationPort: 443}
```

Add passing rule:
```
./magma.sh --allow '{'protocol': 'TCP', 'sourceAddressPrefix': '10.0.0.0/8', 'destinationAddressPrefix': '10.1.0.0/15', 'destinationPort': '443'}' --direction Inbound

{protocol: TCP, sourceAddressPrefix: 10.0.0.0/8, destinationAddressPrefix: 10.1.0.0/15, destinationPort: 443} added to closed in redis
```

Add blocking rule:
```
./magma.sh --block '{'protocol': 'TCP', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.1.255.8/31', 'destinationPort': '443'}' --direction Inbound

{protocol: TCP, sourceAddressPrefix: *, destinationAddressPrefix: 10.1.255.8/31, destinationPort: 443} added to open in redis
```

Compile (calculate the passlet):
```
./magma.sh --compile --direction Inbound

```

## in production (cron task)
```
./magma.sh ---whatIf '{'protocol': 'TCP', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.1.0.0/15', 'destinationPort': '443'}' --direction Inbound
```

# Drift scenario

## testing

## in production (cron task)
```
./magma.sh --drift --direction --Inbound
```
