# Scaling oversight of Network Security Groups

![alt text](https://github.com/labyrinthinesecurity/magma/blob/master/magma.png?raw=true)


## What is Azure Magma?

***Azure Magma*** is a powerful tool that lets organizations automate the management of thousands of Network Security Groups in a cost-efficient way.

To use this tool, your organization souhld ideally meet these 3 criteria:
- devSecOps model: each local feature team manages its own security groups
- central supervision: a central security team oversees network security
- zero-trust: your zero-trust model is **identity-based**, not network-based. It means that you don't allow network connections on a point-to-point basis. Rather, you allow relatively large source and destination IP ranges to communicate


## Quick start


## How it works?

### Principle: direction matters

### Principle: Allowed access only
Magma fetches your Network security groups using the Azure Resource Graph Explorer API. It is only interested in **non-default** security rules, with **Allowed** access.

Security rules with **Denied** access are safely ignored because of the choice of the zero-trust model: we assume that, in each of your NSGs, you have a default security rule with least priority blocking every flow not explicitely allowed. 

### Principle: Priorities are irrelevant

### Principle: Scope matters, because NSGs are equivalent

### Principle: network security tags are equivalent

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

## fetch NSGs from Azure Resources Explorer and store them to redis as propositions

### Command (inbound direction)

```
./magma.sh --init --direction Inbound
123 rules imported
```

Verify by listing all propositions:
```
./magma.sh --list --direction Inbound
{"protocol": "TCP", "sourceAddressPrefix": "VirtualNetwork", "destinationAddressPrefix": "VirtualNetwork", "destinationPort": "443"}
...
{"protocol": "*", "sourceAddressPrefix": "10.0.0.0/8", "destinationAddressPrefix": "VirtualNetwork", "destinationPort": "22"}
total: 123 
```

### ARG query used for fetching NSGs

The query is currently set to:
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

Empty Inbound redis cache completely
```
./magma.sh --flushall --direction Inbound
Inbound axioms and propositions flushed
```

Add passing rule (/15 netmask => 10.20.0.0 - 10.21.255.255). The force mode will require a confirmation, it should only be used for testing
```
./magma.sh --force:allow '{'protocol': 'TCP', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.20.0.0/15', 'destinationPort': '443'}' --direction Inbound
WARNING! force:allow might break the Magma Quotient and should ONLY be used for testing! Proceed? (Y/n)
Y
{protocol: TCP, sourceAddressPrefix: *, destinationAddressPrefix: 10.20.0.0/15, destinationPort: 443} added to closed in redis
```

Add blocking rule (/30  netmask => 10.22.0.12 - 10.22.0.15).The force mode will require a confirmation, it should only be used for testing
```
./magma.sh --force:block '{'protocol': 'TCP', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.22.0.12/30', 'destinationPort': '443'}' --direction Inbound
WARNING! force:block might break the Magma Quotient and should ONLY be used for testing! Proceed? (Y/n)
Y
{protocol: TCP, sourceAddressPrefix: *, destinationAddressPrefix: 10.22.0.12/30, destinationPort: 443} added to open in redis
```

Add proposition (/13 netmask => 10.16.0.0 - 10.23.255.255)
```
./magma.sh --prove '{'protocol': 'TCP', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.16.0.0/13', 'destinationPort': '443'}' --direction Inbound

{protocol: *, sourceAddressPrefix: TCP, destinationAddressPrefix: 10.16.0.0/13, destinationPort: 443} added to propositions in redis
```

List propositions
```
./magma.sh --list --direction Inbound

the following proposition(s) must be proved:
  {protocol: TCP, sourceAddressPrefix: *, destinationAddressPrefix: 10.16.0.0/13, destinationPort: 443}
total: 1
```

Compile (calculate the passlets):
```
./magma.sh --compile --direction Inbound

  proposition replaced by the following passlets
    {'protocol': '0', 'sourceAddressPrefix': '0.0.0.1-255.255.255.254', 'destinationAddressPrefix': '10.22.0.16-10.23.255.255', 'destinationPort': '443'}
    {'protocol': '0', 'sourceAddressPrefix': '0.0.0.1-255.255.255.254', 'destinationAddressPrefix': '10.22.0.0-10.22.0.11', 'destinationPort': '443'}
    {'protocol': '0', 'sourceAddressPrefix': '0.0.0.1-255.255.255.254', 'destinationAddressPrefix': '10.16.0.0-10.19.255.255', 'destinationPort': '443'}
```

# What-if scenario

```
./magma.sh --whatIf '{'protocol': '*', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.1.0.0/15', 'destinationPort': '443'}' --direction Inbound
```

# Drift scenario

```
./magma.sh --drift --direction Inbound
```
