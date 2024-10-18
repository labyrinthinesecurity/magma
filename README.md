# Scaling oversight of Network Security Groups

![alt text](https://github.com/labyrinthinesecurity/magma/blob/master/magma.png?raw=true)


## What is Azure Magma?
***Azure Magma*** is a powerful tool that lets organizations automate the management of thousands of Network Security Groups in a cost-efficient way.

To use this tool, your organization should ideally meet these 3 criteria:
- devSecOps model: each local feature team manages its own security groups
- central supervision: a central security team oversees network security
- zero-trust: your zero-trust model is **identity-based**, not network-based. It means that you don't allow network connections on a point-to-point basis. Rather, you allow relatively large source and destination IP ranges to communicate


## Quick start
### installation
```
apt-get install redis-server python3-redis azure-cli
```

### environment variables
Scope your NSGs to some coma separated Azure management groups:
```
export MGMT_GROUPS="\"MY-PROD-GROUP\",\"MY-DEV-GROUP\""
```
Declare a read only SPN to fetch the SPNs:
```
export ARM_TENANT_ID="***"
export ARM_CLIENT_ID="***"
export ARM_CLIENT_SECRET="***"
```

### First test
Empty propositions for NSGs in the Inbound direction
```
./magma.sh --flushall --direction Inbound
Inbound axioms and propositions flushed
```

Add a sample security rule allowing access. The force mode will require a confirmation, it should only be used for testing
```
./magma.sh --force:allow '{'protocol': 'TCP', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.20.0.0/15', 'destinationPort': '443'}' --direction Inbound
WARNING! force:allow might break the Magma Quotient and should ONLY be used for testing! Proceed? (Y/n)
Y
{protocol: TCP, sourceAddressPrefix: *, destinationAddressPrefix: 10.20.0.0/15, destinationPort: 443} added to closed in redis
```
(Note the /15 netmask => 10.20.0.0 - 10.21.255.255).

Add a sample blocking security rule.
```
./magma.sh --force:block '{'protocol': 'TCP', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.22.0.12/30', 'destinationPort': '443'}' --direction Inbound
WARNING! force:block might break the Magma Quotient and should ONLY be used for testing! Proceed? (Y/n)
Y
{protocol: TCP, sourceAddressPrefix: *, destinationAddressPrefix: 10.22.0.12/30, destinationPort: 443} added to open in redis
```
(Note the /30 netmask => 10.22.0.12 - 10.22.0.15)

Add a sample proposition, overlapping partially the above rules. Adding propositions are always safe since they are unproven, no need to require confirmation
```
./magma.sh --prove '{'protocol': 'TCP', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.16.0.0/13', 'destinationPort': '443'}' --direction Inbound

{protocol: *, sourceAddressPrefix: TCP, destinationAddressPrefix: 10.16.0.0/13, destinationPort: 443} added to propositions in redis
```
(Note the /13 netmask => 10.16.0.0 - 10.23.255.255)


List current propositions. There should be only one
```
./magma.sh --list --direction Inbound

the following proposition(s) must be proved:
  {protocol: TCP, sourceAddressPrefix: *, destinationAddressPrefix: 10.16.0.0/13, destinationPort: 443}
total: 1
```

Compile. This will break down the proposition into the smallest possible fragments, called ***passlets***, that are actually unproven. 
```
./magma.sh --compile --direction Inbound

  proposition replaced by the following passlets
    {'protocol': '0', 'sourceAddressPrefix': '0.0.0.1-255.255.255.254', 'destinationAddressPrefix': '10.22.0.16-10.23.255.255', 'destinationPort': '443'}
    {'protocol': '0', 'sourceAddressPrefix': '0.0.0.1-255.255.255.254', 'destinationAddressPrefix': '10.22.0.0-10.22.0.11', 'destinationPort': '443'}
    {'protocol': '0', 'sourceAddressPrefix': '0.0.0.1-255.255.255.254', 'destinationAddressPrefix': '10.16.0.0-10.19.255.255', 'destinationPort': '443'}
```
In the above example, the initial proposition was broken down into 3 passlets.


### What next
Refer to the documentation for detailed information on:
- the foundations (what is an axiom, a proposition, a Magma Quotient)
- how to works behind the scene
- how it compares with other Azure tools

The next section explains how to backfill your existing NSGs into a Magma Quotient.

## Backfiling your NSGs into a Magma Quotient

### Import inbound NSGs

The following rule will import all your inbound NSGs as propositions
```
./magma.sh --init --direction Inbound
123 rules imported
```

Verify import by listing all propositions:
```
./magma.sh --list --direction Inbound
{"protocol": "TCP", "sourceAddressPrefix": "VirtualNetwork", "destinationAddressPrefix": "VirtualNetwork", "destinationPort": "443"}
...
{"protocol": "*", "sourceAddressPrefix": "10.0.0.0/8", "destinationAddressPrefix": "VirtualNetwork", "destinationPort": "22"}
total: 123 
```

For information, the import query is:
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

### Prove/disprove each proposition one by one

List all the proposition which remain to be proved:
```
./magma.sh --list --direction Inbound
```

For each proposition that you have reviewed and that you want to ***allow***, copy/paste the proposition into a prove:allow command
```
./magma.sh --direction Inbound prove:allow '{"protocol": "TCP", "sourceAddressPrefix": "VirtualNetwork", "destinationAddressPrefix": "VirtualNetwork", "destinationPort": "100-200"}'
```

Likewise, for each proposition that you have reviewed and that you want to ***block***, copy/paste the proposition into a prove:block command
```
./magma.sh --direction Inbound prove:block '{"protocol": "TCP", "sourceAddressPrefix": "VirtualNetwork", "destinationAddressPrefix": "VirtualNetwork", "destinationPort": "3389"}'
```

Rince and repeat (list, prove:allow or prove:block, etc) until the list of propositions is empty.

## What-if scenario

```
./magma.sh --whatIf '{'protocol': '*', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.1.0.0/15', 'destinationPort': '443'}' --direction Inbound
```

## Drift scenario

```
./magma.sh --drift --direction Inbound
```
