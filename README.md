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
Initialize and empty the cache (Inbound direction)
```
./magma --flushall --direction Inbound
Inbound axioms and propositions flushed
```

Add a sample security rule allowing access. The force mode will require a confirmation, it should only be used for testing
```
./magma --force:allow '{'protocol': 'TCP', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.20.0.0/15', 'destinationPort': '443'}' --direction Inbound
WARNING! force:allow might break the Magma Quotient and should ONLY be used for testing! Proceed? (Y/n)
Y
{protocol: TCP, sourceAddressPrefix: *, destinationAddressPrefix: 10.20.0.0/15, destinationPort: 443} added to closed in redis
```
(Note the /15 netmask => 10.20.0.0 - 10.21.255.255).

Add a sample blocking security rule.
```
./magma --force:block '{'protocol': 'TCP', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.22.0.12/30', 'destinationPort': '443'}' --direction Inbound
WARNING! force:block might break the Magma Quotient and should ONLY be used for testing! Proceed? (Y/n)
Y
{protocol: TCP, sourceAddressPrefix: *, destinationAddressPrefix: 10.22.0.12/30, destinationPort: 443} added to open in redis
```
(Note the /30 netmask => 10.22.0.12 - 10.22.0.15)

Add a sample proposition, overlapping partially the above rules. Adding propositions are always safe since they are unproven, no need to require confirmation
```
./magma --prove '{'protocol': 'TCP', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.16.0.0/13', 'destinationPort': '443'}' --direction Inbound

{protocol: *, sourceAddressPrefix: TCP, destinationAddressPrefix: 10.16.0.0/13, destinationPort: 443} added to propositions in redis
```
(Note the /13 netmask => 10.16.0.0 - 10.23.255.255)


List current propositions. There should be only one
```
./magma --list --direction Inbound

the following proposition(s) must be proved:
  {protocol: TCP, sourceAddressPrefix: *, destinationAddressPrefix: 10.16.0.0/13, destinationPort: 443}
total: 1
```

Compile. This will break down the proposition into the smallest possible fragments, called ***passlets***, that are actually unproven. 
```
./magma --compile --direction Inbound

  proposition replaced by the following passlets
    {'protocol': '0', 'sourceAddressPrefix': '0.0.0.1-255.255.255.254', 'destinationAddressPrefix': '10.22.0.16-10.23.255.255', 'destinationPort': '443'}
    {'protocol': '0', 'sourceAddressPrefix': '0.0.0.1-255.255.255.254', 'destinationAddressPrefix': '10.22.0.0-10.22.0.11', 'destinationPort': '443'}
    {'protocol': '0', 'sourceAddressPrefix': '0.0.0.1-255.255.255.254', 'destinationAddressPrefix': '10.16.0.0-10.19.255.255', 'destinationPort': '443'}
```
In the above example, the initial proposition was broken down into 3 passlets.


The next section explains how to backfill your existing NSGs into a Magma Quotient.

## Backfilling your NSGs into a Magma Quotient

You have two options: 
- fetch all your current NSGs as propositions, then review them one by one to turn them into axioms
- start from an empty cache, and add each axiom one by one

### Option 1: mass import existing NSGs

The following rule will import all your inbound NSGs as propositions into redis 
```
./magma --force:init --direction Inbound
123 rules imported
```

Verify import by listing all propositions:
```
./magma --list --direction Inbound
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
  | distinct subscriptionId) 
  on subscriptionId
| mv-expand prules = properties.securityRules
| extend rule = extractjson("$.properties",tostring(prules))
| where prules.properties.access=="Allow"
| where prules.properties.direction=="'$direction'"
| mv-expand nics = properties.networkInterfaces
| mv-expand subs = properties.subnets
| extend associated = isnotnull(nics) or isnotnull(subs)
| where associated
```

### Review each proposition one by one

Inspect the rule and determine a status:
- allow: the rule is OK, it can be directly turned into an allow axiom
- block: the rule is dangerous, it can be directly turned into a deny axiom
- mix: part of the rule is OK, the other part is dangerous: we break split it to create an allow axiom and a deny axiom
- undetermined: we don't know what to do with this rule for now: we keep it as a proposition.

#### Turn a proposition into an axiom

Copy the proposition from the previous listing and paste it into a prove:allow or prove:block command.

Unlike force:allow and force:block that we used before, prove:allow and prove:block don't break the Magma Quotient.

Here is an example that turns a proposition into an allow axiom:
```
./magma --prove:allow '{'protocol': 'TCP', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.20.0.0/15', 'destinationPort': '443'}' --direction Inbound
```

This command appends the axiom into a file called recording/ALLOWED.txt

If you make a mistake, simply edit ALLOWED.txt, remove the line, and restore the state (without the bogus line):

```
./magma --cache:init --direction Inbound
./magma --force:redo --direction Inbound
```

cache:init imports your NSGs from a local file (managed by magma) rather than directly from Azure: this is faster. You may use force:init if you prefer

force:redo restores all allow axioms from recording/ALLOWED.txt without re-proving them, so it is fast

In production, ALWAYS use prove:redo. It restores all allow axioms from recording/ALLOWED.txt by proving them first

Here is an example that turns a proposition into a deny axiom:
```
./magma --prove:block '{'protocol': 'TCP', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.20.0.0/15', 'destinationPort': '443'}' --direction Inbound
```

This command appends the axiom into a file called recording/BLOCKED.txt

Here again, edit BLOCKED.txt if you make a mistake, then restore the state:
```
./magma --cache:init --direction Inbound
./magma --force:redo --direction Inbound
```

List the remaining propositions and ensure that the counter as decreased by one:
```
./magma --list --direction Inbound
```

Repeat the process until you've reviewed all the propositions (i.e. the list is empty except undetermined propositions)

#### Split a proposition into its allow and block parts

Copy the proposition from the previous listing, identify the parts, and save them as allow and deny axioms

In the following example, the proposition is split depending on the source address prefix: all ingress flows to TCP port 443 are allowed, except when coming from IP 10.10.0.0
```
./magma --prove:allow '{'protocol': 'TCP', 'sourceAddressPrefix': '0.0.0.0-10.9.255.255', 'destinationAddressPrefix': '10.20.0.0/15', 'destinationPort': '443'}' --direction Inbound
./magma --prove:block '{'protocol': 'TCP', 'sourceAddressPrefix': '10.10.0.0', 'destinationAddressPrefix': '10.20.0.0/15', 'destinationPort': '443'}' --direction Inbound
./magma --prove:allow '{'protocol': 'TCP', 'sourceAddressPrefix': '10.10.0.1-255.255.255.255', 'destinationAddressPrefix': '10.20.0.0/15', 'destinationPort': '443'}' --direction Inbound
```

If you make an error, proceed as explained before: edit ALLOWED.txt or BLOCKED.txt then issue a redo command

Note that if you list propositions, this "split" rule will remain and the counter won't decrease. That's because NSG owners MUST modify their NSGs to align with the allow axiom. Only when all owners have updated their NSG will the proposition vanish from the list.


### Option 2: import axioms one by one














For each proposition that you have reviewed and that you want to ***allow***, copy/paste the proposition into a prove:allow command
```
./magma --direction Inbound prove:allow '{"protocol": "TCP", "sourceAddressPrefix": "VirtualNetwork", "destinationAddressPrefix": "VirtualNetwork", "destinationPort": "100-200"}'
```

Likewise, for each proposition that you have reviewed and that you want to ***block***, copy/paste the proposition into a prove:block command
```
./magma --direction Inbound prove:block '{"protocol": "TCP", "sourceAddressPrefix": "VirtualNetwork", "destinationAddressPrefix": "VirtualNetwork", "destinationPort": "3389"}'
```

Rince and repeat (list, prove:allow or prove:block, etc) until the list of propositions is empty.

## What-if scenario

```
./magma --whatIf '{'protocol': '*', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.1.0.0/15', 'destinationPort': '443'}' --direction Inbound
```

## Drift scenario

```
./magma --drift --direction Inbound
```
### What's next?
Refer to the documentation for detailed information on:
- the foundations (what is an axiom, a proposition, a Magma Quotient)
- how to works behind the scene
- how it compares with other Azure tools
