# Keep hold of your Network Security Groups!

![alt text](https://github.com/labyrinthinesecurity/magma/blob/master/magma.png?raw=true)


## What is Azure Magma?
***Azure Magma*** is a free powerful tool that lets medium and large organizations automate the management of ***thousands*** of Network Security Groups in a cost-efficient way. 
It uses a SMT solver to implement the super-fast ALLBVSAT algorithm, from Microsoft's secGuru.

The two main uses cases addressed by Magma are:
1. **Impact analysis**: what if I add this rule to a NSG? To answer the question, Magma will break the rule into its biggest unknown components, so that everything that was already allowed or blocked in the past is not revalidated
2. **Drift management**: if a new rule shows up, is it already allowed? blocked? partially allowed? what remains to review manualy?

To use this tool, your organization should ideally meet 4 criteria:
- have a devSecOps model where each local feature team manages its own security groups independently
- have central supervision: a single security team oversees network security
- embrace **identity-based** zero-trust: your network segmentation shouldn't be too fine-grain. Rather, it should let relatively large source and destination IP ranges communicate freely on a per-portbasis
- have a default rule in every NSG which blocks everything that hasn't been explicitely allowed. This rule shouldn't be overriden by a more lenient, higher priority one, of course.

### Concepts
Magma fetches your NSGs from Azure, but it doesn't fetch all NSGs: only the useful ones! 
These are the ones featuring ***custom rules*** (not default rules), in ***allowed*** access mode, and ***associated*** to a subnet or to a network interface.

- A ***security rule*** is an atomic rule of a Network Security Group. Note that **Magma doesn't care about the rule priority**. So a security rule, for Magma, is unnumbered. 
- A ***proposition*** is an unproven security rule.
- An ***axiom*** is a proven security rule. Axioms can be of two kinds: allow, and block.

There is no GUI: all operations are carried out using the Magma CLI, which is [documented here](docs/reference.html).

The theoretical foundations of Magma are explained in [my newsletter](https://www.linkedin.com/pulse/introducing-azure-magma-christophe-parisel/).
Since this article, a [few design choices and mathemetical assumptions](docs/index.html) have been clarified or modified. 

## Quick start
### installation

Magma is written in Python, it requires redis or valkey using database IDs 0 and 1 to work properly.

The SMT part is handled by Z3, a theorem prover by Microsoft Research.

Azure CLI is required to fetch NSGs from Azure Resource Graph Explorer's REST API.

```
apt-get install redis-server python3-redis azure-cli python3-z3
```

### environment variables
Scope your NSGs to some coma separated Azure management groups:
```
export MGMT_GROUPS="\"MY-PROD-GROUP\",\"MY-DEV-GROUP\""
```
Declare a ***read only SPN*** to fetch NSGs from these management groups. Obviously, ensure first that it has proper RBAC permissions:
```
export ARM_TENANT_ID="***"
export ARM_CLIENT_ID="***"
export ARM_CLIENT_SECRET="***"
```

### First test
Initialize the cache (Inbound direction is bound to database ID 0, Outbound direction is bound to ID 1):

```
./magma --flushall --direction Inbound
Inbound axioms and propositions flushed
```

Add a sample security rule allowing access, using the **force:allow** command. This mode requires an interactive confirmation, it should only be used for testing:
```
./magma --force:allow '{'protocol': 'TCP', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.20.0.0/15', 'destinationPort': '443'}' --direction Inbound
WARNING! force:allow might break the Magma Quotient and should ONLY be used for testing! Proceed? (Y/n)
Y
{protocol: TCP, sourceAddressPrefix: *, destinationAddressPrefix: 10.20.0.0/15, destinationPort: 443} added to closed in redis
```
(Note the /15 netmask => 10.20.0.0 - 10.21.255.255).

Add a sample blocking security rule using the **force:block** command.
```
./magma --force:block '{'protocol': 'TCP', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.22.0.12/30', 'destinationPort': '443'}' --direction Inbound
WARNING! force:block might break the Magma Quotient and should ONLY be used for testing! Proceed? (Y/n)
Y
{protocol: TCP, sourceAddressPrefix: *, destinationAddressPrefix: 10.22.0.12/30, destinationPort: 443} added to open in redis
```
(Note the /30 netmask => 10.22.0.12 - 10.22.0.15)

Add a sample proposition using the **prove** command Adding propositions are always safe since they are unproven, no need to require confirmation. 
Note that this proposition was designed to overlap part of the axioms defined above.
```
./magma --prove '{'protocol': 'TCP', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.16.0.0/13', 'destinationPort': '443'}' --direction Inbound

{protocol: *, sourceAddressPrefix: TCP, destinationAddressPrefix: 10.16.0.0/13, destinationPort: 443} added to propositions in redis
```
(Note the /13 netmask => 10.16.0.0 - 10.23.255.255)


List all propositions using the **list** command. (there should be only one proposition for now)
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


The next section explains how to backfill your existing NSGs into Magma.

## Backfilling your NSGs into a Magma

You have two options: 
- fetch all your current NSGs as propositions, then review them one by one to turn them into axioms
- start from an empty cache, and add each axiom one by one

Let's review both of them

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
- block: the rule is dangerous, it can be directly turned into a block axiom
- mix: part of the rule is OK, the other part is dangerous: we break split it to create an allow axiom and a block axiom
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

force:redo restores all allow axioms from recording/ALLOWED.txt without re-proving them, so it is very fast.
In production, ALWAYS use prove:redo. It restores all allow axioms from recording/ALLOWED.txt by proving them first, but it is slighlty slower.

If prove:redo cannot prove an axiom, it will explain why by printing all the counter examples which cannot be satisfied:
```
./magma --prove:redo --direction Inbound
{"protocol": "TCP", "sourceAddressPrefix": "VirtualNetwork", "destinationAddressPrefix": "VirtualNetwork", "destinationPort": "80"}
PROPOSITION 1 {"protocol": "TCP", "sourceAddressPrefix": "VirtualNetwork", "destinationAddressPrefix": "VirtualNetwork", "destinationPort": "80"}
  proposition 1 intersects only the closed class
NOT proved
    counterexample(s)
     {'protocol': '0', 'sourceAddressPrefix': 'VirtualNetwork', 'destinationAddressPrefix': 'VirtualNetwork', 'destinationPort': '80'}
FATAL: cannot prove block axiom: {"protocol": "TCP", "sourceAddressPrefix": "VirtualNetwork", "destinationAddressPrefix": "VirtualNetwork", "destinationPort": "80"}
```

Here is an example that turns a proposition into a block axiom:
```
./magma --prove:block '{'protocol': 'TCP', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.20.0.0/15', 'destinationPort': '443'}' --direction Inbound
```

This command appends the axiom into a file called recording/BLOCKED.txt

Here again, edit BLOCKED.txt if you make a mistake, then restore the state:
```
./magma --cache:init --direction Inbound
./magma --force:redo --direction Inbound
```

List the remaining propositions and ensure that the counter has decreased by one:
```
./magma --list --direction Inbound
```

Repeat the process until you've reviewed all the propositions (i.e. the list is empty except undetermined propositions)

#### Split a proposition into its allow and block parts

Copy the proposition from the previous listing, identify the parts, and save them as allow and block axioms

In the following example, the proposition is split depending on the source address prefix: all ingress flows to TCP port 443 are allowed, except when coming from IP 10.10.0.0
```
./magma --prove:allow '{'protocol': 'TCP', 'sourceAddressPrefix': '0.0.0.0-10.9.255.255', 'destinationAddressPrefix': '10.20.0.0/15', 'destinationPort': '443'}' --direction Inbound
./magma --prove:block '{'protocol': 'TCP', 'sourceAddressPrefix': '10.10.0.0', 'destinationAddressPrefix': '10.20.0.0/15', 'destinationPort': '443'}' --direction Inbound
./magma --prove:allow '{'protocol': 'TCP', 'sourceAddressPrefix': '10.10.0.1-255.255.255.255', 'destinationAddressPrefix': '10.20.0.0/15', 'destinationPort': '443'}' --direction Inbound
```

Here is another example where we forbid reaching TCP port 80 from the Virtual Network:
```
./magma --prove:allow '{"protocol": "TCP", "sourceAddressPrefix": "VirtualNetwork", "destinationAddressPrefix": "*", "destinationPort": "1-79"}' --direction Inbound
./magma --prove:allow '{"protocol": "TCP", "sourceAddressPrefix": "VirtualNetwork", "destinationAddressPrefix": "*", "destinationPort": "81-65535"}' --direction Inbound
./magma --prove:block '{"protocol": "TCP", "sourceAddressPrefix": "VirtualNetwork", "destinationAddressPrefix": "*", "destinationPort": "80"}' --direction Inbound
```

If you make an error, proceed as explained before: edit ALLOWED.txt or BLOCKED.txt then issue a redo command

Note that if you list propositions, this "split" rule will remain and the counter won't decrease. That's because NSG owners MUST modify their NSGs to align with the allow axiom. Only when all owners have updated their NSG will the proposition vanish from the list.

#### Backup the recording folder!

When you are done, you are strongly advised to make a copy of the recording directory, this will save you the pain to start over the whole process should you erase ALLOWED.txt or BLOCKED.Txt by mistake

### Option 2: import axioms one by one

Initialize an empty cache:
```
./magma --direction Inbound --flushall
```

Note that, unlike cache:init or force:init, flushall doesn't fetch any actual NSG. After a flushall, your cache contains no axioms and no propositions.

For each proposition that you want to ***allow***, issue a prove:allow command
```
./magma --direction Inbound prove:allow '{"protocol": "TCP", "sourceAddressPrefix": "VirtualNetwork", "destinationAddressPrefix": "VirtualNetwork", "destinationPort": "100-200"}'
```

Likewise, for each proposition that you want to ***block***, issue a prove:block command
```
./magma --direction Inbound prove:block '{"protocol": "TCP", "sourceAddressPrefix": "VirtualNetwork", "destinationAddressPrefix": "VirtualNetwork", "destinationPort": "3389"}'
```

Rince and repeat until the list of propositions is empty.


## What-if scenario

Suppose you want to assess the impact of adding an allow axiom to the Inbound direction. The ***whatIf*** command wil let you know if it is possible, and , if not, what is the acceptable subset.
```
./magma --whatIf '{'protocol': '*', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.1.0.0/15', 'destinationPort': '443'}' --direction Inbound
```

Currently, whatIf only works for allow axioms, not for block axioms.


## Drift scenario

Run a regular cron job to check if the depoyed NSGs have drifted from the set of allow and block axioms stored in cache (also stored in the recording directory)
```
./magma --drift --direction Inbound
```

## What's next?
Refer to the documentation for detailed information on:
- the foundations (what is an axiom, a proposition, a Magma Quotient)
- how Magma works behind the scene
- how it compares with native Azure tools

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

