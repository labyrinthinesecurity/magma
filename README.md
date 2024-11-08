# Keep hold of your Network Security Groups!

![alt text](https://github.com/labyrinthinesecurity/magma/blob/master/magma.png?raw=true)


## What is Azure Magma (Preview)?
***Azure Magma*** is a free but powerful tool that lets organizations automate the management of ***thousands*** of Network Security Groups in a cost-efficient way. 
It uses a SMT solver to implement Microsoft's super-fast ALLBVSAT algorithm.

The two main uses cases addressed by Magma are:
1. **Impact analysis**: what if I add this rule to a NSG? To answer the question, Magma will break the rule into its biggest unknown components, so that everything that was already allowed or blocked in the past is not revalidated
2. **Drift management**: if a new rule shows up, is it already allowed? blocked? partially allowed? what remains to review manualy?

To use this tool, your organization should meet 2 criteria:
- have a devSecOps model where each local feature team manages its own security groups independently
- your assets perimeter should embrace **identity-based** zero-trust: your network segmentation shouldn't be too fine-grain. Rather, it should let relatively large source and destination IP ranges communicate freely on a per-port basis

Proper scoping of the assets perimeter is very important: you may have as many network zones (VNets) in scope, but whenever a security rule is allowed or denied in one zone at the subnet or NIC level, it should be allowed in **all** zones (***property 1***). So, the function and the network security guarantees of all zones in scope should be identical, even if zones are dedicated to independent business apps. Property 1 should drive the delineation of scopes, and not the other way around. 

Another important feature is that, unlike in Azure, security rules share all the same priority. Conflicts between allowed rules and denied rules is prevented by the structure of the underlying logic representation called a Magma Quotient (see theoretical foundations and mathematical assumptions in the ressources section below). This is ***property 2***.

Finally, you must have a default catch-all deny rule in every NSG which blocks everything that hasn't been explicitely allowed. In deployed NSGs, this rule shouldn't be overriden by a more lenient, higher priority one, of course (***property 3***)

An information system / a cloud deployment meeting properties 1,2 and 3 are called **Magmatic systems**.

### Concepts
Magma fetches your NSGs from Azure, but it doesn't fetch all NSGs: only the useful ones! 
These are the ones featuring ***custom rules*** (not default rules), in ***allowed*** access mode, and ***associated*** to a subnet or to a network interface.

- A ***security rule*** is an atomic rule of a Network Security Group. Note that **Magma doesn't care about the rule priority**. So a security rule, for Magma, is unnumbered. 
- A ***proposition*** is an unproven security rule.
- An ***axiom*** is a proven security rule. Axioms can be of two kinds: allow, and block.

The ONE single principle to understand for scalability is that all security rules belonging to the same class are equivalent (because of ***property 1***):
Suppose a security rule allows flows from 'VirtualNetwork' to '*' on port 80 in a NSG implemented in subscription A, and that another rule allows flows from '10.0.0.0/8' to '10.10.0.0/16' on port 443 in a NSG implemented in subscription B.

For Magma, both security rules will be the equivalent!

That's why it is critically important to scope Azure Magma to similar subscriptions, using proper management groups.

### Resources
There is no GUI: all operations are carried out using the Magma CLI, which is [documented here](https://labyrinthinesecurity.github.io/magma/reference.html).

The theoretical foundations of Magma are explained in [my newsletter](https://www.linkedin.com/pulse/introducing-azure-magma-christophe-parisel/).

Since this article, a [few design choices and mathematical assumptions](https://labyrinthinesecurity.github.io/magma/index.html) have been clarified or modified. 

The groundbreaking 2016 research paper introducing secGuru is available on [Microsoft Research web site](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/secguru.pdf).

### Known limitations of the Preview
Currently, we don't support:
1. Azure network security tags in wildcards. A source address prefix like '*' will not include tags like 'VirtualNetwork', for example. You will need to add an extra explicit axiom for each tag of interest
2. Application Security groups

### Other known limitations
1. Denies in security rules. Because Magma doesn't manage rule priorities, if some of your custom rules feature denies with a higher priority than allows, it will wreak havoc into the logic.
2. If you are using Azure managed VNets, security admin rules are not supported by Magma

## Quick start

Magma is written in Python, it requires redis or valkey using database IDs 0 and 1 to work properly.

The SMT part is handled by Z3, a theorem prover by Microsoft Research.

Azure CLI is required to fetch NSGs from Azure Resource Graph Explorer's REST API.

### installation

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

Compile. This will break down the proposition into the largest possible ***hyperrectangles*** that are actually unproven. 
```
./magma --compile --direction Inbound

  proposition replaced by the following hyperrectangluar propositions: 
    {'protocol': '0', 'sourceAddressPrefix': '0.0.0.1-255.255.255.254', 'destinationAddressPrefix': '10.22.0.16-10.23.255.255', 'destinationPort': '443'}
    {'protocol': '0', 'sourceAddressPrefix': '0.0.0.1-255.255.255.254', 'destinationAddressPrefix': '10.22.0.0-10.22.0.11', 'destinationPort': '443'}
    {'protocol': '0', 'sourceAddressPrefix': '0.0.0.1-255.255.255.254', 'destinationAddressPrefix': '10.16.0.0-10.19.255.255', 'destinationPort': '443'}
```
In the above example, the initial proposition was broken down into 3 hyperrectangles.


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
| distinct rule
```

#### Create a golden source

Storing your decisions on file will save you a lot of time if you need to edit axioms or start over. 

Use the **create:source** command to create a golden source of allowed axioms (ALLOWED.txt) and blocked ones (BLOCKED.txt) in a subdirectory called **source**:

```
./magma --create:source --direction Inbound
```

#### Review each proposition one by one

Inspect the rule and determine a status:
- allow: the rule is OK, it can be directly turned into an allow axiom
- block: the rule is dangerous, it can be directly turned into a block axiom
- mix: part of the rule is OK, the other part is dangerous: split it to create an allow axiom and a block axiom
- undetermined: we don't know what to do with this rule for now: keep it untouched as a proposition.

#### Turn a proposition into an axiom

Copy the proposition from the previous listing and paste it into a prove:allow or prove:block command.

Unlike force:allow and force:block that we used before, prove:allow and prove:block don't break the Magma Quotient. What's more, it appends the new axiom not only in memory cache, but in the source/ALLOWED.txt file

Here is an example that turns a proposition into an allow axiom:
```
./magma --prove:allow '{'protocol': 'TCP', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.20.0.0/15', 'destinationPort': '443'}' --direction Inbound
```

If you make a mistake, simply edit source/ALLOWED.txt, remove the line, and restore the state (without the bogus line):

```
./magma --cache:init --direction Inbound
./magma --force:redo --direction Inbound
```

cache:init imports your NSGs from a local file (managed by magma) rather than directly from Azure: this is faster. You may use force:init if you prefer

force:redo restores the golden source without re-proving each individual axiom, so it is very fast.
In production, ALWAYS use prove:redo. It restores axioms, proving them first.

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

This command store the axiom in memory cache and appends it to the golden source source/BLOCKED.txt

Here again, edit source/BLOCKED.txt if you make a mistake, then restore the golden source to its new state:
```
./magma --cache:init --direction Inbound
./magma --force:redo --direction Inbound
```

List the remaining propositions and ensure that their number has decreased by one:
```
./magma --list --direction Inbound
```

Repeat the process until you've reviewed all the propositions (i.e. the list is empty except undetermined propositions)

#### Split a proposition into its allow and block parts

Copy the proposition from the previous listing, identify the parts, and save them as allow and block axioms.


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

Note that if you list propositions, this "split" rule will remain and the number of propositions won't decrease. That's because NSG owners MUST modify their NSGs to align with the allow axiom. Only when all owners have updated their NSG will the proposition vanish from the list.

#### Backup the golden source!

When you are done, you are strongly advised to make a copy of the **source** directory using ***backup:source***, this will save you the pain to start over the whole process should you erase ALLOWED.txt or BLOCKED.txt by mistake

```
./magma --backup:source --direction Inbound
```

### Option 2: import axioms one by one

Initialize an empty cache:
```
./magma --direction Inbound --flushall
```

Note that, unlike cache:init or force:init, flushall doesn't fetch any actual NSG. After a flushall, your cache contains no axioms and no propositions.

#### Create golden source 

Storing your decisions as a golden source on file will save you a lot of time if you need to edit axioms or start over.
Use the **create:source*** command to create ALLOWED.txt and BLOCKED.txt files in a subdirectory called **source**:

```
./magma --create:source --direction Inbound
```

#### Review each proposition one by one and add them to the proper axiom set

For each proposition that you want to ***allow***, issue a prove:allow command
```
./magma --direction Inbound prove:allow '{"protocol": "TCP", "sourceAddressPrefix": "VirtualNetwork", "destinationAddressPrefix": "VirtualNetwork", "destinationPort": "100-200"}'
```

This will save the axiom in cache memory and append it to ALLOWED.txt

Likewise, for each proposition that you want to ***block***, issue a prove:block command
```
./magma --direction Inbound prove:block '{"protocol": "TCP", "sourceAddressPrefix": "VirtualNetwork", "destinationAddressPrefix": "VirtualNetwork", "destinationPort": "3389"}'
```

This will save the axiom in cache memory and append it to BLOCKED.txt

Rince and repeat until the list of propositions is empty.

#### Backup the golden source!

When you are done, you are strongly advised to make a copy of the golden source using ***backup:source***, this will save you the pain to start over the whole process should you erase ALLOWED.txt or BLOCKED.txt by mistake

```
./magma --backup:source --direction Inbound
```

## What-if scenario

Suppose you want to assess the impact of adding an allow axiom to the Inbound direction. The ***whatIf*** command wil let you know if it is possible, and , if not, what is the acceptable subset.
```
./magma --whatIf '{'protocol': '*', 'sourceAddressPrefix': '*', 'destinationAddressPrefix': '10.1.0.0/15', 'destinationPort': '443'}' --direction Inbound
```

Currently, whatIf only works for allow axioms, not for block axioms.


## Drift scenario

Run a regular cron job to check if the depoyed NSGs have drifted from the set of allow and block axioms stored in cache (also stored in the golden source)
```
./magma --drift --direction Inbound
```

## What's next?
Refer to [Magma documentation](https://labyrinthinesecurity.github.io/magma/index.html) for detailed information on:
- the foundations (what is an axiom, a proposition, a Magma Quotient)
- how Magma works behind the scene
- how it compares with native Azure tools

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

