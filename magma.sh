#!/usr/bin/bash

usage() {
    echo "Usage: $0 --init --db <redis database id> --direction <Inbound|Outbound>"
    exit 1
}

PROVE="0"
PROP="0"
SOURCE="0"
OP="0"
DIRECTION="0"

fetch_ARG() {
    az login --service-principal --tenant $ARM_TENANT_ID -u $ARM_CLIENT_ID -p "$ARM_CLIENT_SECRET" &> /dev/null
    local excode=$?
    if [ $excode -gt 0 ]
    then
      echo "ERROR: az login failed"
      exit
    fi
    local skip=0
    local query='''
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
| where prules.properties.direction=="'$2'"
| extend destwild = extractjson("$.properties.destinationAddressPrefix",tostring(prules))
| extend srcwild = extractjson("$.properties.sourceAddressPrefix",tostring(prules))
| extend portwild = extractjson("$.properties.destinationPortRange",tostring(prules))
| where portwild!="*"
    '''
    echo $query
    local records=`az graph query -q "$query" --first 1 --output json | jq .total_records`
    az graph query -q "$query" --first 1000 | jq ".data" > $1.$2.txt
    while [ $skip -lt $records ];
          do
                  skip=$(( $skip + 1000))
                  az graph query -q "$query" --first 1000 --skip $skip | jq ".data" >> $1.$2.txt
          done
    jq -s add $1.$2.txt > $1.$2.json
    rm $1.$2.txt
}

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --direction)
           if [[ -n "$2" ]] && [[ "$2" != --* ]]; then
             DIRECTION="$2"
             shift 2
           else
             echo "Error: Argument for $1 is missing" >&2
             usage
           fi
           ;;
	--init)
	   OP="init"
	   shift 1
	   ;;
	--flush)
	   OP="flush"
	   shift 1
	   ;;
	--list)
	   OP="list"
	   shift 1
	   ;;
        --whatIf)
           if [[ -n "$2" ]] && [[ "$2" != --* ]]; then
    	     OP="whatif"
             PROP="$2"
             shift 2
           else
             echo "Error: Argument for $1 is missing" >&2
             usage
           fi
           ;;
        --compile)
	   OP="compile"
           PROP="$2"
           shift 1
           ;;
        --allow)
	   OP="allow"
           if [[ -n "$2" ]] && [[ "$2" != --* ]]; then
             PROP="$2"
             shift 2
           else
             echo "Error: Argument for $1 is missing" >&2
             usage
           fi
           ;;
        --block)
           OP="block"
           if [[ -n "$2" ]] && [[ "$2" != --* ]]; then
             PROP="$2"
             shift 2
           else
             echo "Error: Argument for $1 is missing" >&2
             usage
           fi
           ;;
        --prove)
           OP="prove"
           if [[ -n "$2" ]] && [[ "$2" != --* ]]; then
             PROP="$2"
             shift 2
           else
             echo "Error: Argument for $1 is missing" >&2
             usage
           fi
           ;;
	--drift)
	  OP="drift"
	  shift 1
	  ;;
        *)
          echo "Unknown parameter passed: $1" >&2
          usage
          ;;
    esac
done

if [[ "$DIRECTION" == "Inbound" ]] || [[ "$DIRECTION" == "Outbound" ]]; then
  if [[ "$DIRECTION" == "Inbound" ]]; then
    DB=0
  else
    DB=1
  fi
else
  usage
fi

if [[ "$OP" == "init" ]]; then
#    fetch_ARG "init" "$DIRECTION"                   # generates init.json from ARG live ground truth in ARG
#    echo "Please standby, it may take a minute..."
#    python3 ./ARG.normalize.py --db $DB --op init --direction "$DIRECTION"   # (PREPROCESSOR): generates normalized.init.json from init.json
    python3 ./blade.py --db $DB --op init --direction "$DIRECTION" # flush redis then load normalized.init.json into redis as (closed) axioms 
elif [[ "$OP" == "list" ]]; then
    python3 ./proposition.py --db $DB --list  # list propositions in redis
elif [[ "$OP" == "drift" ]]; then
    #fetch_ARG "asof" "$DIRECTION"                   # generates asof.json from ARG live ground truth
    #python3 ./ARG.normalize.py --db $DB --op asof --direction "$DIRECTION"  # (PREPROCESSOR): generates normalized.asof.json from asof.json
    #python3 ./blade.py --db $DB --op asof --direction "$DIRECTION" # flush propositions (ONLY) in redis then load normalized.asof.json into redis as propositions
    python3 ./NSG.compiler.py --db $DB  --op drift    # compile
elif [[ "$OP" == "whatif" ]]; then
    python3 ./proposition.py --db $DB --load "$PROP"  # loads a NSG rule into redis propositions from CLI
    python3 ./NSG.compiler.py --db $DB  --op whatIf    # compile
elif [[ "$OP" == "allow" ]]; then
    python3 ./proposition.py --db $DB --load "$PROP"  --allow  # loads a NSG rule into redis closed axioms from CLI
elif [[ "$OP" == "block" ]]; then
    python3 ./proposition.py --db $DB --load "$PROP"  --block  # loads a NSG rule into redis open axioms from CLI
elif [[ "$OP" == "prove" ]]; then
    python3 ./proposition.py --db $DB --load "$PROP"  --prove  # loads a NSG rule into redis propositions from CLI
elif [[ "$OP" == "compile" ]]; then
    python3 ./NSG.compiler.py --db $DB  --op prove    # compile (same as whatIf)
elif [[ "$OP" == "flush" ]]; then
    python3 ./blade.py --db $DB --flush --direction "$DIRECTION" # flush redis
fi
