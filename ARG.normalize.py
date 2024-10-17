#!/usr/bin/python3

import json,argparse,redis

parser = argparse.ArgumentParser()
parser.add_argument("--db", required=True, type=int, choices=[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15], help="redis database id")
parser.add_argument("--op", required=True, type=str, choices=["init","asof"], help="init|asof")
parser.add_argument("--direction", required=True, type=str, choices=["Inbound","Outbound"], help="Inbound|Outbound")
args = parser.parse_args()

DB=args.db
DIR=args.direction

if args.op=="init":
  sfile=f"init.{DIR}.json"
  dfile=f"normalized.init.{DIR}.json"
elif args.op=="asof":
  sfile=f"asof.{DIR}.json"
  dfile=f"normalized.asof.{DIR}.json"

r = redis.StrictRedis(host='localhost', port=6379, db=DB)
if r.exists('unknown'):
  r.delete('unknown')
#  r.sadd('unknown')
tags=r.smembers("tags")

def findRule(rule):
  found=False
  tag=None
  for aC in tags:
    members=r.smembers(aC)
    for aM in members:
      if aM.decode('UTF-8')==rule:
        found=True
        tag=aC
        break
  return found,tag


def normalizeNSG(aN,ruleset,debug):
  if debug:
    print("")
    print("===NEW===")
    print(aN['rule'])
    print("===OUT===")
  aR=json.loads(aN['rule'])
  aR['protocol']=aR['protocol'].upper()
  aNR={}
  dprs=[]
#  print("reproto",aR['protocol'])
  if (aR['direction']=="Inbound") and (aR['access']=="Allow"):
    if 'sourceAddressPrefix' in aR:
      if aR['sourceAddressPrefix']!="":
        if len(aR['sourceAddressPrefixes'])>0:
          sapfs=sorted(aR['sourceAddressPrefixes'].append(aR['sourceAddressPrefix']))
        else:
          sapfs=[]
          sapfs.append(aR['sourceAddressPrefix'])
      else:
        if len(aR['sourceAddressPrefixes'])>0:
          sapfs=sorted(aR['sourceAddressPrefixes'])
        else:
          sapfs=[]
    else:
      sapfs=sorted(aR['sourceAddressPrefixes'])
    if 'destinationAddressPrefix' in aR:
      if 'destinationAddressPrefixes' in aR and len(aR['destinationAddressPrefixes'])>0:
        dapfs=sorted(aR['destinationAddressPrefixes'].append(aR['destinationAddressPrefix']))
      else:
        dapfs=[]
        dapfs.append(aR['destinationAddressPrefix'])
    else:
      dapfs=sorted(aR['destinationAddressPrefixes'])
    if 'destinationPortRanges' in aR and aR['destinationPortRanges'] is not None:
      if len(aR['destinationPortRanges'])>0:
        dprs=sorted(aR['destinationPortRanges'])
    if 'destinationPortRange' in aR and len(aR['destinationPortRange'])>0:
      dprs.append(aR['destinationPortRange'])
    if 'destinationPort' in aR and aR['destinationPort'] is not None:
        dprs.append(aR['destinationPort'])
    dpro=aR['protocol']
    if debug:
      print("DPRS",dprs)
    if len(sapfs)>0:
      for aS in sapfs:
        if len(dapfs)>0:
          for aD in dapfs:
            if len(dprs)>0:
              for aP in dprs:
                aNR={}     
                aNR['protocol']=dpro
                aNR['sourceAddressPrefix']=aS
                aNR['destinationAddressPrefix']=aD
                aNR['destinationPort']=aP
                ruleset.append(aNR) if aNR not in ruleset else ruleset
            else:
              aNR={}
              aNR['protocol']=dpro
              aNR['sourceAddressPrefix']=aS
              aNR['destinationAddressPrefix']=aD
#              aNR['destinationPort']=aP
              ruleset.append(aNR) if aNR not in ruleset else ruleset
        else:
          if len(dprs)>0:
            for aP in dprs:
              aNR={}
              aNR['protocol']=dpro
              aNR['sourceAddressPrefix']=aS
              aNR['destinationPort']=aP
              ruleset.append(aNR) if aNR not in ruleset else ruleset
          else:
            aNR={}
            aNR['protocol']=dpro
            aNR['sourceAddressPrefix']=aS
            ruleset.append(aNR) if aNR not in ruleset else ruleset
    else: 
      if len(dapfs)>0:
        for aD in dapfs:
          if len(dprs)>0:
            for aP in dprs:
              aNR={}
              aNR['protocol']=dpro
              aNR['destinationAddressPrefix']=aD
              aNR['destinationPort']=aP
              ruleset.append(aNR) if aNR not in ruleset else ruleset
          else:
            aNR={}
            aNR['protocol']=dpro
            aNR['destinationAddressPrefix']=aD
            aNR['destinationPort']=aP
            ruleset.append(aNR) if aNR not in ruleset else ruleset
      else:
        if len(dprs)>0:
          for aP in dprs:
            aNR={}
            aNR['protocol']=dpro
            aNR['destinationPort']=aP
            ruleset.append(aNR) if aNR not in ruleset else ruleset
        else:
          aNR={}
          aNR['protocol']=dpro
          ruleset.append(aNR) if aNR not in ruleset else ruleset
  if debug:
    print(aNR) 
  return ruleset

NSGtags={}
NSGruleset={}
ruleset=[]

with open(sfile,'r') as data_file:
    nsg_data = json.load(data_file)

for aN in nsg_data:
  ruleset=normalizeNSG(aN,ruleset,False)
  for aR in ruleset:
    (found,tag)=findRule(str(aR))
    if found:
#      print("... ",aR,tag)
      if aN['id'] in NSGtags:
        NSGtags[aN['id']].append(tag.decode('UTF-8')) if tag.decode('UTF-8') not in NSGtags[aN['id']] else  NSGtags[aN['id']]
      else:
        NSGtags[aN['id']]=[]
        NSGtags[aN['id']].append(tag.decode('UTF-8')) if tag.decode('UTF-8') not in NSGtags[aN['id']] else  NSGtags[aN['id']]
    else:
      if aN['id'] in NSGtags:
        NSGtags[aN['id']].append("unknown") if "unknown" not in NSGtags[aN['id']] else  NSGtags[aN['id']]
      else:
        NSGtags[aN['id']]=[]
        NSGtags[aN['id']].append("unknown")
    if aN['id'] in NSGruleset:
       NSGruleset[aN['id']].append(aR)
    else:
      NSGruleset[aN['id']]=[]
      NSGruleset[aN['id']].append(aR)

with open(dfile,'w') as data_file:
  json.dump(ruleset,data_file,indent=2)

for an in NSGruleset:
  aRl=NSGruleset[an]
  for aR in aRl: 
#    print("AR__",str(aR))
    r.sadd('unknown',str(aR))

def classify():
  cntNotClosed=0
  for key in NSGtags:
    if len(NSGtags[key])>1:
#      print(key,NSGtags[key])
#      print(NSGruleset[key])
#      print("**")
      cntNotClosed=cntNotClosed+1
    elif NSGtags[key][0]!="closed":
#      print(key,NSGtags[key])
#      print(NSGruleset[key])
#      print("**")
      cntNotClosed=cntNotClosed+1
#  print("number of NSGs not closed: ",cntNotClosed)

classify()
