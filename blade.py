#!/usr/bin/python3 -u

import json,argparse,redis,sys,os

parser = argparse.ArgumentParser()
parser.add_argument("--db", required=True, type=int, choices=[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15], help="redis database id")
parser.add_argument("--op", required=False, choices=['add','retag','show','init','asof'], help="operation")
parser.add_argument("--direction", required=True, choices=['Inbound','Outbound'], help="Inbound|Outbound")
parser.add_argument("--flushall", required=False, action="store_true",help="flush redis axioms and propositions")
parser.add_argument("--flush", required=False, action="store_true",help="flush redis propositions only")
parser.add_argument("--redo", required=False, action="store_true",help="reload exioms from last golden source version")
args = parser.parse_args()

DB=args.db
OP=args.op
DIR=args.direction

if args.op=="init":
  sfile=f"normalized.init.{DIR}.json"
elif args.op=="asof":
  sfile=f"normalized.asof.{DIR}.json"

r = redis.StrictRedis(host='localhost', port=6379, db=DB)
r.sadd("tags","allowed")
r.sadd("tags","blocked")
tags=r.smembers("tags")

def delete_db(scope):
  if scope=='all':
    r.flushdb()
  else:
    members=r.smembers(scope)
    for member in members:
      r.srem(scope,member)

if args.flushall:
  r.flushdb(DB)
  print(f"{DIR} axioms and propositions flushed")
  sys.exit()

if args.flush:
  delete_db('unknown')
  print(f"{DIR} propositions flushed")
  sys.exit()

allowed0=r.smembers("allowed")
if OP=='show':
  print(" ")
  if len(allowed0)>0:
    print("begin axioms (allowed partition)")
    for aC in allowed0:
      print("  ",aC.decode('UTF-8'))
    print("end axiomms (allowed partition)")
  else:
    print("no axioms in allowed partition")

blocked0=r.smembers("blocked")
if OP=='show':
  print(" ")
  if len(blocked0)>0:
    print("begin axioms (blocked partition)")
    for aC in blocked0:
      print("  ",aC.decode('UTF-8'))
    print("end axioms (blocked partition)")
  else:
    print("no axioms in blocked partition")

uk0=r.smembers("unknown")
if OP=='show':
  print(" ")
  if len(uk0)>0:
    print("begin propositions")
    for aC in uk0:
      print("  ",aC.decode('UTF-8'))
    print("end propositions")
  else:
    print("no propositions")


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

def tagUntaggedRules():
  with open('normalizedrules.json') as data_file:
      test_data = json.load(data_file)
  for aS in test_data:
#    print("read ",aS)
    decide=False
    for aC in tags:
      req=r.sismember(aC,str(aS))
#      print(aC,aS,req)
      if req:
  #      print(aS,"is member of class",aC)
        decide=True
        break
    for aC in tags:
      while not decide:
        print(" ")
        tag=input(str(aS)+" ====> ?")
        btag=bytes(tag,'UTF-8')
        if len(tag)>0:
          if btag in tags:
            r.sadd(tag,str(aS))
            print("ok?",r.sismember(tag,str(aS)))
            decide=True
        else:
          print("CLASS NOT FOUND")
          decide=True

def retagRule():
  rule=input("enter rule?")
  brule=bytes(rule,'UTF-8')
  (found,tag)=findRule(rule)
  if tag is not None:
    print(found,tag,rule,brule)
    print("ismember ",r.sismember(tag,rule))
    rez=r.srem(tag,rule)
    if rez!=1:
      print("error: ",rule,"not found in ",tag)
      return False
    print(rule,"successfully removed from",tag)
  decide=False
  while not decide:
    print(" ")
    which=input("new tag?")
    bwhich=bytes(which,'UTF-8')
    if len(which)>0:
      print("which",which,"tags",tags)
      if which in ['allowed','blocked','unknown']:
        rez=r.sadd(which,rule)
        if rez==1:
          decide=True
          print(rule,"successfully added to",which)
        else:
          print("error: ","could not add",rule,"to",which) 
      else:
        print("CLASS NOT FOUND")
        decide=True

def removeRule():
  rule=input("enter rule?")
  brule=bytes(rule,'UTF-8')
  (found,tag)=findRule(rule)
  if tag is not None:
    print(found,tag,rule,brule)
    print("ismember ",r.sismember(tag,rule))
    rez=r.srem(tag,rule)
    if rez!=1:
      print("error: ",rule,"not found in tag",tag)
      return False
    print(rule,"successfully removed from tag",tag)

def addRule():
  rule=input("enter rule?")
  brule=bytes(rule,'UTF-8')
  decide=False
  print("tags",tags)
  while not decide:
    print(" ")
    which=input("new tag?")
    bwhich=bytes(which,'UTF-8')
#    print(bwhich,tags)
    if len(which)>0:
      if which in ['blocked','allowed','unknown']:
        rez=r.sadd(which,rule)
        if rez==1:
          decide=True
          print(rule,"successfully added to",which)
        else:
          print("error: ","could not add",rule,"to",which)
      else:
        print("CLASS NOT FOUND")
        decide=True

def importRules(what):
  if what=='axioms':
    delete_db('all')
  elif what=='propositions':
    what=='unknown' 
    delete_db(what)
  elif what=='allowed':
    delete_db('all')
  with open(sfile,'r') as f:
    ns=json.load(f)
  cnt=0
  for an in ns:
    ans=json.dumps(an)
    if r.sismember('allowed',ans):
      print("ignoring rule, already a allowed axiom",ans)
    elif r.sismember('blocked',ans):
      print("ignoring rule, already an blocked axiom",ans)
    else:
      cnt+=1
      rez=r.sadd(what,ans)
      if rez!=1:
        print("error cannot load rule",ans)
        sys.exit()
  print(f"{cnt} rules imported")

def reloadRules():
  print("RELOADING...")
  with open('source/ALLOWED.txt','r') as f:
    ll = [line.strip() for line in f]
  ns=[]
  for l in ll:
    print(l,json.loads(l))
    ns.append(json.loads(l))
  cnt=0
  for an in ns:
    ans=json.dumps(an)
    if r.sismember('allowed',ans):
      print("ignoring rule, already a allowed axiom",ans)
    else:
      cnt+=1
      rez=r.sadd('allowed',ans)
      if rez!=1:
        print("error cannot load rule",ans)
        sys.exit()
      if r.sismember('unknown',ans):
        r.srem('unknown',ans)
  print(f"{cnt} rules loaded as allowed axioms")
  with open('source/BLOCKED.txt','r') as f:
    ll = [line.strip() for line in f]
  ns=[]
  for l in ll:
    print(l,json.loads(l))
    ns.append(json.loads(l))
  cnt=0
  for an in ns:
    ans=json.dumps(an)
    if r.sismember('blocked',ans):
      print("ignoring rule, already an blocked axiom",ans)
    else:
      cnt+=1
      rez=r.sadd('blocked',ans)
      if rez!=1:
        print("error cannot load rule",ans)
        sys.exit()
      if r.sismember('unknown',ans):
        r.srem('unknown',ans)
  print(f"{cnt} rules loaded as blocked axioms")


def listRules(tag):
  res=r.smembers(tag)
  resstr=[]
  for aR in res:
    aR=aR.decode('UTF-8').replace("\'","\"")
    if aR[-1]=="\"":
      aR=aR+"}"
    resstr.append(aR)
  return resstr

if OP=='add':
  addRule()
elif OP=='retag':
  retagRule()
elif OP=='init':
  delete_db('all')
  importRules('unknown')
elif OP=='asof':
  delete_db('unknown')
  importRules('unknown')
elif args.redo:
  delete_db('allowed')
  delete_db('blocked')
  reloadRules()
