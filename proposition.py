#!/usr/bin/python3
import random,math,sys
from simplejson import loads as jloads
import argparse,redis

parser = argparse.ArgumentParser()
parser.add_argument("--db", required=True, type=int, choices=[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15], help="redis database id")
parser.add_argument("--load", required=False, type=str, help="normalized NSG rule to load as proposition in redis cache")
parser.add_argument("--list", required=False, action="store_true",help="list propositions from redis cache")
parser.add_argument("--allow", required=False, action="store_true",help="add a closed axiom to redis")
parser.add_argument("--block", required=False, action="store_true",help="add an open axiom to redis")
parser.add_argument("--prove", required=False, action="store_true",help="add a proposal to redis")
args = parser.parse_args()

DB=args.db
WHAT='unknown'

if args.allow:
  WHAT='closed'
elif args.block:
  WHAT='open'
elif args.prove:
  WHAT='unknown'

r = redis.StrictRedis(host='localhost', port=6379, db=DB)

if args.load and WHAT:
  r.sadd(WHAT,args.load)
  if WHAT=='unknown':
    WHAT="propositions"
  print(f"{args.load} added to {WHAT} in redis")


if args.list:
  unknowns=r.smembers('unknown')
  if len(unknowns)==0:
    print("no propositions to prove.")
  else:
    print("the following proposition(s) must be proved:")
    cnt=0
    for rule in sorted(unknowns):
      cnt+=1
      print("  ",rule.decode('utf-8'))
    print(f"total: {cnt}")
