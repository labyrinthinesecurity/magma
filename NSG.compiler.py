#!/usr/bin/python3
import hashlib,json,redis,copy,logging,time,os
#https://ericpony.github.io/z3py-tutorial/guide-examples.htm
from z3 import *
import random,math,sys
import lex as lex
import yacc as yacc
import argparse, re

def delete_db(scope):
  if scope=='all':
    r.flushdb()
  else:
    members=r.smembers(scope)
    for member in members:
      r.srem(scope,member)

def manage_magma(atag):
  global nrules,tag,closedRules,openRules
  global ClosedRules,ClosedPredicates,OpenRules,OpenPredicates
  magma=[True]
  if atag not in ['closed','open']:
    print(f"unknown tag {tag}")
    sys.exit()
  tag=atag
  nrules=0
  s=loader(tag)
  if len(s)>2:
    lex.lex(debug=False)
    yacc.yacc(debug=False)
    yacc.parse(s)
    cntRules=nrules
    #print(f"{tag} predicates (axioms):",nrules)
    if tag=='closed':
      Rules=sortRules(ClosedRules,ClosedPredicates)
      Predicates=ClosedPredicates
    elif tag=='open':
      Rules=sortRules(OpenRules,OpenPredicates)
      Predicates=OpenPredicates
    magma=Bool('magma')
    magma=False
    for i in range(0,cntRules):
      magma=Or(magma,Predicates[Rules[i]['predicate']])
      #print("DEBUG",Predicates[Rules[i]['predicate']])
  else:
    magma=False
    #print(f"no {tag} axioms found in REDIS")
  return magma

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

def listRules(tag):
  res=r.smembers(tag)
  resstr=[]
  for aR in res:
    aR=aR.decode('UTF-8')
    resstr.append(aR)
  return resstr

def BitVecVector(prefix, sz, N):
  """Create a vector with N Bit-Vectors of size sz"""
  return [ BitVec('%s__%s' % (prefix, i), sz) for i in range(N) ]

def toHex(a1,a2,a3,a4):
  global h1,h2,h3
  return hex(h3*a1+h2*a2+h1*a3+a4)

def toInt(a1,a2,a3,a4):
  global h1,h2,h3
  return (h3*a1+h2*a2+h1*a3+a4)

def IntToIP(intIp):
  a4=intIp%h1
  a3=int(((intIp-a4)/h1)%h1)
  a2=int((((intIp-a4)/h1)/h1)%h1)
  a1=int(((((intIp-a4)/h1)/h1)/h1)%h1)
  return str(a1)+"."+str(a2)+"."+str(a3)+"."+str(a4)

def toHexLow(intip,mask):
  bip=bin(intip)
  m=int(math.pow(2,mask)-1)
  m=m << (32 - mask)
  return hex(m & intip)

def toIntLow(intip,mask):
  bip=bin(intip)
  m=int(math.pow(2,mask)-1)
  m=m << (32 - mask)
  return int(m & intip)

def toHexHigh(intip,mask):
  bip=bin(intip)
  n=int(math.pow(2,32-mask)-1)
  return hex( n | intip)

def toIntHigh(intip,mask):
  bip=bin(intip)
  n=int(math.pow(2,32-mask)-1)
  return int( n | intip)

def sortRules(rlist,preds):
  rr=[]
  cnt=0
  for aC in rlist:
    aR={}
    aR['rule']=aC
    aR['hash']=hashlib.md5(str(aC).encode('utf-8')).hexdigest()
    aR['predicate']=cnt
    rr.append(aR)
    cnt=cnt+1
  rr.sort(key=theHash)
  rlist=[]
  return rr

def theHash(r):
  return r['hash']

### lex and yacc rules follow

def t_NUMBER(t):
    r'\d+'
    t.value = int(t.value)
    return t

def t_newline(t):
    r'\n+'
    t.lexer.lineno += t.value.count("\n")

def t_error(t):
    print(f"Illegal character {t.value[0]!r}")
    sys.exit()
#    t.lexer.skip(1)

def p_list(p):
  '''list : LEFTB itemopt RIGHTB'''
  p[0] = ('LIST', p[1])

def p_itemopt(p):
  '''itemopt : itemopt COMMA item
               | item'''
  if p[0] is None:
    p[0]=p[1]
  if len(p)>2:
    p[0].append(p[3])

def p_item(p):
  '''item :  LEFTC kvopt RIGHTC'''
  global nrules
  global rules
  global cubes 
  global sip
  global dport
  global tag
  global prt
  p[0]=p[2]
  siplo=None
  siphi=None
  diplo=None
  diphi=None
  plo=None
  phi=None
  sazTAG=False
  sazTAGval=0
  dazTAG=False
  dazTAGval=0
  sazVNET=False
  dazVNET=False
  sazVNETval=0
  dazVNETval=0
  protolo=None
  protohi=None
  for aP in p[0]:
    if aP[0]=='PROTORANGE':
      protolo=aP[1]
      protohi=aP[2]
    if aP[0]=="PORTRANGE":
      plo=aP[1]
      phi=aP[2]
    if aP[0]=="SIPRANGE":
      siplo=aP[1]
      siphi=aP[2]
    if aP[0]=="SAZURETAG":
      sazTAG=True
      sazTAGval=aP[1]
    if aP[0]=="DIPRANGE":
      diplo=aP[1]
      diphi=aP[2]
    if aP[0]=="DAZURETAG":
      dazTAG=True
      dazTAGval=aP[1]
    if aP=="SAZVNET":
      sazVNET=True
      sazVNETval=1
    if aP=="DAZVNET":
      dazVNET=True
      dazVNETval=1
  if (plo is not None) and (phi is not None) and (protolo is not None):
    Portlows[nrules]=plo
    Porthighs[nrules]=phi
    Protolows[nrules]=protolo
    Protohighs[nrules]=protohi
    if tag=="closed":
      Predicates=ClosedPredicates
      Rules=ClosedRules
    elif tag=="open":
      Predicates=OpenPredicates
      Rules=OpenRules
    elif tag=="singleRule":
      Predicates=SingleRulePredicate
      Rules=SingleRule
    else:
      print("unknown tag...")
      sys.exit()
    if (sazTAG==False) and (sazVNET==False) and (siplo is not None) and (siphi is not None):
      sIPlows[nrules]=siplo
      sIPhighs[nrules]=siphi
      if nrules>0:
        Predicates[nrules]=And(UGE(prt,Protolows[nrules]),ULE(prt,Protohighs[nrules]),hasSIP,UGE(sip,sIPlows[nrules]),ULE(sip,sIPhighs[nrules]),saztagval==zeroVal,sazvnetval==zeroVal)
      else:
        Predicates[nrules]=And(UGE(prt,Protolows[nrules]),ULE(prt,Protohighs[nrules]),hasSIP,UGE(sip,sIPlows[nrules]),ULE(sip,sIPhighs[nrules]),saztagval==zeroVal,sazvnetval==zeroVal)
    elif (sazTAG==True):
      if nrules>0:
        Predicates[nrules]=And(UGE(prt,Protolows[nrules]),ULE(prt,Protohighs[nrules]),hasSIP==zFalse,sazTAGval==saztagval,sazvnetval==zeroVal)
      else:
          Predicates[nrules]=And(UGE(prt,Protolows[nrules]),ULE(prt,Protohighs[nrules]),hasSIP==zFalse,sazTAGval==saztagval,sazvnetval==zeroVal)
    elif (sazVNET==True):
      if nrules>0:
        Predicates[nrules]=And(UGE(prt,Protolows[nrules]),ULE(prt,Protohighs[nrules]),hasSIP==zFalse,sazVNETval==sazvnetval,saztagval==zeroVal)
      else:
          Predicates[nrules]=And(UGE(prt,Protolows[nrules]),ULE(prt,Protohighs[nrules]),hasSIP==zFalse,sazVNETval==sazvnetval,saztagval==zeroVal)
    else:
      print("something nasty happened...",sazTAG,sazTAGval,sazVNET,p[0])
      sys.exit()
    if (dazTAG==False) and (dazVNET==False) and (diplo is not None) and (diphi is not None):
      dIPlows[nrules]=diplo
      dIPhighs[nrules]=diphi
      if nrules>0:
        Predicates[nrules]=And(Predicates[nrules],hasDIP,UGE(dip,dIPlows[nrules]),ULE(dip,dIPhighs[nrules]),UGE(dport,Portlows[nrules]),ULE(dport,Porthighs[nrules]))
      else:
        Predicates[nrules]=And(Predicates[nrules],hasDIP,UGE(dip,dIPlows[nrules]),ULE(dip,dIPhighs[nrules]),UGE(dport,Portlows[nrules]),ULE(dport,Porthighs[nrules]))
    elif (dazTAG==True):
      if nrules>0:
        Predicates[nrules]=And(Predicates[nrules],hasDIP==zFalse,dazTAGval==daztagval,dazvnetval==zeroVal,UGE(dport,Portlows[nrules]),ULE(dport,Porthighs[nrules]))
      else:
        Predicates[nrules]=And(Predicates[nrules],hasDIP==zFalse,dazTAGval==daztagval,dazvnetval==zeroVal,UGE(dport,Portlows[nrules]),ULE(dport,Porthighs[nrules]))
    elif (dazVNET==True):
      if nrules>0:
        Predicates[nrules]=And(Predicates[nrules],hasDIP==zFalse,dazVNETval==dazvnetval,daztagval==zeroVal,UGE(dport,Portlows[nrules]),ULE(dport,Porthighs[nrules]))
      else:
        Predicates[nrules]=And(Predicates[nrules],hasDIP==zFalse,dazVNETval==dazvnetval,daztagval==zeroVal,UGE(dport,Portlows[nrules]),ULE(dport,Porthighs[nrules]))
    else:
      print("major problem...",sazTAG,sazTAGval,sazVNET,p[0])
      sys.exit()
    rr=copy.deepcopy(p[0])
    rl=[]
    for aR in rr:
      if aR[0] in ['SIPRANGE','DIPRANGE']:
        aR=(aR[0],IntToIP(aR[1]),IntToIP(aR[2]))
      rl.append(aR)
    Rules.append(rl)
  else:
    print("major problem...",p[0])
    sys.exit()
  nrules=nrules+1

def p_kvopt(p):
  '''kvopt :  kvopt COMMA kv
           | kvopt DASH kv
           | kv'''
  if p[0] is None:
    p[0]=p[1]
  if len(p)>2:
    p[0].append(p[3])
  else:
    p[0]=[p[1]]

def p_kv(p):
  '''kv : PROTOK SEMI protovw 
        | SAPK SEMI scidr
        | SAPK SEMI sdashrange
        | DAPK SEMI dcidr
        | DAPK SEMI ddashrange
        | DPORTK SEMI dport'''
  p[0]=p[3]

def p_protovw(p):
  '''protovw : PROTOV1
             | PROTOV2
             | PROTOV4
             | WILDCARD'''
  if p[1]=='*':
    p[0]=('PROTORANGE',0,2)  # TCP,UDP,ICMP
  elif p[1]=='TCP':
    p[0]=('PROTORANGE',0,0) 
  elif p[1]=='UDP':
    p[0]=('PROTORANGE',1,1)
  elif p[1]=='ICMP':
    p[0]=('PROTORANGE',2,2)

def p_sdashrange(p):
  '''sdashrange : NUMBER DOT NUMBER DOT NUMBER DOT NUMBER DASH NUMBER DOT NUMBER DOT NUMBER DOT NUMBER'''
  p[0]=('SIPRANGE',toInt(p[1],p[3],p[5],p[7]),toInt(p[9],p[11],p[13],p[15]))

def p_ddashrange(p):
  '''ddashrange : NUMBER DOT NUMBER DOT NUMBER DOT NUMBER DASH NUMBER DOT NUMBER DOT NUMBER DOT NUMBER'''
  p[0]=('DIPRANGE',toInt(p[1],p[3],p[5],p[7]),toInt(p[9],p[11],p[13],p[15]))

def p_scidr(p):
  '''scidr : NUMBER DOT NUMBER DOT NUMBER DOT NUMBER maskopt
         | AZVNET
         | AZTAG1
         | AZTAG2
         | AZTAG3
         | AZTAG4
         | AZTAG5
         | AZTAG6
         | AZTAG7
         | WILDCARD'''
  if len(p)>8 and p[8] is not None:
    p[0]=('SIPRANGE',toIntLow(toInt(p[1],p[3],p[5],p[7]),p[8]),toIntHigh(toInt(p[1],p[3],p[5],p[7]),p[8]))
  elif len(p)>7:
    p[0]=('SIPRANGE',toInt(p[1],p[3],p[5],p[7]),toInt(p[1],p[3],p[5],p[7]))
  else:
    if p[1]=='*':
#      p[0]=('SIPRANGE',0,4294967295)
      p[0]=('SIPRANGE',1,4294967294)
    elif p[1]=="VirtualNetwork":
      p[0]=('SAZVNET')
    else:
      if p[1]=='AppServiceManagement':
        p[0]=('SAZURETAG',1)
      elif p[1]=='AzureLoadBalancer':
        p[0]=('SAZURETAG',2)
      elif p[1]=='ApiManagement':
        p[0]=('SAZURETAG',3)
      elif p[1][:7]=='Storage':
        p[0]=('SAZURETAG',4)
      elif p[1]=='BatchNodeManagement':
        p[0]=('SAZURETAG',5)
      elif p[1]=='ServiceFabric':
        p[0]=('SAZURETAG',6)
      elif p[1][:9]=='HDInsight':
        p[0]=('SAZURETAG',7)
      else:
        p[0]=('SAZURETAG',0)
        print("ERROR! unknown stagval",p)
        sys.exit()

def p_dcidr(p):
  '''dcidr : NUMBER DOT NUMBER DOT NUMBER DOT NUMBER maskopt
         | AZVNET
         | AZTAG1
         | AZTAG2
         | AZTAG3
         | AZTAG4
         | AZTAG5
         | AZTAG6
         | AZTAG7
         | WILDCARD'''
  if len(p)>8 and p[8] is not None:
    p[0]=('DIPRANGE',toIntLow(toInt(p[1],p[3],p[5],p[7]),p[8]),toIntHigh(toInt(p[1],p[3],p[5],p[7]),p[8]))
  elif len(p)>7:
    p[0]=('DIPRANGE',toInt(p[1],p[3],p[5],p[7]),toInt(p[1],p[3],p[5],p[7]))
  else:
    if p[1]=='*':
#      p[0]=('DIPRANGE',0,4294967295)
      p[0]=('DIPRANGE',1,4294967294)
    elif p[1]=="VirtualNetwork":
      p[0]=('DAZVNET')
    else:
      if p[1]=='AppServiceManagement':
        p[0]=('DAZURETAG',1)
      elif p[1]=='AzureLoadBalancer':
        p[0]=('DAZURETAG',2)
      elif p[1]=='ApiManagement':
        p[0]=('DAZURETAG',3)
      elif p[1][:7]=='Storage':
        p[0]=('DAZURETAG',4)
      elif p[1]=='BatchNodeManagement':
        p[0]=('DAZURETAG',5)
      elif p[1]=='ServiceFabric':
        p[0]=('DAZURETAG',6)
      elif p[1][:9]=='HDInsight':
        p[0]=('DAZURETAG',7)
      else:
        p[0]=('DAZURETAG',0)
        print("ERROR! unknown dtagval",p)
        sys.exit()

def p_maskopt(p):
  '''maskopt : SLASH NUMBER
             | empty'''
  if len(p)>2:
    p[0]=p[2]
  else:
    pass

def p_empty(p):
  'empty :'
  pass

def p_dport(p):
  '''dport : NUMBER
           | WILDCARD
           | NUMBER DASH NUMBER'''
  if len(p)>2:
    p[0]=('PORTRANGE', p[1], p[3])
  else:
    if p[1]=='*':
#      p[0]=('PORTRANGE', 0, 65535)
      p[0]=('PORTRANGE', 1, 65534)
    else:
      p[0]=('PORTRANGE', p[1], p[1])

def p_error(p):
    print(nrules)
    print(f"Syntax error at {p.value!r}")
    sys.exit()

def loader(tag):
  rules=[]
  membs=r.smembers(tag)
  cnt=0
  for aM in membs:
    aR=aM.decode('UTF-8')
    aR=aR.replace("\'","\"")
    if aR[-1]=="\"":
      aR=aR+"}"
    rules.append(aR)
    cnt=cnt+1
#  random.shuffle(rules)
  srules=str(rules)
  srules=srules.replace("\'","\"")
  return srules

## ALLBVSAT logic follows

def generate_Sprime(Sk,index):
  Sprime=[]
  i=0
  for aS in Sk:
    if i==index:
      Sprime.append([])
    else:
      Sprime.append(aS)
    i=i+1
  Sp=cubify(Sk,index)
  return Sprime,Sp

def substitute_Sprime(Sk,index,B,phi):
  Sprime=[]
  i=0
  for aS in Sk:
    if i==index:
      if ((i==0) and (phi['SVNET']==False) and (phi['STAG']==False)):
        Sprime.append(phi['indexes'][i])
      elif (i==0) and phi['STAG']:
        if phi['SVAL']==1:
          Sprime.append([t_AZTAG1])
        if phi['SVAL']==2:
          Sprime.append([t_AZTAG2])
        if phi['SVAL']==3:
          Sprime.append([t_AZTAG3])
        if phi['SVAL']==4:
          Sprime.append(['Storage'])
        if phi['SVAL']==5:
          Sprime.append([t_AZTAG5])
        if phi['SVAL']==6:
          Sprime.append([t_AZTAG6])
        if phi['SVAL']==7:
          Sprime.append(['HDInsight'])
      elif (i==0 and phi['SVNET']==True):
        Sprime.append([t_AZVNET])
      elif ((i==1) and (phi['DVNET']==False)):
        Sprime.append(phi['indexes'][i])
      elif (i==1) and phi['DVNET']==True:
        Sprime.append([t_AZVNET])
      elif i==2:
        Sprime.append(phi['indexes'][i])
    i=i+1
  Sp=cubify(Sk,index)
  return Sprime,Sp

def maxBVSAT(S,k,index,formula):
  #print("")
  #print(k,index,"MAXBVSAT Sk BEFORE",S[k])
  cont=True
  breakout=False
  origSi=S[k][index]
  #print(k,index,"ORIGSI len",len(origSi))
  #for i in range(0,index+1):
  #  print("  index ",i,S[k][i])
  #if len(origSi)>1:
  #  print(origSi[0],origSi[1])
  #else:
  #  print("mm... at index",index)
  Sprime,Sp=generate_Sprime(S[k],index)
  SK=cubify(S[k],None)
  opt=Optimize()
  opt.add(SK)
  sol=Solver()
  sol.add(constraints)
  sol.add(Implies(hasSIP,And(saztagval==0,sazvnetval==0)),Implies(hasDIP,And(daztagval==0,dazvnetval==0)))
  sol.add(Implies(UGE(sip,0),hasSIP),Implies(UGE(dip,0),hasDIP))
  sol.add(Implies(Not(hasSIP),Xor(saztagval>0,sazvnetval>0)),Implies(Not(hasDIP),Xor(daztagval>0,dazvnetval>0)))
  maxSi=9999999999999999999999
  if index==0:
    choice=sip
  elif index==1:
    choice=dip
  elif index==2:
    choice=dport
  elif index==3:
    choice=prt
  opt.maximize(choice)
  if opt.check() == sat:
    model = opt.model()
    maxSi = model[choice].as_long()
  else:
    print("ERR: cannot optimize",index,choice,S[k],k)
    print(SK)
    sys.exit()
  sl=str(maxSi)
  #print("maxSi",maxSi)
  B=And(Sp,Not(formula))   # B = not(phi) ^x belongs to Sp. Not(formula)=OR(before,Not(Z3proposition))
  while cont and not breakout:
    #print(' initial Sp',Sp)
#    print(index,'maxSi',maxSi)
    #print("current B",B)
    BS=''
    if (index==0):
      B=And(B,UGT(sip,maxSi))   # B = not(phi)  ^x belongs to Sp ^  xi > maxSi
      BS='And(B,UGT(sip,'+sl+'))'
    elif (index==1):
      B=And(B,UGT(dip,maxSi))
      BS='And(B,UGT(dip,'+sl+'))'
    elif (index==2):
      B=And(B,UGT(dport,maxSi))
      BS='And(B,UGT(dport,'+sl+'))'
    elif (index==3):
      B=And(B,UGT(prt,maxSi))
      BS='And(B,UGT(prt,'+sl+'))'
    sol.add(B)
    init=True
    c=sol.check()
    #print("ISmaxBVSAT?",c,"for maxSi",maxSi,BS)
    if c==unsat:
      cont=False
      l=maxSi+1
    else:
      l=maxSi
    l0=maxSi
    while c==sat:
      m=sol.model()
      #print("MAX sol",m)
      if init:
        l0=l
        init=False
      for aM in m:
        if str(aM)=='sip' and index==0:
          l=m[aM].as_long()
          break
        elif str(aM)=='dip' and index==1:
          l=m[aM].as_long()
          break
        elif str(aM)=='dport' and index==2:
          l=m[aM].as_long()
          break
        elif str(aM)=='prt' and index==3:
          l=m[aM].as_long()
          break
      sl=str(l)
      #print("SOL was",maxSi,"now",l)
      l0=l
      sol.push()
      if index==0:
        sol.add(And(ULT(sip,l0)))
      elif (index==1):
        sol.add(And(ULT(dip,l0)))
      elif (index==2):
        sol.add(And(ULT(dport,l0)))
      elif (index==3):
        sol.add(And(ULT(prt,l0)))
      c=sol.check()
      if c==unsat:
        sol.pop()
        #print(f"UNSAT! moving below {l0} would move us from Not(formula) to fomula",l)
        S[k][index][1]=l0-1 # l0 in Not(formula), l-1 in formula => maxsi is lower than l0
        maxSi=l0-1
        cont=False
      else:
        #print("SAT! there is still room below",l)
        sol.pop()
        if index==0:
          sol.add(And(ULT(sip,l)))
        elif (index==1):
          sol.add(And(ULT(dip,l)))
        elif (index==2):
          sol.add(And(ULT(dport,l)))
        elif (index==3):
          sol.add(And(ULT(prt,l)))
        c=sol.check()
        if c==unsat:
          breakout=True
          S[k][index][1]=l-1
          maxSi=l-1
        else:
          pass
  i=0
  capRange=0
  for aS in S[k]:
    if index==i:
      if capRange>CAP:
        print("ERROR: cap reached in maxBVSAT",index,maxSi)
        sys.exit()
      else:
         if maxSi<9999999999999999999999:
           S[k][i]=[min(maxSi,origSi[0],origSi[1]),max(maxSi,origSi[0],origSi[1])]
         else:
           S[k][i]=[min(origSi[0],origSi[1]),max(origSi[0],origSi[1])]
    i=i+1
  #print(k,index,"MAXBVSAT AFTER",S[k])
  return S[k]

def minBVSAT(S,k,index,formula):
  #print("")
  #print(k,index,"minBVSAT Sk BEFORE",S[k])
  cont=True
  breakout=False
  origSi=S[k][index]
  #print(k,index,"ORIGSI len",len(origSi))
  #for i in range(0,index+1):
  #  print("  index ",i,S[k][i])
  #if len(origSi)>1:
  #  print(origSi[0],origSi[1])
  #else:
  #  print("mm... at index",index)
  Sprime,Sp=generate_Sprime(S[k],index)
  SK=cubify(S[k],None)
  opt=Optimize()
  opt.add(SK)
  sol=Solver()
  sol.add(constraints)
  sol.add(Implies(hasSIP,And(saztagval==0,sazvnetval==0)),Implies(hasDIP,And(daztagval==0,dazvnetval==0)))
  sol.add(Implies(UGE(sip,0),hasSIP),Implies(UGE(dip,0),hasDIP))
  sol.add(Implies(Not(hasSIP),Xor(saztagval>0,sazvnetval>0)),Implies(Not(hasDIP),Xor(daztagval>0,dazvnetval>0)))
  minSi=-1
  if index==0:
    choice=sip
  elif index==1:
    choice=dip
  elif index==2:
    choice=dport
  elif index==3:
    choice=prt
  opt.minimize(choice)
  if opt.check() == sat:
    model = opt.model()
    minSi = model[choice].as_long()
  else:
    print("ERR: cannot optimize",index,choice,S[k],k)
    print(SK)
    sys.exit()
  sl=str(minSi)
  #print("minSi",minSi)
  B=And(Sp,Not(formula)) # B = not(phi) ^x belongs to Sp.  Not(formula)=Or(Not(Z3proposition),before)
  while cont and not breakout:
    #print("initial Sp",Sp)
    #print("current B",B)
    BS=''
    if index==0:
      B=And(B,ULT(sip,minSi))  # B = not(phi) ^x belongs to Sp ^ xi < minSi
      BS='And(B,ULT(sip,'+sl+'))'  
    elif index==1:
      B=And(B,ULT(dip,minSi))
      BS='And(B,ULT(dip,'+sl+'))'
    elif index==2:
      B=And(B,ULT(dport,minSi))
      BS='And(B,ULT(dport,'+sl+'))'
    elif index==3:
      B=And(B,ULT(prt,minSi))
      BS='And(B,ULT(prt,'+sl+'))'
    sol.add(B)
    init=True
    c=sol.check()
    #print("ISminBVSAT?",c,"for minSi",minSi,BS)
    if c==unsat:
      cont=False
      l=minSi-1
    else:
      l=minSi
    l0=minSi
    while c==sat:  # while B is SATisfiable do
      m=sol.model() # l <- the satisfying assignment to xi
      #print("MIN sol",m)
      if init:
        l0=l
        init=False
      for aM in m:
        if str(aM)=='sip' and index==0:
          l=m[aM].as_long()
          break
        elif str(aM)=='dip' and index==1:
          l=m[aM].as_long()
          break
        elif str(aM)=='dport' and index==2:
          l=m[aM].as_long()
          break
        elif str(aM)=='prt' and index==3:
          l=m[aM].as_long()
          break
      sl=str(l)
      #print("SOL was",minSi,"now",l)
      l0=l
      sol.push()
      if index==0:
        sol.add(And(UGT(sip,l0)))
      elif (index==1):
        sol.add(And(UGT(dip,l0)))
      elif (index==2):
        sol.add(And(UGT(dport,l0)))
      elif (index==3):
        sol.add(And(UGT(prt,l0)))
      c=sol.check()
      if c==unsat:
        sol.pop()
        #print(f"UNSAT moving above {l0} would move us from Not(formula) to formula")
        S[k][index][0]=l0+1  # l0 in Not(formula), above l0 in formula => l0+1 is minSi
        minSi=l0+1
        cont=False
      else:
        #print("SAT! there is still room",l,minSi)
        sol.pop()
        if index==0:
          sol.add(And(UGT(sip,l)))
        elif (index==1):
          sol.add(And(UGT(dip,l)))
        elif (index==2):
          sol.add(And(UGT(dport,l)))
        elif (index==3):
          sol.add(And(UGT(prt,l)))
        c=sol.check()
        if c==unsat:
          breakout=True
          S[k][index][0]=l+1
          minSi=l+1
        else:
          pass
    i=0
    capRange=0
    for aS in S[k]:
      if index==i:
        if capRange>CAP:
          print("ERROR: cap reached in minBVSAT")
          sys.exit()
        else:
          if minSi>=0:
            S[k][i]=[min(minSi,origSi[0],origSi[1]),max(minSi,origSi[0],origSi[1])]
          else:
            S[k][i]=[min(origSi[0],origSi[1]),max(origSi[0],origSi[1])]
      i=i+1
  #print(k,index,"minBVSAT AFTER",S[k])
  return S[k]

def cubify(Sk,idx):
  SK=And(True)
  index=-1
  for aS in Sk:
    index+=1
    if idx is not None:
      if index==idx:
        continue
    if len(aS)==1:  
      if str(aS[0])==aS[0]: # it is a TAG, not an interval of integers
        if str(aS[0])=='VirtualNetwork':
          if index==0:
            SK=And(SK,sazvnetval==1,saztagval==0,hasSIP==False)
          elif index==1:
            SK=And(SK,dazvnetval==1,daztagval==0,hasDIP==False)
        else:   # this is an Azure Network tag different from VNET
          stv=0
          dtv=0
          if index==0:
            if str(aS[0])=='AppServiceManagement':
              stv=1
            elif str(aS[0])=='AzureLoadBalancer':
              stv=2
            elif str(aS[0])=='ApiManagement':
              stv=3
            elif str(aS[0])=='Storage':
              stv=4
            elif str(aS[0])=='BatchNodeManagement':
              stv=5
            elif str(aS[0])=='ServiceFabric':
              stv=6
            elif str(aS[0])=='HDInsight':
              stv=7
            SK=And(SK,sazvnetval==0,saztagval==stv,hasSIP==False)
          elif index==1:
            if str(aS[0])=='AppServiceManagement':
              dtv=1
            elif str(aS[0])=='AzureLoadBalancer':
              dtv=2
            elif str(aS[0])=='ApiManagement':
              dtv=3
            elif str(aS[0])=='Storage':
              dtv=4
            elif str(aS[0])=='BatchNodeManagement':
              dtv=5
            elif str(aS[0])=='ServiceFabric':
              dtv=6
            elif str(aS[0])=='HDInsight':
              dtv=7
            SK=And(SK,dazvnetval==0,daztagval==dtv,hasDIP==False)
    elif len(aS)==2:   # an interval of integers
      if index==0:
        op='And(sazvnetval==0,saztagval==0,hasSIP,UGE(sip,'+str(aS[0])+'),ULE(sip,'+str(aS[1])+'))'
      elif index==1:
        op='And(dazvnetval==0,daztagval==0,hasDIP,UGE(dip,'+str(aS[0])+'),ULE(dip,'+str(aS[1])+'))'
      elif index==2:
        op='And(UGE(dport,'+str(aS[0])+'),ULE(dport,'+str(aS[1])+'))'
      elif index==3:
        op='And(UGE(prt,'+str(aS[0])+'),ULE(prt,'+str(aS[1])+'))'
      OPE=eval(op)
      SK=And(SK,OPE)
  return SK 

def coalesceInterval(interval,intervalType):
  if len(interval)>1:
    minVal=min(interval[0],interval[1])
    maxVal=max(interval[0],interval[1])
  elif len(interval)==1:
    minVal=interval[0]
    maxVal=interval[0]
  else:
    print("interval error")
    sys.exit()
  if intervalType=='IP':
    if (minVal!=t_AZVNET) and (minVal not in [t_AZTAG1,t_AZTAG2,t_AZTAG3,'Storage',t_AZTAG5,t_AZTAG6,'HDInsight']):
      minVal=IntToIP(minVal)
      maxVal=IntToIP(maxVal)
  cinterval=str(minVal)
  if maxVal!=minVal:
    cinterval=cinterval+'-'+str(maxVal)
  return cinterval

def coalesce(cube):
  ccube=[]
  i=-1
  for interval in cube:
    i+=1
    if i<2:
      intervalType='IP'
    else:
      intervalType='INT16'
    cinterval=coalesceInterval(interval,intervalType)
    if i==3 and cinterval=='1-4':
      cinterval='7'
    ccube.append(cinterval)
  return ccube

def extend(Sk,phi,B):
  for index in range(0,1,2,3):
    Sprime,Sp=substitute_Sprime(Sk,index,B,phi) 
    A=And(Not(B),Sp)
    sol=Solver()
    c=sol.check()
    if c==unsat:
      sol=Solver()
      if index==0:
        A=And(phi[index],S[index])
      elif index==1:
        A=And(phi[index],S[index])
      elif index==2:
        A=And(phi[index],S[index])
      elif index==3:
        A=And(phi[index],S[index])
      c=sol.check(A)
      if c==unsat:
        minBVSAT
  return Sk
    
def ALLBVSAT(Z3proposition,magma):
  global tag
  global nrules
  k=0
  S={}
  sol=Solver()
#  sol.add(constraints)
  sol.add(Implies(hasSIP,And(saztagval==0,sazvnetval==0)),Implies(hasDIP,And(daztagval==0,dazvnetval==0)))
  NSK=BoolVector('NSK',10000)
  formula=And(Not(magma),Z3proposition)   # what's new
  sol.add(formula)
  c=sol.check()
  init=True
  print("ALLBVSAT check",c)
  while c==sat:
    S[k]=[]
    asn=True
    m=sol.model()
    aSip=[]
    aDip=[]
    aDport=[]
    aPrt=[]
    phi={}
    notphi={}
    phi['indexes']=[0,0,0,0]   # sip, dip, dport, proto
    phi['SVNET']=False
    phi['STAG']=False
    phi['SVAL']=-1
    phi['DTAG']=False
    phi['DVAL']=-1
    phi['DVNET']=False
    #print("** here is a satisfiable solution for iteration",k)
    for aM in m:
      #print("  ",aM,m[aM])
      if str(aM)=='sip':
        aSip=m[aM].as_long()
        phi['indexes'][0]=m[aM]
        asn=And(asn,sip==phi['indexes'][0])
      elif str(aM)=='dip':
        aDip=m[aM].as_long()
        phi['indexes'][1]=m[aM]
        asn=And(asn,dip==phi['indexes'][1])
      elif str(aM)=='dport':
        aDport=m[aM].as_long()
        phi['indexes'][2]=m[aM]
        asn=And(asn,dport==phi['indexes'][2])
      elif str(aM)=='dazvnetval':
        if (m[aM].as_long()==1):
          phi['DVNET']=True
          asn=And(asn,dazvnetval==1)
      elif str(aM)=='sazvnetval':
        if (m[aM].as_long()==1):
          phi['SVNET']=True
          asn=And(asn,sazvnetval==1)
      elif str(aM)=='saztagval':
        if (m[aM].as_long()>0):
          phi['STAG']=True
          phi['SVAL']=m[aM].as_long()
          asn=And(asn,saztagval==phi['SVAL'])
      elif str(aM)=='daztagval':
        if (m[aM].as_long()>0):
          phi['DTAG']=True
          phi['DVAL']=m[aM].as_long()
          asn=And(asn,daztagval==phi['DVAL'])
      elif str(aM)=='prt':
        aPrt=m[aM].as_long()
        phi['indexes'][3]=m[aM]
        asn=And(asn,prt==phi['indexes'][3])
    nasn=Not(asn)
    if (phi['STAG']==False) and (phi['SVNET']==False):
      S[k].append([aSip,aSip])
    elif phi['STAG']==True:
      if phi['SVAL']==1:
        S[k].append([t_AZTAG1])
      if phi['SVAL']==2:
        S[k].append([t_AZTAG2])
      if phi['SVAL']==3:
        S[k].append([t_AZTAG3])
      if phi['SVAL']==4:
        S[k].append(['Storage'])
      if phi['SVAL']==5:
        S[k].append([t_AZTAG5])
      if phi['SVAL']==6:
        S[k].append([t_AZTAG6])
      if phi['SVAL']==7:
        S[k].append(['HDInsight'])
    elif phi['SVNET']==True:
      S[k].append([t_AZVNET])
    if (phi['DTAG']==False) and (phi['DVNET']==False):
      S[k].append([aDip,aDip])
    elif phi['DTAG']==True:
      if phi['DVAL']==1:
        S[k].append([t_AZTAG1])
      if phi['DVAL']==2:
        S[k].append([t_AZTAG2])
      if phi['DVAL']==3:
        S[k].append([t_AZTAG3])
      if phi['DVAL']==4:
        S[k].append(['Storage'])
      if phi['DVAL']==5:
        S[k].append([t_AZTAG5])
      if phi['DVAL']==6:
        S[k].append([t_AZTAG6])
      if phi['DVAL']==7:
        S[k].append(['HDInsight'])
    elif phi['DVNET']==True:
      S[k].append([t_AZVNET])
    S[k].append([aDport,aDport])
    S[k].append([aPrt,aPrt])
    #print(k,"about to pass this phi to BVSAT",phi)
    #print(k,"inpout Sk",S[k])
    #print(k,"this nasn",nasn)
    for index in (0,1,2,3): #index values 0=sip, 1=dip, 2=dport, 3=proto
      if ((index==0) and (phi['SVNET']==False) and (phi['STAG']==False)):
        S[k]=minBVSAT(S,k,index,formula)
        S[k]=maxBVSAT(S,k,index,formula)
      elif ((index==0) and (phi['STAG']==True)):
        pass
      elif ((index==0) and (phi['SVNET']==True)):
        pass
      elif ((index==1) and (phi['DVNET']==False) and (phi['DTAG']==False)):
        S[k]=minBVSAT(S,k,index,formula)
        S[k]=maxBVSAT(S,k,index,formula)
      elif ((index==1) and (phi['DVNET']==True)):
        pass
      elif ((index==1) and (phi['DTAG']==True)):
        pass
      elif (index==2) or (index==3):
        S[k]=minBVSAT(S,k,index,formula)
        S[k]=maxBVSAT(S,k,index,formula)
    #print(k,"CUBE -> ",S[k])
    NSK[k]=Not(cubify(S[k],None))  # B <- B ^ xi doesnt belong to Sk
    if init:
      nasn=NSK[k]
      init=False
    else:
      nasn=And(nasn,NSK[k])
    formula=And(formula,nasn)
    sol=Solver()
    sol.add(formula)
    sol.add(constraints)
    sol.add(Implies(hasSIP,And(saztagval==0,sazvnetval==0)),Implies(hasDIP,And(daztagval==0,dazvnetval==0)))
    c=sol.check()
    k=k+1
  coalescedCubes=[]
  print("XS",S)
  for aCubeIndex in S:
    coalescedCube=coalesce(S[aCubeIndex])
    coalescedCubes.append(coalescedCube)
  rzs=[]
  for ac in coalescedCubes:
    rz={}
    rz['protocol']=ac[3]
    rz['sourceAddressPrefix']=ac[0]
    rz['destinationAddressPrefix']=ac[1]
    rz['destinationPort']=ac[2]
    rzs.append(rz)
  return c,rzs

def intersect(proposition,partition):
  global ClosedRules,ClosedPredicates,OpenRules,OpenPredicates
  global nrules,closedRules,openRules,s,tag,magma
  before=manage_magma(partition)
  if partition=='closed':
    cntRules=closedRules
    Predicates=ClosedPredicates
    Rules=ClosedRules
  elif partition=='open':
    cntRules=openRules
    Predicates=OpenPredicates
    Rules=OpenRules
  else:
    print("Intersection error")
    sys.exit()
  if before is None:
    before=False
  tag='singleRule'
  nrules=0
  sol=Solver()
  if proposition is None:
    RXL='[]'
    RXpredicate=True
  else:
    RXL='['+str(proposition)+']'
  lex.lex(debug=False)
  yacc.yacc(debug=False)
  yacc.parse(RXL)
  RXpredicate=Bool('RXpredicate')
  RXpredicate=SingleRulePredicate[0]
  #print("BEFORE",before)
  formula=And(before,RXpredicate)
  #print("PROPOSITION",RXpredicate)
  sol.add(Implies(hasSIP,And(saztagval==0,sazvnetval==0)),Implies(hasDIP,And(daztagval==0,dazvnetval==0)))
  sol.add(formula)
  c=sol.check()
  if c==sat:
    pass
#    print(f"  intersection found between this proposition and {partition} axioms")
#    print("MODEL",sol.model())
  else:
    pass
    #print(f"NO intersection found between this proposition and {partition} axioms")
  return c,before,RXpredicate


def prove(aproposition,quotient):
  global OpenPredicates,ClosedPredicates,OpenRules,ClosedRules,Rules,openRules,closedRules,magma_open,magma_closed
  mode='commit'
  if not aproposition:
    mode='search'
    l=listRules('unknown')
    if (len(l))==0:
      print("no proposition found")
      return None
  else:
    l=[aproposition]
  cnt=0
  for proposition in l:
    ClosedRules=[]
    OpenRules=[]
    Rules=[]
    openRules=0
    closedRules=0
    for i in range(0,PREDICATES_CAP):
      OpenPredicates[i]=True
    for i in range(0,PREDICATES_CAP):
      ClosedPredicates[i]=True
    SingleRulePredicate[0]=True
    cnt+=1
    print(f"PROPOSITION {cnt}",proposition)
    intc,magma_closed,Z3proposition=intersect(proposition,'closed')
    into,magma_open,Z3proposition=intersect(proposition,'open')
    if (quotient=='allow' or quotient=='closed') and aproposition:
      recfile='ALLOWED.txt'
    elif (quotient=='block' or quotient=='open')  and aproposition:
      recfile='BLOCKED.txt'
    else:
      recfile=None
    if intc==unsat and into==unsat:
      print(f"  proposition {cnt} is fully undetermined. No passlets can be extracted.")
      if mode=='commit':
        print("PROVED")
        r.srem('unknown',proposition)
        r.sadd(quotient,proposition)
        if recfile is not None and os.path.isdir("recording") and os.path.isfile(f"recording/{recfile}"):
          with open(f"recording/{recfile}","a") as f:
            f.write(aproposition+"\n")
        sys.exit(0)
      continue
    if intc==sat and into==unsat:
      print(f"  proposition {cnt} intersects only the closed class")
      if mode=='commit' and (quotient=='allow' or quotient=='closed'):
        print("PROVED")
        r.srem('unknown',proposition)
        r.sadd(quotient,proposition)
        if recfile is not None and os.path.isdir("recording") and os.path.isfile(f"recording/{recfile}"):
          with open(f"recording/{recfile}","a") as f:
            f.write(aproposition+"\n")
        sys.exit(0)
      elif mode=='commit' and (quotient!='allow' and quotient!='closed'):
        print("NOT proved")
        sys.exit(-1)
      postanswer,ccpost=ALLBVSAT(Z3proposition,magma_closed)
      if (postanswer==unsat):
        if ccpost is not None:
          #print(f"  *** removing PROPOSITION {cnt} from unknowns")
          r.srem('unknown',proposition)
          if len(ccpost)>0:
            print(f"  proposition replaced by the following passlets")
            for ac in ccpost:
              print("    ",ac)
              r.sadd('unknown',str(ac))
        else:
          print("  *** nothing new under the sun")
    elif intc==unsat and into==sat:
      print(f"  proposition {cnt} intersects only the open class")
      if mode=='commit' and (quotient=='block' or quotient=='open'):
        print("PROVED")
        r.srem('unknown',proposition)
        r.sadd(quotient,proposition)
        if recfile is not None and os.path.isdir("recording") and os.path.isfile(f"recording/{recfile}"):
          with open(f"recording/{recfile}","a") as f:
            f.write(aproposition+"\n")
        sys.exit(0)
      elif mode=='commit' and (quotient!='block' and quotient!='open'):
        print("NOT proved")
        sys.exit(-1)
      postanswer,ccpost=ALLBVSAT(Z3proposition,magma_open)
      if (postanswer==unsat):
        if ccpost is not None:
          #print(f"  *** removing PROPOSITION {cnt} from unknowns")
          r.srem('unknown',proposition)
          if len(ccpost)>0:
            print(f"  proposition replaced by the following passlets")
            for ac in ccpost:
              print("    ",ac)
              r.sadd('unknown',str(ac))
        else:
          print("  *** nothing new under the sun")
    elif intc==sat and into==sat:
      print(f"  proposition {cnt} intersects both classes")
      postanswer,ccpost=ALLBVSAT(Z3proposition,Or(magma_closed,magma_open))
      if (postanswer==unsat):
        if ccpost is not None:
          #print(f"  *** removing PROPOSITION {cnt} from unknowns")
          r.srem('unknown',proposition)
          if len(ccpost)>0:
            print(f"  proposition replaced by the following passlets")
            for ac in ccpost:
              print("    ",ac)
              r.sadd('unknown',str(ac))
        else:
          print("  *** nothing new under the sun")

parser = argparse.ArgumentParser()
parser.add_argument("--db", required=True, type=int, choices=[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15], help="redis database")
parser.add_argument("--op", required=True, type=str, choices=["whatIf","prove","drift","prove:allow","prove:block"], help="whatIf|prove|drift")
parser.add_argument("--proposition", required=False, type=str, help="normalized proposition")
args = parser.parse_args()

DB=args.db
OP=args.op

'''
logging.basicConfig(
     level = logging.DEBUG,
     filename = "parselog.txt",
     filemode = "w",
     format = "%(filename)10s:%(lineno)4d:%(message)s"
 )
log = logging.getLogger()
'''

r = redis.StrictRedis(host='localhost', port=6379, db=DB)
tags=r.smembers("tags")

openRules=0
closedRules=0
CAP=65536
PREDICATES_CAP=1000
h1=256
h2=h1*h1
h3=h2*h1

OpenPredicates=BoolVector('openpredicates',PREDICATES_CAP)
for i in range(0,PREDICATES_CAP):
  OpenPredicates[i]=True
ClosedPredicates=BoolVector('closedpredicates',PREDICATES_CAP)
for i in range(0,PREDICATES_CAP):
  ClosedPredicates[i]=True
SingleRulePredicate=BoolVector('singleRulePredicate',2)
SingleRulePredicate[0]=True

ClosedRules=[]
OpenRules=[]
SingleRule=[]
Rules=[]

sIPlows=BitVecVector('sIPlows', 32, 1000)
sIPhighs=BitVecVector('sIPhighs', 32, 1000)
dIPlows=BitVecVector('dIPlows', 32, 1000)
dIPhighs=BitVecVector('dIPhighs', 32, 1000)
Portlows=BitVecVector('Portlows', 16, 1000)
Porthighs=BitVecVector('Porthighs', 16, 1000)
Protolows=BitVecVector('Protolows', 4, 1000)
Protohighs=BitVecVector('Protohis', 4, 1000)
zeroVal=IntVal(0)
eightVal=IntVal(8)

hasSIP=Bool('hasSIP')
hasDIP=Bool('hasDIP')
zTrue=Bool('zTrue')
zTrue=True
zFalse=Bool('zFalse')
zFalse=False
sip=BitVec('sip',32)
dip=BitVec('dip',32)
dport=BitVec('dport',16)
prt=BitVec('prt',4)
saztagval=Int('saztagval')
sazvnetval=Int('sazvnetval')
daztagval=Int('daztagval')
dazvnetval=Int('dazvnetval')
azprotoval=Int('azprotoval')

constraints=And(saztagval<8,saztagval>=0,daztagval<8,daztagval>=0,dazvnetval>=0,dazvnetval<=1,sazvnetval>=0,sazvnetval<=1,prt>=0,prt<=3)

tokens = (
'LEFTB','RIGHTB', 'LEFTC', 'RIGHTC',
'COMMA','SEMI','PROTOK','PROTOV1','PROTOV2','PROTOV4','SAPK','DAPK','DPORTK','AZVNET','AZTAG1','AZTAG2','AZTAG3','AZTAG4','AZTAG5','AZTAG6','AZTAG7',
'WILDCARD', 'NUMBER','DASH','DOT','SLASH'
    )

# Tokens
t_LEFTB  = r'\['
t_RIGHTB  = r'\]'
t_LEFTC  = r'\{'
t_RIGHTC  = r'\}'
t_COMMA    = r'\,'
t_SEMI    = r'\:'
t_WILDCARD    = r'\*'
t_PROTOK    = r'protocol'
t_PROTOV1    = r'TCP'
t_PROTOV2    = r'UDP'
t_PROTOV4    = r'ICMP'
t_SAPK    = r'sourceAddressPrefix'
t_DAPK    = r'destinationAddressPrefix'
t_DPORTK    = r'destinationPort'
t_AZVNET     = r'VirtualNetwork'
t_AZTAG1     = r'AppServiceManagement'
t_AZTAG2     = r'AzureLoadBalancer'
t_AZTAG3     = r'ApiManagement'
t_AZTAG4     = r'Storage.[0-9A-Z-a-z]+'
t_AZTAG5     = r'BatchNodeManagement'
t_AZTAG6     = r'ServiceFabric'
t_AZTAG7     = r'HDInsight.[0-9A-Z-a-z]+'
t_DASH    = r'\-'
t_SLASH   = r'\/'
t_DOT     = r'\.'
t_ignore = ' \t\"\'' # Ignored characters

magma_closed=None
magma_open=None

if OP=='whatIf' or OP=='prove':
  prove(None,None)
elif OP=='drift':
  prove(None,None)
elif OP=='prove:allow' and args.proposition:
  prove(args.proposition,'closed')
elif OP=='prove:block' and args.proposition:
  prove(args.proposition,'open')
