#!/usr/bin/env python3

from pytm import *


tm = TM("my test tm")
tm.description = """This is a sample threat model of a very simple system - a web-based comment system. 
The user enters comments and these are added to a database and displayed back to the user. 
The thought is that it is, though simple, a complete enough example to express meaningful threats."""
tm.isOrdered = False         # DataFlow 순서 정렬 
tm.mergeResponses = True
tm.assumptions = [
    "Here you can document a list of assumptions about the system",
]

## most of defi protocols include 2 party (A Threat Modeling Approach for Blockchain Security Assessment - 2024)
## - Liquidity Provider - providing crypto fund to DeFi Protocol
## - Service User (here, trader) - who use lending/exchange service funded by Liquidity Provider

# Process
pnode1 = Process("Peer Node1")
pnode1.function_type = "Peer Node"
pnode2 = Process("Peer Node2")
pnode2.function_type = "Peer Node"
pnode3 = Process("Peer Node3")
pnode3.function_type = "Peer Node"
consensus = Process("Consensus Mechanism")
defi_pro1 = Process("Asset Exchange Contract")
defi_pro1.function_type = "Asset Exchange"
defi_pro2 = Process("Collateral Provision Contract")
defi_pro2.function_type = "Collateral Provision"
defi_pro3 = Process("Liquidity Provision")
oracle = Process("on-chain price Oracle")
oracle.function_type = "On-chain Price Oracle Contract"

# External Entity
trader_wallet = ExternalEntity("Trader")
liquidity_provider =ExternalEntity("Liquidity Provider")    

# Data Store
ledger1 = Datastore("Ledger (owned by Peer Node 1)")
ledger2 = Datastore("Ledger (owned by Peer Node 2)")
ledger3 = Datastore("Ledger (owned by Peer Node 3)")

# DataFlow
pnode1_to_ledger1 = Dataflow(ledger1, pnode1, "Data Read")
ledger1_to_pnode1 = Dataflow(pnode1, ledger1, "Data Write")

pnode2_to_ledger2 = Dataflow(ledger2, pnode2, "Data Read")
ledger2_to_pnode2 = Dataflow(pnode2,ledger2,  "Data Write")

pnode3_to_ledger3 = Dataflow(ledger3, pnode3, "Data Read")
ledger3_to_pnode3 = Dataflow(pnode3,ledger3, "Data Write")


pnode1_to_pnode2 = Dataflow(pnode1, pnode2, "Block/Tx Propagation")
pnode2_to_pnode1 = Dataflow(pnode2, pnode1, "Block/Tx Propagation")

pnode1_to_pnode3 = Dataflow(pnode1, pnode3, "Block/Tx Propagation")
pnode3_to_pnode1 = Dataflow(pnode3, pnode1, "Block/Tx Propagation")

pnode2_to_pnode3  = Dataflow(pnode2, pnode3, "Block/Tx Propagation")
pnode3_to_pnode2 = Dataflow(pnode3, pnode2, "Block/Tx Propagation")


cons_to_pnode1 = Dataflow(consensus, pnode1, "Block Validation Rsesult")
pnode1_to_cons = Dataflow(pnode1, consensus, "Block Validation")

cons_to_pnode2 = Dataflow(consensus, pnode2, "Block Validation Rsesult")
pnode2_to_cons = Dataflow(pnode2, consensus, "Block/Tx Propagation")

cons_to_pnode3 = Dataflow(consensus, pnode3, "Block Validation Rsesult")
pnode3_to_cons = Dataflow(pnode3, consensus, "Block/Tx Propagation")


pnode3_to_defi_pro1 = Dataflow(pnode3,defi_pro1, "Execution (Request Type - Hoard)")
pnode3_to_defi_pro1.order = 1 
defi_pro1_to_pnode3 = Dataflow(defi_pro1, pnode3, "Result State")
defi_pro1_to_pnode3.order = 2

pnode3_to_oracle = Dataflow(pnode3, oracle, "Oracle Read")
pnode3_to_oracle.order = 3
oracle_to_pnode3 = Dataflow(oracle,pnode3, "price info")
oracle_to_pnode3.order = 6

oracle_to_defi_pro1 = Dataflow(oracle,defi_pro1, "Liquidity Info Read")
oracle_to_defi_pro1.order = 4
defi_pro1_to_oracle = Dataflow(defi_pro1,oracle, "Liquidity Info")
defi_pro1_to_oracle.order = 5

pnode3_to_defi_pro2 = Dataflow(pnode3,defi_pro2, "Execution(Request Type - Dump)")
pnode3_to_defi_pro2.order = 7
defi_pro2_to_pnode3 = Dataflow(defi_pro2,pnode3, "Result State")
defi_pro2_to_pnode3.order = 10

trader_to_pnode2 = Dataflow(trader_wallet,pnode2,"Hoard & Dump (Transaction)")
pnode2_to_trader = Dataflow(pnode2,trader_wallet,"profit & Tx Reuslt")


defi_pro3_to_pnode3 = Dataflow(defi_pro3,pnode3,"Result State")
pnode3_to_defi_pro3 = Dataflow(pnode3,defi_pro3,"Execution")



defi_pro2_to_oracle = Dataflow(defi_pro2,oracle,"Collateral Price Request")
defi_pro2_to_oracle.order = 8
oracle_to_defi_pro2 = Dataflow(oracle,defi_pro2,"Collateral Price")
oracle_to_defi_pro2.order = 9


if __name__ == "__main__":
    ## @func
    ## process : analyze the given threat model (using system model and threat knowledge base)
    ## - extended : now we can analyze attack scenario defined in 'threatlib/scenarios.json'
    ## @param 
    ## - starts : The starting point for initiating attack scenario analysis on the DFD (Asset object in DFD)
    ##   --> left the param blank if you don't want to analyze attack scenario
    tm.process(pnode3)
