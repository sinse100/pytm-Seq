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

## External Entity
User =ExternalEntity("User")

## Process
process1 = Process("Database Reader")
process1.function_type = "Read"
process2 = Process("Database Writer")
process2.function_type = "Write"
process3 = Process("Web Application Server (Router program)")

## Data Store
db =Datastore("User Database (Shared)")

## Data Flow
process1_to_db = Dataflow(process1,db,"Read Request Info")
process1_to_db.order = 1
db_to_process1 = Dataflow(db,process1"Read Response (Data)")
db_to_process1.order = 4
db_to_process2 = Dataflow(db,process2, "Data Offset, Data Identification Result (Info required for Data, File Write)")
db_to_process2.order = 2
process2_to_db = Dataflow(process2, db, "Write Request Info")
process2_to_db.order = 3
User_to_process3 = Dataflow(User,process3, "Request for User Database Operation")
process3_to_User = Dataflow(process3, User, "Response for User Database Operation")
process3_to_process2 = Dataflow(process3, process2, "Routing Info - Read Request")
process2_to_process3 = Dataflow(process2, process3, "User Data")
process3_to_process1 = Dataflow(process3,process1, "Routing Info - Write Request"
process1_to_process3 = Dataflow(process1, process3, "Write Status & "Overwritten User Data")


if __name__ == "__main__":
    tm.process(mode = 1)
