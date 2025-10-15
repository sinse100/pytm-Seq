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

# External Entity
hmi1 = ExternalEntity("HMI-Channel 1 (Human-Machine Interface)")
hmi2 = ExternalEntity("HMI-Channel 2 (Human-Machine Interface)")
current_sensor =ExternalEntity("Current Sensor")
voltage_sensor =ExternalEntity("Voltage Sensor")
circuit_breaker = ExternalEntity("Circuit Breaker")

# Data Store
acq_log = Datastore("Data Acquisition Log (Session Status)")
conf_db = Datastore("System Configuration Database")
historian_db = Datastore("Historical Data / Trend Storage")

# Process
eng_station = Process("Engineer Station")
ops_station = Process("Operator Station")
router = Process("Control Network Router")
acq_server = Process("Data Acquisition Server")
mtu = Process("Master Terminal Unit")
scada_server = Process("MicroSCADA Server")
scada_server.function_type = "Control Server"
ems = Process("Energy Management System (EMS)")
historian = Process("Time-Series Historian Server")
historian.function_type = "Data Historian"
scil_app = Process("SKILL Runtime Environment")
scil_app.function_type = "Application Server"
rtu = Process("Control RTU")
rtu.function_type = "RTU"
ied = Process("Smart Electronic Control Device(IED)")
ied.function_type = "IED"

# DataFlow
df1 = Dataflow(hmi1, eng_station,"Control Command Data")
df2 = Dataflow(eng_station, hmi1,"Display/Event/Alarm Acknowledgement")
df3 = Dataflow(hmi2, ops_station,"User Authentication Input/Setpoint/Parameter Adjustment Input")
df4 = Dataflow(ops_station, hmi2, "Display/Event/Alarm Acknowledgement")
df5 = Dataflow(eng_station, router, "Software,Project Deployment Data/Control Command")
df6 = Dataflow(router, eng_station, "Security Event/Access Log/Alarm/Event Data")
df7 = Dataflow(ops_station, router,"Setpoint/Parameter Update Data/User Authentication/Session Token")
df8 = Dataflow(router, ops_station,"Real-Time Status Data/System Message/Network Health/Alarm/Event Data")
df9 = Dataflow(router, acq_server,"RTU/IED communication sessions and failure history logging data")
df10 = Dataflow(acq_server, router,"Results of RTU/IED communication session and failure history logging")
df11 = Dataflow(acq_server, acq_log,"RTU/IED communication sessions and failure history logging data")
df12 = Dataflow(acq_log, acq_server,"Results of RTU/IED communication session and failure history logging")
df13 = Dataflow(router, mtu,"Status Read & Update Command/Diagnostic Data/Communication Quality Data")
df14 = Dataflow(mtu, router,"Communication Management Data / Setpoint & Parameter Update Result")
df15 = Dataflow(ems, mtu,"Current, voltage, power (P/Q), frequency, and phase angle measurements used for load flow calculation and voltage profile analysis of EMS")
df16 = Dataflow(ems, mtu,"Load Flow Calculation Results/Voltage Profile Analysis Results")
df17 = Dataflow(historian,ems,"Results of load flow calculation and frequency and voltage stability logging")
df18 = Dataflow(ems, historian,"Load Flow Calculation Results / Frequency & Voltage Stability Indicators")
df19 = Dataflow(mtu,scada_server, "Configuration/Equipment Identification/Control Command Data")
df20 = Dataflow(scada_server,mtu, "Telemetry/Indication/Event/Measurement/SOE/Alarm")
df21 = Dataflow(scada_server,conf_db,"System Definition Data / Equipment / Tag Metadata")
df22 = Dataflow(conf_db,scada_server,"Latest Configuration Data / Tag / Signal Definition Data")
df23 = Dataflow(scada_server,historian,"Periodic Sampling Data/Post-Processed Real-Time Measurement Data")
df24 = Dataflow(historian,scada_server,"Periodic snapshot data storage and retrieval results/Measurement data storage and retrieval results")
df25 = Dataflow(historian,historian_db,"Periodic Sampling Data/Real-Time Measurement Data")
df26 = Dataflow(historian_db,historian,"Periodic snapshot data storage and retrieval results/Measurement data storage and retrieval results")
df27 = Dataflow(historian,scil_app,"Time-Series Data (Log)/SKILL Command Sequence")
df28 = Dataflow(scil_app,historian,"SKILL Command Result / RTU Terminal Status/Measured Values - Voltage & Current Combined")
df29 = Dataflow(scil_app,rtu,"SKILL Command (IED Manipulation)")
df30 = Dataflow(rtu,ied,"SKILL Binary Command")
df31 = Dataflow(ied,rtu,"Measured Values - Voltage & Current Combined")
df32 = Dataflow(ied,circuit_breaker,"Circuit Manipulation Command (Enabled/Disabled)")
df33 = Dataflow(voltage_sensor,ied,"Measured Values - Voltage")
df34 = Dataflow(current_sensor,ied,"Measured Values - Current")

if __name__ == "__main__":
    tm.process()
