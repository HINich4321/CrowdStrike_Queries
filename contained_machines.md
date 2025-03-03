#event_simpleName=SensorHeartbeat event_platform=/(^(Win|Mac|Lin)$)/
NetworkContainmentState=1
| groupBy(["UserName", "ComputerName"], function=[ collect(["NetworkContainmentState"])])
