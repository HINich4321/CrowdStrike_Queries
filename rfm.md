#event_simpleName=OsVersionInfo event_platform=/(^(Win|Mac|Lin)$)/
| RFMState=1
| RFMState match {
    1 => RFMState := "RFM" ;
    0 => RFMState := "OK" ;
}
| osData:=concat([OSVersionString, ProductName])
| groupBy([ComputerName,RFMState], function=([selectFromMax(field="@timestamp", include=[ComputerName, RFMState, AgentVersion, osData])]))
| default(value="-", field=[ComputerName, RFMState, AgentVersion, osData])
