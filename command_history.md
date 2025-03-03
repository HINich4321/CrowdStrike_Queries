#event_simpleName=CommandHistory event_platform=Win
| aid=~wildcard(?aid, ignoreCase=true) 
| ComputerName=~wildcard(?ComputerName, ignoreCase=true) 
| ComputerName!="VM*"
| groupby([ComputerName,aid,ApplicationName], function=[ collect([CommandHistory]), count(aid, as=CommandCount)],limit=max)
| default(value="-", field=[ApplicationName])
