#event_simpleName=ActiveDirectoryAccountLocked
| SamAccountName!="*$*"
| time :=formatTime(format="%Y-%m-%d %H:%M:%S", field=@timestamp)
| groupBy([SamAccountName], function=(collect([time])))
