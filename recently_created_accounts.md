#event_simpleName=ActiveDirectoryAccountCreated
| SamAccountName!="*$*"
| time :=formatTime(format="%Y-%m-%d %H:%M:%S", field=@timestamp)
| groupBy([SamAccountName], function=(collect([time])))
