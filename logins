#event_simpleName=UserLogon event_platform=Win
| aid=~wildcard(?aid, ignoreCase=true) 
| UserName=~wildcard(?UserName, ignoreCase=true) 
| RemoteAddressIP4=~wildcard(?RemoteAddressIP4, ignoreCase=true)
| UserName!="*$*"
| UserName!="*svc*"
| ComputerName=~wildcard(?ComputerName, ignoreCase=true)
| ComputerName="L0*" or "D0*"
| ipLocation(aip)
| case {
    UserIsAdmin="1" | UserIsAdmin:="Yes" ;
    UserName=~wildcard("a_*", ignoreCase=true) | UserIsAdmin:="Yes";
    UserIsAdmin="0" | UserIsAdmin:="No" ;
    *;
}
| case {
    LogonType="0" | readable_LogonType:="System";
    LogonType="2" | readable_LogonType:="Interactive";
    LogonType="3" | readable_LogonType:="Network";
    LogonType="4" | readable_LogonType:="Batch";
    LogonType="5" | readable_LogonType:="Service";
    LogonType="7" | readable_LogonType:="Unlock";
    LogonType="8" | readable_LogonType:="NetworkCleartext";
    LogonType="9" | readable_LogonType:="NewCredentials";
    LogonType="10" | readable_LogonType:="RemoteInteractive";
    LogonType="11" | readable_LogonType:="CachedInteractive";
    LogonType="12" | readable_LogonType:="CahedRemoteInteractive";
    LogonType="13" | readable_LogonType:="CachedUnlock";
    *;
}
| groupBy(["aid","UserName", "ComputerName", "UserIsAdmin", "LogonType", "readable_LogonType", "RemoteAddressIP4", "aip.city", "aip.state", "aip.country"], function=[count(as=loginCount), selectLast(["@timestamp"])])
| default(value="-", field=[UserName,ComputerName,aip.city,aip.state,aip.country,RemoteAddressIP4])
