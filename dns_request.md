#event_simpleName=DnsRequest event_platform=Win
| aid=~wildcard(?aid, ignoreCase=true) 
| ComputerName=~wildcard(?ComputerName, ignoreCase=true) 
| ContextBaseFileName=~wildcard(?FileName, ignoreCase=true)
| FirstIP4Record=~wildcard(?FirstIP4Record, ignoreCase=true)
| ComputerName!="VM*"
| format("[FileNameSearch](https://www.virustotal.com/gui/file/%s)", field=[ContextBaseFileName], as="FileNameVT")
| format("[DomainName](https://www.virustotal.com/gui/domain/%s)", field=[DomainName], as="DomainNameVT")
| format("[FirstIP4Record](https://www.virustotal.com/gui/ip-address/%s)", field=[FirstIP4Record], as="IPVT")
| groupby([ComputerName,aid], function=[ collect([DomainName,DomainNameVT,ContextBaseFileName,FileNameVT,FirstIP4Record,IPVT]), count(aid, as=DnsRequestCount)],limit=max)
| default(value="-", field=[DomainName,ContextBaseFileName,FirstIP4Record])
