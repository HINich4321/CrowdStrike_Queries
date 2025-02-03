#event_simpleName=ProcessRollup2 event_platform=Win
| ComputerName=~wildcard(?ComputerName, ignoreCase=true)
| UserName=~wildcard(?UserName, ignoreCase=true) 
| aid=~wildcard(?aid, ignoreCase=true) 
| UserName!="*$"
| UserName!="*svc*"
| FileName=~wildcard(?FileName, ignoreCase=true)
| format("[VirusTotal](https://www.virustotal.com/gui/file/%s)", field=[SHA256HashData], as="VirusTotal")
| format("[HybridAnalysis](https://www.hybrid-analysis.com/search?query=%s)", field=[SHA256HashData], as="HybridAnalysis")
| groupby([ComputerName,UserName,ImageFileName], function=[ collect([aid,FileName,SHA256HashData,VirusTotal,HybridAnalysis]), count(aid, as=NumberOfRuns)],limit=max)
| default(value="-", field=[UserName,FileName, SHA256HashData])
