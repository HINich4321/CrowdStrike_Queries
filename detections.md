ExternalApiType=Event_DetectionSummaryEvent
| format(format="%s > %s", field=[Tactic, Technique], as=MITRE)
| format("[Link](https://falcon.crowdstrike.com/activity-v2/detections?info=%s)", field=[AgentIdString], as="Detections")
| groupBy([AgentIdString, ComputerName, UserName], function=([count(DetectId, as=totalDetections), min(@timestamp, as=firstDetect), max(@timestamp, as=lastDetect), collect([MITRE, SeverityName, Detections])]))
| formatTime(field=firstDetect, format="%Y-%m-%d %H:%M:%S", as=firstDetect)
| formatTime(field=lastDetect, format="%Y-%m-%d %H:%M:%S", as=lastDetect)
| sort(severityWeight, order=desc, limit=1000)
