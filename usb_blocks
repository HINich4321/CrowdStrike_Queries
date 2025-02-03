#event_simpleName=DcUsbDeviceBlocked event_platform=/(^(Win|Mac|Lin)$)/
DcPolicyAction=1 OR 2
| case {
    DcPolicyAction="1" | readable_DcPolicyAction:="BLOCK";
    DcPolicyAction="2" | readable_DcPolicyAction:="PARTIAL BLOCK";
    *;
}
| case {
    DcPolicyMassStorageBlockPermissions="1" | readable_DcPolicyMassStorageBlockPermissions:="READ";
    DcPolicyMassStorageBlockPermissions="2" | readable_DcPolicyMassStorageBlockPermissions:="WRITE";
    DcPolicyMassStorageBlockPermissions="4" | readable_DcPolicyMassStorageBlockPermissions:="EXECUTE";
    *;
}
| format("[Link](https://falcon.crowdstrike.com/investigate/dashboards/device-usage-by-host?computer=%s&isLive=false&sharedTime=true&start=7d)", field=[ComputerName], as="USB Page")
| groupBy(["ComputerName"], function=[ collect(["DeviceUsbVersion", "DeviceManufacturer","DeviceSerialNumber","readable_DcPolicyAction","readable_DcPolicyMassStorageBlockPermissions","USB Page"])])
| default(value="-", field=[DeviceUsbVersion,DeviceSerialNumber,readable_DcPolicyAction,readable_DcPolicyMassStorageBlockPermissions])
