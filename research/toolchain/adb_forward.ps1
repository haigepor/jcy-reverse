param(
    [int]$hostPort = 5555,
    [string]$guestIp = "172.16.1.4",
    [int]$guestPort = 5555
)
$ErrorActionPreference = 'Stop'
$v = New-Object -ComObject 'VirtualBox.VirtualBox'
$n = $v.FindNATNetworkByName('LdNatNetwork0')
Write-Output ("net: {0} {1} enabled={2} dhcp={3}" -f $n.networkName, $n.network, $n.enabled, $n.dhcp)
# AddPortForwardRule(isIpv6:bool, hostAddr:str, hostPort:uint32, proto:NATProtocolVariant(0=TCP), guestAddr:str, guestPort:uint32, creationTime:uint64)
$n.AddPortForwardRule($false, [string]'0.0.0.0', [uint32]$hostPort, [uint32]0, [string]$guestIp, [uint32]$guestPort, [uint64]0)
Write-Output ("forward added: 0.0.0.0:{0} -> {1}:{2}" -f $hostPort, $guestIp, $guestPort)
