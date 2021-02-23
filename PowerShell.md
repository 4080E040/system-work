# Powershell概念報告
```
PowerShell 語法為"動詞-名詞"
利用"Get-Command"指令獲取資訊
```
### 呈現結果如下(第一部分 =>aliases(別名))
```
Get-Command

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Alias           Add-AppPackage                                     2.0.1.0    Appx
Alias           Add-AppPackageVolume                               2.0.1.0    Appx
Alias           Add-AppProvisionedPackage                          3.0        Dism
Alias           Add-ProvisionedAppPackage                          3.0        Dism
Alias           Add-ProvisionedAppxPackage                         3.0        Dism
Alias           Add-ProvisioningPackage                            3.0        Provisioning
Alias           Add-TrustedProvisioningCertificate                 3.0        Provisioning
Alias           Apply-WindowsUnattend                              3.0        Dism
Alias           Disable-PhysicalDiskIndication                     2.0.0.0    Storage
Alias           Disable-StorageDiagnosticLog                       2.0.0.0    Storage
Alias           Dismount-AppPackageVolume                          2.0.1.0    Appx
Alias           Enable-PhysicalDiskIndication                      2.0.0.0    Storage
Alias           Enable-StorageDiagnosticLog                        2.0.0.0    Storage
Alias           Export-VMCheckpoint                                2.0.0.0    Hyper-V
Alias           Flush-Volume                                       2.0.0.0    Storage
Alias           Get-AppPackage                                     2.0.1.0    Appx
Alias           Get-AppPackageDefaultVolume                        2.0.1.0    Appx
Alias           Get-AppPackageLastError                            2.0.1.0    Appx
Alias           Get-AppPackageLog                                  2.0.1.0    Appx
Alias           Get-AppPackageManifest                             2.0.1.0    Appx
Alias           Get-AppPackageVolume                               2.0.1.0    Appx
Alias           Get-AppProvisionedPackage                          3.0        Dism
Alias           Get-DiskSNV                                        2.0.0.0    Storage
Alias           Get-PhysicalDiskSNV                                2.0.0.0    Storage
Alias           Get-ProvisionedAppPackage                          3.0        Dism
Alias           Get-ProvisionedAppxPackage                         3.0        Dism
Alias           Get-StorageEnclosureSNV                            2.0.0.0    Storage
Alias           Get-VMCheckpoint                                   2.0.0.0    Hyper-V
Alias           Initialize-Volume                                  2.0.0.0    Storage
Alias           Mount-AppPackageVolume                             2.0.1.0    Appx
Alias           Move-AppPackage                                    2.0.1.0    Appx
Alias           Move-SmbClient                                     2.0.0.0    SmbWitness
Alias           Optimize-AppProvisionedPackages                    3.0        Dism
Alias           Optimize-ProvisionedAppPackages                    3.0        Dism
Alias           Optimize-ProvisionedAppxPackages                   3.0        Dism
Alias           Remove-AppPackage                                  2.0.1.0    Appx
Alias           Remove-AppPackageVolume                            2.0.1.0    Appx
Alias           Remove-AppProvisionedPackage                       3.0        Dism
Alias           Remove-EtwTraceSession                             1.0.0.0    EventTracin...
Alias           Remove-ProvisionedAppPackage                       3.0        Dism
Alias           Remove-ProvisionedAppxPackage                      3.0        Dism
Alias           Remove-ProvisioningPackage                         3.0        Provisioning
Alias           Remove-TrustedProvisioningCertificate              3.0        Provisioning
Alias           Remove-VMCheckpoint                                2.0.0.0    Hyper-V
Alias           Rename-VMCheckpoint                                2.0.0.0    Hyper-V
Alias           Restore-VMCheckpoint                               2.0.0.0    Hyper-V
Alias           Set-AppPackageDefaultVolume                        2.0.1.0    Appx
Alias           Set-AppPackageProvisionedDataFile                  3.0        Dism
Alias           Set-AutologgerConfig                               1.0.0.0    EventTracin...
Alias           Set-EtwTraceSession                                1.0.0.0    EventTracin...
Alias           Set-ProvisionedAppPackageDataFile                  3.0        Dism
Alias           Set-ProvisionedAppXDataFile                        3.0        Dism
Alias           Write-FileSystemCache                              2.0.0.0    Storage
```
### 呈現結果如下(第二部分=>functions)
```
Function        A:
Function        Add-BCDataCacheExtension                           1.0.0.0    BranchCache
Function        Add-BitLockerKeyProtector                          1.0.0.0    BitLocker
Function        Add-DnsClientNrptRule                              1.0.0.0    DnsClient
Function        Add-DtcClusterTMMapping                            1.0.0.0    MsDtc
Function        Add-EtwTraceProvider                               1.0.0.0    EventTracin...
Function        Add-InitiatorIdToMaskingSet                        2.0.0.0    Storage
Function        Add-MpPreference                                   1.0        ConfigDefender
Function        Add-MpPreference                                   1.0        Defender
Function        Add-NetEventNetworkAdapter                         1.0.0.0    NetEventPac...
Function        Add-NetEventPacketCaptureProvider                  1.0.0.0    NetEventPac...
Function        Add-NetEventProvider                               1.0.0.0    NetEventPac...
Function        Add-NetEventVFPProvider                            1.0.0.0    NetEventPac...
Function        Add-NetEventVmNetworkAdapter                       1.0.0.0    NetEventPac...
Function        Add-NetEventVmSwitch                               1.0.0.0    NetEventPac...
Function        Add-NetEventVmSwitchProvider                       1.0.0.0    NetEventPac...
Function        Add-NetEventWFPCaptureProvider                     1.0.0.0    NetEventPac...
Function        Add-NetIPHttpsCertBinding                          1.0.0.0    NetworkTran...
Function        Add-NetLbfoTeamMember                              2.0.0.0    NetLbfo
Function        Add-NetLbfoTeamNic                                 2.0.0.0    NetLbfo
Function        Add-NetNatExternalAddress                          1.0.0.0    NetNat
Function        Add-NetNatStaticMapping                            1.0.0.0    NetNat
Function        Add-NetSwitchTeamMember                            1.0.0.0    NetSwitchTeam
Function        Add-OdbcDsn                                        1.0.0.0    Wdac
Function        Add-PartitionAccessPath                            2.0.0.0    Storage
Function        Add-PhysicalDisk                                   2.0.0.0    Storage
Function        Add-Printer                                        1.1        PrintManage...
Function        Add-PrinterDriver                                  1.1        PrintManage...
Function        Add-PrinterPort                                    1.1        PrintManage...
Function        Add-StorageFaultDomain                             2.0.0.0    Storage
Function        Add-TargetPortToMaskingSet                         2.0.0.0    Storage
Function        Add-VirtualDiskToMaskingSet                        2.0.0.0    Storage
Function        Add-VpnConnection                                  2.0.0.0    VpnClient
Function        Add-VpnConnectionRoute                             2.0.0.0    VpnClient
Function        Add-VpnConnectionTriggerApplication                2.0.0.0    VpnClient
Function        Add-VpnConnectionTriggerDnsConfiguration           2.0.0.0    VpnClient
Function        Add-VpnConnectionTriggerTrustedNetwork             2.0.0.0    VpnClient
Function        AfterAll                                           3.4.0      Pester
Function        AfterEach                                          3.4.0      Pester
Function        Assert-MockCalled                                  3.4.0      Pester
Function        Assert-VerifiableMocks                             3.4.0      Pester
Function        B:
Function        Backup-BitLockerKeyProtector                       1.0.0.0    BitLocker
Function        BackupToAAD-BitLockerKeyProtector                  1.0.0.0    BitLocker
Function        BeforeAll                                          3.4.0      Pester
Function        BeforeEach                                         3.4.0      Pester
Function        Block-FileShareAccess                              2.0.0.0    Storage
Function        Block-SmbShareAccess                               2.0.0.0    SmbShare
Function        C:
Function        cd..
Function        cd\
Function        Clear-AssignedAccess                               1.0.0.0    AssignedAccess
Function        Clear-BCCache                                      1.0.0.0    BranchCache
Function        Clear-BitLockerAutoUnlock                          1.0.0.0    BitLocker
Function        Clear-Disk                                         2.0.0.0    Storage
Function        Clear-DnsClientCache                               1.0.0.0    DnsClient
Function        Clear-FileStorageTier                              2.0.0.0    Storage
Function        Clear-Host
Function        Clear-PcsvDeviceLog                                1.0.0.0    PcsvDevice
Function        Clear-StorageBusDisk                               1.0.0.0    StorageBusC...
Function        Clear-StorageDiagnosticInfo                        2.0.0.0    Storage
Function        Close-SmbOpenFile                                  2.0.0.0    SmbShare
Function        Close-SmbSession                                   2.0.0.0    SmbShare
Function        Compress-Archive                                   1.0.1.0    Microsoft.P...
Function        Configuration                                      1.1        PSDesiredSt...
Function        Connect-IscsiTarget                                1.0.0.0    iSCSI
Function        Connect-VirtualDisk                                2.0.0.0    Storage
Function        Context                                            3.4.0      Pester
Function        ConvertFrom-SddlString                             3.1.0.0    Microsoft.P...
Function        ConvertTo-HgsKeyProtector                          1.0.0.0    HgsClient
Function        Copy-NetFirewallRule                               2.0.0.0    NetSecurity
Function        Copy-NetIPsecMainModeCryptoSet                     2.0.0.0    NetSecurity
Function        Copy-NetIPsecMainModeRule                          2.0.0.0    NetSecurity
Function        Copy-NetIPsecPhase1AuthSet                         2.0.0.0    NetSecurity
Function        Copy-NetIPsecPhase2AuthSet                         2.0.0.0    NetSecurity
Function        Copy-NetIPsecQuickModeCryptoSet                    2.0.0.0    NetSecurity
Function        Copy-NetIPsecRule                                  2.0.0.0    NetSecurity
Function        D:
Function        Debug-FileShare                                    2.0.0.0    Storage
Function        Debug-MMAppPrelaunch                               1.0        MMAgent
Function        Debug-StorageSubSystem                             2.0.0.0    Storage
Function        Debug-Volume                                       2.0.0.0    Storage
Function        Describe                                           3.4.0      Pester
Function        Disable-BC                                         1.0.0.0    BranchCache
Function        Disable-BCDowngrading                              1.0.0.0    BranchCache
Function        Disable-BCServeOnBattery                           1.0.0.0    BranchCache
Function        Disable-BitLocker                                  1.0.0.0    BitLocker
Function        Disable-BitLockerAutoUnlock                        1.0.0.0    BitLocker
Function        Disable-DAManualEntryPointSelection                1.0.0.0    DirectAcces...
Function        Disable-DscDebug                                   1.1        PSDesiredSt...
Function        Disable-MMAgent                                    1.0        MMAgent
Function        Disable-NetAdapter                                 2.0.0.0    NetAdapter
Function        Disable-NetAdapterBinding                          2.0.0.0    NetAdapter
Function        Disable-NetAdapterChecksumOffload                  2.0.0.0    NetAdapter
Function        Disable-NetAdapterEncapsulatedPacketTaskOffload    2.0.0.0    NetAdapter
Function        Disable-NetAdapterIPsecOffload                     2.0.0.0    NetAdapter
Function        Disable-NetAdapterLso                              2.0.0.0    NetAdapter
Function        Disable-NetAdapterPacketDirect                     2.0.0.0    NetAdapter
Function        Disable-NetAdapterPowerManagement                  2.0.0.0    NetAdapter
Function        Disable-NetAdapterQos                              2.0.0.0    NetAdapter
Function        Disable-NetAdapterRdma                             2.0.0.0    NetAdapter
Function        Disable-NetAdapterRsc                              2.0.0.0    NetAdapter
Function        Disable-NetAdapterRss                              2.0.0.0    NetAdapter
Function        Disable-NetAdapterSriov                            2.0.0.0    NetAdapter
Function        Disable-NetAdapterUso                              2.0.0.0    NetAdapter
Function        Disable-NetAdapterVmq                              2.0.0.0    NetAdapter
Function        Disable-NetDnsTransitionConfiguration              1.0.0.0    NetworkTran...
Function        Disable-NetFirewallRule                            2.0.0.0    NetSecurity
Function        Disable-NetIPHttpsProfile                          1.0.0.0    NetworkTran...
Function        Disable-NetIPsecMainModeRule                       2.0.0.0    NetSecurity
Function        Disable-NetIPsecRule                               2.0.0.0    NetSecurity
Function        Disable-NetNatTransitionConfiguration              1.0.0.0    NetworkTran...
Function        Disable-NetworkSwitchEthernetPort                  1.0.0.0    NetworkSwit...
Function        Disable-NetworkSwitchFeature                       1.0.0.0    NetworkSwit...
Function        Disable-NetworkSwitchVlan                          1.0.0.0    NetworkSwit...
Function        Disable-OdbcPerfCounter                            1.0.0.0    Wdac
Function        Disable-PhysicalDiskIdentification                 2.0.0.0    Storage
Function        Disable-PnpDevice                                  1.0.0.0    PnpDevice
Function        Disable-PSTrace                                    1.0.0.0    PSDiagnostics
Function        Disable-PSWSManCombinedTrace                       1.0.0.0    PSDiagnostics
Function        Disable-ScheduledTask                              1.0.0.0    ScheduledTasks
Function        Disable-SmbDelegation                              2.0.0.0    SmbShare
Function        Disable-StorageBusCache                            1.0.0.0    StorageBusC...
Function        Disable-StorageBusDisk                             1.0.0.0    StorageBusC...
Function        Disable-StorageEnclosureIdentification             2.0.0.0    Storage
Function        Disable-StorageEnclosurePower                      2.0.0.0    Storage
Function        Disable-StorageHighAvailability                    2.0.0.0    Storage
Function        Disable-StorageMaintenanceMode                     2.0.0.0    Storage
Function        Disable-WdacBidTrace                               1.0.0.0    Wdac
Function        Disable-WSManTrace                                 1.0.0.0    PSDiagnostics
Function        Disconnect-IscsiTarget                             1.0.0.0    iSCSI
Function        Disconnect-VirtualDisk                             2.0.0.0    Storage
Function        Dismount-DiskImage                                 2.0.0.0    Storage
Function        E:
Function        Enable-BCDistributed                               1.0.0.0    BranchCache
Function        Enable-BCDowngrading                               1.0.0.0    BranchCache
Function        Enable-BCHostedClient                              1.0.0.0    BranchCache
Function        Enable-BCHostedServer                              1.0.0.0    BranchCache
Function        Enable-BCLocal                                     1.0.0.0    BranchCache
Function        Enable-BCServeOnBattery                            1.0.0.0    BranchCache
Function        Enable-BitLocker                                   1.0.0.0    BitLocker
Function        Enable-BitLockerAutoUnlock                         1.0.0.0    BitLocker
Function        Enable-DAManualEntryPointSelection                 1.0.0.0    DirectAcces...
Function        Enable-DscDebug                                    1.1        PSDesiredSt...
Function        Enable-MMAgent                                     1.0        MMAgent
Function        Enable-NetAdapter                                  2.0.0.0    NetAdapter
Function        Enable-NetAdapterBinding                           2.0.0.0    NetAdapter
Function        Enable-NetAdapterChecksumOffload                   2.0.0.0    NetAdapter
Function        Enable-NetAdapterEncapsulatedPacketTaskOffload     2.0.0.0    NetAdapter
Function        Enable-NetAdapterIPsecOffload                      2.0.0.0    NetAdapter
Function        Enable-NetAdapterLso                               2.0.0.0    NetAdapter
Function        Enable-NetAdapterPacketDirect                      2.0.0.0    NetAdapter
Function        Enable-NetAdapterPowerManagement                   2.0.0.0    NetAdapter
Function        Enable-NetAdapterQos                               2.0.0.0    NetAdapter
Function        Enable-NetAdapterRdma                              2.0.0.0    NetAdapter
Function        Enable-NetAdapterRsc                               2.0.0.0    NetAdapter
Function        Enable-NetAdapterRss                               2.0.0.0    NetAdapter
Function        Enable-NetAdapterSriov                             2.0.0.0    NetAdapter
Function        Enable-NetAdapterUso                               2.0.0.0    NetAdapter
Function        Enable-NetAdapterVmq                               2.0.0.0    NetAdapter
Function        Enable-NetDnsTransitionConfiguration               1.0.0.0    NetworkTran...
Function        Enable-NetFirewallRule                             2.0.0.0    NetSecurity
Function        Enable-NetIPHttpsProfile                           1.0.0.0    NetworkTran...
Function        Enable-NetIPsecMainModeRule                        2.0.0.0    NetSecurity
Function        Enable-NetIPsecRule                                2.0.0.0    NetSecurity
Function        Enable-NetNatTransitionConfiguration               1.0.0.0    NetworkTran...
Function        Enable-NetworkSwitchEthernetPort                   1.0.0.0    NetworkSwit...
Function        Enable-NetworkSwitchFeature                        1.0.0.0    NetworkSwit...
Function        Enable-NetworkSwitchVlan                           1.0.0.0    NetworkSwit...
Function        Enable-OdbcPerfCounter                             1.0.0.0    Wdac
Function        Enable-PhysicalDiskIdentification                  2.0.0.0    Storage
Function        Enable-PnpDevice                                   1.0.0.0    PnpDevice
Function        Enable-PSTrace                                     1.0.0.0    PSDiagnostics
Function        Enable-PSWSManCombinedTrace                        1.0.0.0    PSDiagnostics
Function        Enable-ScheduledTask                               1.0.0.0    ScheduledTasks
Function        Enable-SmbDelegation                               2.0.0.0    SmbShare
Function        Enable-StorageBusCache                             1.0.0.0    StorageBusC...
Function        Enable-StorageBusDisk                              1.0.0.0    StorageBusC...
Function        Enable-StorageEnclosureIdentification              2.0.0.0    Storage
Function        Enable-StorageEnclosurePower                       2.0.0.0    Storage
Function        Enable-StorageHighAvailability                     2.0.0.0    Storage
Function        Enable-StorageMaintenanceMode                      2.0.0.0    Storage
Function        Enable-WdacBidTrace                                1.0.0.0    Wdac
Function        Enable-WSManTrace                                  1.0.0.0    PSDiagnostics
Function        Expand-Archive                                     1.0.1.0    Microsoft.P...
Function        Export-BCCachePackage                              1.0.0.0    BranchCache
Function        Export-BCSecretKey                                 1.0.0.0    BranchCache
Function        Export-HgsGuardian                                 1.0.0.0    HgsClient
Function        Export-ODataEndpointProxy                          1.0        Microsoft.P...
Function        Export-ScheduledTask                               1.0.0.0    ScheduledTasks
Function        F:
Function        Find-Command                                       1.0.0.1    PowerShellGet
Function        Find-DscResource                                   1.0.0.1    PowerShellGet
Function        Find-Module                                        1.0.0.1    PowerShellGet
Function        Find-NetIPsecRule                                  2.0.0.0    NetSecurity
Function        Find-NetRoute                                      1.0.0.0    NetTCPIP
Function        Find-RoleCapability                                1.0.0.1    PowerShellGet
Function        Find-Script                                        1.0.0.1    PowerShellGet
Function        Flush-EtwTraceSession                              1.0.0.0    EventTracin...
Function        Format-Hex                                         3.1.0.0    Microsoft.P...
Function        Format-Volume                                      2.0.0.0    Storage
Function        G:
Function        Get-AppBackgroundTask                              1.0.0.0    AppBackgrou...
Function        Get-AppvVirtualProcess                             1.0.0.0    AppvClient
Function        Get-AppxLastError                                  2.0.1.0    Appx
Function        Get-AppxLog                                        2.0.1.0    Appx
Function        Get-AssignedAccess                                 1.0.0.0    AssignedAccess
Function        Get-AutologgerConfig                               1.0.0.0    EventTracin...
Function        Get-BCClientConfiguration                          1.0.0.0    BranchCache
Function        Get-BCContentServerConfiguration                   1.0.0.0    BranchCache
Function        Get-BCDataCache                                    1.0.0.0    BranchCache
Function        Get-BCDataCacheExtension                           1.0.0.0    BranchCache
Function        Get-BCHashCache                                    1.0.0.0    BranchCache
Function        Get-BCHostedCacheServerConfiguration               1.0.0.0    BranchCache
Function        Get-BCNetworkConfiguration                         1.0.0.0    BranchCache
Function        Get-BCStatus                                       1.0.0.0    BranchCache
Function        Get-BitLockerVolume                                1.0.0.0    BitLocker
Function        Get-ClusteredScheduledTask                         1.0.0.0    ScheduledTasks
Function        Get-DAClientExperienceConfiguration                1.0.0.0    DirectAcces...
Function        Get-DAConnectionStatus                             1.0.0.0    NetworkConn...
Function        Get-DAEntryPointTableItem                          1.0.0.0    DirectAcces...
Function        Get-DedupProperties                                2.0.0.0    Storage
Function        Get-Disk                                           2.0.0.0    Storage
Function        Get-DiskImage                                      2.0.0.0    Storage
Function        Get-DiskStorageNodeView                            2.0.0.0    Storage
Function        Get-DnsClient                                      1.0.0.0    DnsClient
Function        Get-DnsClientCache                                 1.0.0.0    DnsClient
Function        Get-DnsClientGlobalSetting                         1.0.0.0    DnsClient
Function        Get-DnsClientNrptGlobal                            1.0.0.0    DnsClient
Function        Get-DnsClientNrptPolicy                            1.0.0.0    DnsClient
Function        Get-DnsClientNrptRule                              1.0.0.0    DnsClient
Function        Get-DnsClientServerAddress                         1.0.0.0    DnsClient
Function        Get-DscConfiguration                               1.1        PSDesiredSt...
Function        Get-DscConfigurationStatus                         1.1        PSDesiredSt...
Function        Get-DscLocalConfigurationManager                   1.1        PSDesiredSt...
Function        Get-DscResource                                    1.1        PSDesiredSt...
Function        Get-Dtc                                            1.0.0.0    MsDtc
Function        Get-DtcAdvancedHostSetting                         1.0.0.0    MsDtc
Function        Get-DtcAdvancedSetting                             1.0.0.0    MsDtc
Function        Get-DtcClusterDefault                              1.0.0.0    MsDtc
Function        Get-DtcClusterTMMapping                            1.0.0.0    MsDtc
Function        Get-DtcDefault                                     1.0.0.0    MsDtc
Function        Get-DtcLog                                         1.0.0.0    MsDtc
Function        Get-DtcNetworkSetting                              1.0.0.0    MsDtc
Function        Get-DtcTransaction                                 1.0.0.0    MsDtc
Function        Get-DtcTransactionsStatistics                      1.0.0.0    MsDtc
Function        Get-DtcTransactionsTraceSession                    1.0.0.0    MsDtc
Function        Get-DtcTransactionsTraceSetting                    1.0.0.0    MsDtc
Function        Get-EtwTraceProvider                               1.0.0.0    EventTracin...
Function        Get-EtwTraceSession                                1.0.0.0    EventTracin...
Function        Get-FileHash                                       3.1.0.0    Microsoft.P...
Function        Get-FileIntegrity                                  2.0.0.0    Storage
Function        Get-FileShare                                      2.0.0.0    Storage
Function        Get-FileShareAccessControlEntry                    2.0.0.0    Storage
Function        Get-FileStorageTier                                2.0.0.0    Storage
Function        Get-HgsClientConfiguration                         1.0.0.0    HgsClient
Function        Get-HgsClientHostKey                               1.0.0.0    HgsClient
Function        Get-HgsGuardian                                    1.0.0.0    HgsClient
Function        Get-HnsEndpoint                                    1.0.0.1    HostNetwork...
Function        Get-HnsNamespace                                   1.0.0.1    HostNetwork...
Function        Get-HnsNetwork                                     1.0.0.1    HostNetwork...
Function        Get-HnsPolicyList                                  1.0.0.1    HostNetwork...
Function        Get-InitiatorId                                    2.0.0.0    Storage
Function        Get-InitiatorPort                                  2.0.0.0    Storage
Function        Get-InstalledModule                                1.0.0.1    PowerShellGet
Function        Get-InstalledScript                                1.0.0.1    PowerShellGet
Function        Get-IscsiConnection                                1.0.0.0    iSCSI
Function        Get-IscsiSession                                   1.0.0.0    iSCSI
Function        Get-IscsiTarget                                    1.0.0.0    iSCSI
Function        Get-IscsiTargetPortal                              1.0.0.0    iSCSI
Function        Get-IseSnippet                                     1.0.0.0    ISE
Function        Get-LogProperties                                  1.0.0.0    PSDiagnostics
Function        Get-MaskingSet                                     2.0.0.0    Storage
Function        Get-MMAgent                                        1.0        MMAgent
Function        Get-MockDynamicParameters                          3.4.0      Pester
Function        Get-MpComputerStatus                               1.0        ConfigDefender
Function        Get-MpComputerStatus                               1.0        Defender
Function        Get-MpPreference                                   1.0        ConfigDefender
Function        Get-MpPreference                                   1.0        Defender
Function        Get-MpThreat                                       1.0        ConfigDefender
Function        Get-MpThreat                                       1.0        Defender
Function        Get-MpThreatCatalog                                1.0        ConfigDefender
Function        Get-MpThreatCatalog                                1.0        Defender
Function        Get-MpThreatDetection                              1.0        ConfigDefender
Function        Get-MpThreatDetection                              1.0        Defender
Function        Get-NCSIPolicyConfiguration                        1.0.0.0    NetworkConn...
Function        Get-Net6to4Configuration                           1.0.0.0    NetworkTran...
Function        Get-NetAdapter                                     2.0.0.0    NetAdapter
Function        Get-NetAdapterAdvancedProperty                     2.0.0.0    NetAdapter
Function        Get-NetAdapterBinding                              2.0.0.0    NetAdapter
Function        Get-NetAdapterChecksumOffload                      2.0.0.0    NetAdapter
Function        Get-NetAdapterEncapsulatedPacketTaskOffload        2.0.0.0    NetAdapter
Function        Get-NetAdapterHardwareInfo                         2.0.0.0    NetAdapter
Function        Get-NetAdapterIPsecOffload                         2.0.0.0    NetAdapter
Function        Get-NetAdapterLso                                  2.0.0.0    NetAdapter
Function        Get-NetAdapterPacketDirect                         2.0.0.0    NetAdapter
Function        Get-NetAdapterPowerManagement                      2.0.0.0    NetAdapter
Function        Get-NetAdapterQos                                  2.0.0.0    NetAdapter
Function        Get-NetAdapterRdma                                 2.0.0.0    NetAdapter
Function        Get-NetAdapterRsc                                  2.0.0.0    NetAdapter
Function        Get-NetAdapterRss                                  2.0.0.0    NetAdapter
Function        Get-NetAdapterSriov                                2.0.0.0    NetAdapter
Function        Get-NetAdapterSriovVf                              2.0.0.0    NetAdapter
Function        Get-NetAdapterStatistics                           2.0.0.0    NetAdapter
Function        Get-NetAdapterUso                                  2.0.0.0    NetAdapter
Function        Get-NetAdapterVmq                                  2.0.0.0    NetAdapter
Function        Get-NetAdapterVMQQueue                             2.0.0.0    NetAdapter
Function        Get-NetAdapterVPort                                2.0.0.0    NetAdapter
Function        Get-NetCompartment                                 1.0.0.0    NetTCPIP
Function        Get-NetConnectionProfile                           1.0.0.0    NetConnection
Function        Get-NetDnsTransitionConfiguration                  1.0.0.0    NetworkTran...
Function        Get-NetDnsTransitionMonitoring                     1.0.0.0    NetworkTran...
Function        Get-NetEventNetworkAdapter                         1.0.0.0    NetEventPac...
Function        Get-NetEventPacketCaptureProvider                  1.0.0.0    NetEventPac...
Function        Get-NetEventProvider                               1.0.0.0    NetEventPac...
Function        Get-NetEventSession                                1.0.0.0    NetEventPac...
Function        Get-NetEventVFPProvider                            1.0.0.0    NetEventPac...
Function        Get-NetEventVmNetworkAdapter                       1.0.0.0    NetEventPac...
Function        Get-NetEventVmSwitch                               1.0.0.0    NetEventPac...
Function        Get-NetEventVmSwitchProvider                       1.0.0.0    NetEventPac...
Function        Get-NetEventWFPCaptureProvider                     1.0.0.0    NetEventPac...
Function        Get-NetFirewallAddressFilter                       2.0.0.0    NetSecurity
Function        Get-NetFirewallApplicationFilter                   2.0.0.0    NetSecurity
Function        Get-NetFirewallInterfaceFilter                     2.0.0.0    NetSecurity
Function        Get-NetFirewallInterfaceTypeFilter                 2.0.0.0    NetSecurity
Function        Get-NetFirewallPortFilter                          2.0.0.0    NetSecurity
Function        Get-NetFirewallProfile                             2.0.0.0    NetSecurity
Function        Get-NetFirewallRule                                2.0.0.0    NetSecurity
Function        Get-NetFirewallSecurityFilter                      2.0.0.0    NetSecurity
Function        Get-NetFirewallServiceFilter                       2.0.0.0    NetSecurity
Function        Get-NetFirewallSetting                             2.0.0.0    NetSecurity
Function        Get-NetIPAddress                                   1.0.0.0    NetTCPIP
Function        Get-NetIPConfiguration                             1.0.0.0    NetTCPIP
Function        Get-NetIPHttpsConfiguration                        1.0.0.0    NetworkTran...
Function        Get-NetIPHttpsState                                1.0.0.0    NetworkTran...
Function        Get-NetIPInterface                                 1.0.0.0    NetTCPIP
Function        Get-NetIPsecDospSetting                            2.0.0.0    NetSecurity
Function        Get-NetIPsecMainModeCryptoSet                      2.0.0.0    NetSecurity
Function        Get-NetIPsecMainModeRule                           2.0.0.0    NetSecurity
Function        Get-NetIPsecMainModeSA                             2.0.0.0    NetSecurity
Function        Get-NetIPsecPhase1AuthSet                          2.0.0.0    NetSecurity
Function        Get-NetIPsecPhase2AuthSet                          2.0.0.0    NetSecurity
Function        Get-NetIPsecQuickModeCryptoSet                     2.0.0.0    NetSecurity
Function        Get-NetIPsecQuickModeSA                            2.0.0.0    NetSecurity
Function        Get-NetIPsecRule                                   2.0.0.0    NetSecurity
Function        Get-NetIPv4Protocol                                1.0.0.0    NetTCPIP
Function        Get-NetIPv6Protocol                                1.0.0.0    NetTCPIP
Function        Get-NetIsatapConfiguration                         1.0.0.0    NetworkTran...
Function        Get-NetLbfoTeam                                    2.0.0.0    NetLbfo
Function        Get-NetLbfoTeamMember                              2.0.0.0    NetLbfo
Function        Get-NetLbfoTeamNic                                 2.0.0.0    NetLbfo
Function        Get-NetNat                                         1.0.0.0    NetNat
Function        Get-NetNatExternalAddress                          1.0.0.0    NetNat
Function        Get-NetNatGlobal                                   1.0.0.0    NetNat
Function        Get-NetNatSession                                  1.0.0.0    NetNat
Function        Get-NetNatStaticMapping                            1.0.0.0    NetNat
Function        Get-NetNatTransitionConfiguration                  1.0.0.0    NetworkTran...
Function        Get-NetNatTransitionMonitoring                     1.0.0.0    NetworkTran...
Function        Get-NetNeighbor                                    1.0.0.0    NetTCPIP
Function        Get-NetOffloadGlobalSetting                        1.0.0.0    NetTCPIP
Function        Get-NetPrefixPolicy                                1.0.0.0    NetTCPIP
Function        Get-NetQosPolicy                                   2.0.0.0    NetQos
Function        Get-NetRoute                                       1.0.0.0    NetTCPIP
Function        Get-NetSwitchTeam                                  1.0.0.0    NetSwitchTeam
Function        Get-NetSwitchTeamMember                            1.0.0.0    NetSwitchTeam
Function        Get-NetTCPConnection                               1.0.0.0    NetTCPIP
Function        Get-NetTCPSetting                                  1.0.0.0    NetTCPIP
Function        Get-NetTeredoConfiguration                         1.0.0.0    NetworkTran...
Function        Get-NetTeredoState                                 1.0.0.0    NetworkTran...
Function        Get-NetTransportFilter                             1.0.0.0    NetTCPIP
Function        Get-NetUDPEndpoint                                 1.0.0.0    NetTCPIP
Function        Get-NetUDPSetting                                  1.0.0.0    NetTCPIP
Function        Get-NetworkSwitchEthernetPort                      1.0.0.0    NetworkSwit...
Function        Get-NetworkSwitchFeature                           1.0.0.0    NetworkSwit...
Function        Get-NetworkSwitchGlobalData                        1.0.0.0    NetworkSwit...
Function        Get-NetworkSwitchVlan                              1.0.0.0    NetworkSwit...
Function        Get-OdbcDriver                                     1.0.0.0    Wdac
Function        Get-OdbcDsn                                        1.0.0.0    Wdac
Function        Get-OdbcPerfCounter                                1.0.0.0    Wdac
Function        Get-OffloadDataTransferSetting                     2.0.0.0    Storage
Function        Get-OperationValidation                            1.0.1      Microsoft.P...
Function        Get-Partition                                      2.0.0.0    Storage
Function        Get-PartitionSupportedSize                         2.0.0.0    Storage
Function        Get-PcsvDevice                                     1.0.0.0    PcsvDevice
Function        Get-PcsvDeviceLog                                  1.0.0.0    PcsvDevice
Function        Get-PhysicalDisk                                   2.0.0.0    Storage
Function        Get-PhysicalDiskStorageNodeView                    2.0.0.0    Storage
Function        Get-PhysicalExtent                                 2.0.0.0    Storage
Function        Get-PhysicalExtentAssociation                      2.0.0.0    Storage
Function        Get-PnpDevice                                      1.0.0.0    PnpDevice
Function        Get-PnpDeviceProperty                              1.0.0.0    PnpDevice
Function        Get-PrintConfiguration                             1.1        PrintManage...
Function        Get-Printer                                        1.1        PrintManage...
Function        Get-PrinterDriver                                  1.1        PrintManage...
Function        Get-PrinterPort                                    1.1        PrintManage...
Function        Get-PrinterProperty                                1.1        PrintManage...
Function        Get-PrintJob                                       1.1        PrintManage...
Function        Get-PSRepository                                   1.0.0.1    PowerShellGet
Function        Get-ResiliencySetting                              2.0.0.0    Storage
Function        Get-ScheduledTask                                  1.0.0.0    ScheduledTasks
Function        Get-ScheduledTaskInfo                              1.0.0.0    ScheduledTasks
Function        Get-SmbBandWidthLimit                              2.0.0.0    SmbShare
Function        Get-SmbClientConfiguration                         2.0.0.0    SmbShare
Function        Get-SmbClientNetworkInterface                      2.0.0.0    SmbShare
Function        Get-SmbConnection                                  2.0.0.0    SmbShare
Function        Get-SmbDelegation                                  2.0.0.0    SmbShare
Function        Get-SmbGlobalMapping                               2.0.0.0    SmbShare
Function        Get-SmbMapping                                     2.0.0.0    SmbShare
Function        Get-SmbMultichannelConnection                      2.0.0.0    SmbShare
Function        Get-SmbMultichannelConstraint                      2.0.0.0    SmbShare
Function        Get-SmbOpenFile                                    2.0.0.0    SmbShare
Function        Get-SmbServerConfiguration                         2.0.0.0    SmbShare
Function        Get-SmbServerNetworkInterface                      2.0.0.0    SmbShare
Function        Get-SmbSession                                     2.0.0.0    SmbShare
Function        Get-SmbShare                                       2.0.0.0    SmbShare
Function        Get-SmbShareAccess                                 2.0.0.0    SmbShare
Function        Get-SmbWitnessClient                               2.0.0.0    SmbWitness
Function        Get-StartApps                                      1.0.0.0    StartLayout
Function        Get-StorageAdvancedProperty                        2.0.0.0    Storage
Function        Get-StorageBusBinding                              1.0.0.0    StorageBusC...
Function        Get-StorageBusDisk                                 1.0.0.0    StorageBusC...
Function        Get-StorageChassis                                 2.0.0.0    Storage
Function        Get-StorageDiagnosticInfo                          2.0.0.0    Storage
Function        Get-StorageEnclosure                               2.0.0.0    Storage
Function        Get-StorageEnclosureStorageNodeView                2.0.0.0    Storage
Function        Get-StorageEnclosureVendorData                     2.0.0.0    Storage
Function        Get-StorageExtendedStatus                          2.0.0.0    Storage
Function        Get-StorageFaultDomain                             2.0.0.0    Storage
Function        Get-StorageFileServer                              2.0.0.0    Storage
Function        Get-StorageFirmwareInformation                     2.0.0.0    Storage
Function        Get-StorageHealthAction                            2.0.0.0    Storage
Function        Get-StorageHealthReport                            2.0.0.0    Storage
Function        Get-StorageHealthSetting                           2.0.0.0    Storage
Function        Get-StorageHistory                                 2.0.0.0    Storage
Function        Get-StorageJob                                     2.0.0.0    Storage
Function        Get-StorageNode                                    2.0.0.0    Storage
Function        Get-StoragePool                                    2.0.0.0    Storage
Function        Get-StorageProvider                                2.0.0.0    Storage
Function        Get-StorageRack                                    2.0.0.0    Storage
Function        Get-StorageReliabilityCounter                      2.0.0.0    Storage
Function        Get-StorageScaleUnit                               2.0.0.0    Storage
Function        Get-StorageSetting                                 2.0.0.0    Storage
Function        Get-StorageSite                                    2.0.0.0    Storage
Function        Get-StorageSubSystem                               2.0.0.0    Storage
Function        Get-StorageTier                                    2.0.0.0    Storage
Function        Get-StorageTierSupportedSize                       2.0.0.0    Storage
Function        Get-SupportedClusterSizes                          2.0.0.0    Storage
Function        Get-SupportedFileSystems                           2.0.0.0    Storage
Function        Get-TargetPort                                     2.0.0.0    Storage
Function        Get-TargetPortal                                   2.0.0.0    Storage
Function        Get-TestDriveItem                                  3.4.0      Pester
Function        Get-Verb
Function        Get-VirtualDisk                                    2.0.0.0    Storage
Function        Get-VirtualDiskSupportedSize                       2.0.0.0    Storage
Function        Get-Volume                                         2.0.0.0    Storage
Function        Get-VolumeCorruptionCount                          2.0.0.0    Storage
Function        Get-VolumeScrubPolicy                              2.0.0.0    Storage
Function        Get-VpnConnection                                  2.0.0.0    VpnClient
Function        Get-VpnConnectionTrigger                           2.0.0.0    VpnClient
Function        Get-WdacBidTrace                                   1.0.0.0    Wdac
Function        Get-WindowsUpdateLog                               1.0.0.0    WindowsUpdate
Function        Get-WUAVersion                                     1.0.0.2    WindowsUpda...
Function        Get-WUIsPendingReboot                              1.0.0.2    WindowsUpda...
Function        Get-WULastInstallationDate                         1.0.0.2    WindowsUpda...
Function        Get-WULastScanSuccessDate                          1.0.0.2    WindowsUpda...
Function        Grant-FileShareAccess                              2.0.0.0    Storage
Function        Grant-HgsKeyProtectorAccess                        1.0.0.0    HgsClient
Function        Grant-SmbShareAccess                               2.0.0.0    SmbShare
Function        H:
Function        help
Function        Hide-VirtualDisk                                   2.0.0.0    Storage
Function        I:
Function        Import-BCCachePackage                              1.0.0.0    BranchCache
Function        Import-BCSecretKey                                 1.0.0.0    BranchCache
Function        Import-HgsGuardian                                 1.0.0.0    HgsClient
Function        Import-IseSnippet                                  1.0.0.0    ISE
Function        Import-PowerShellDataFile                          3.1.0.0    Microsoft.P...
Function        ImportSystemModules
Function        In                                                 3.4.0      Pester
Function        Initialize-Disk                                    2.0.0.0    Storage
Function        InModuleScope                                      3.4.0      Pester
Function        Install-Dtc                                        1.0.0.0    MsDtc
Function        Install-Module                                     1.0.0.1    PowerShellGet
Function        Install-Script                                     1.0.0.1    PowerShellGet
Function        Install-WUUpdates                                  1.0.0.2    WindowsUpda...
Function        Invoke-AsWorkflow                                  1.0.0.0    PSWorkflowU...
Function        Invoke-Mock                                        3.4.0      Pester
Function        Invoke-OperationValidation                         1.0.1      Microsoft.P...
Function        Invoke-Pester                                      3.4.0      Pester
Function        It                                                 3.4.0      Pester
Function        J:
Function        K:
Function        L:
Function        Lock-BitLocker                                     1.0.0.0    BitLocker
Function        M:
Function        mkdir
Function        Mock                                               3.4.0      Pester
Function        more
Function        Mount-DiskImage                                    2.0.0.0    Storage
Function        Move-SmbWitnessClient                              2.0.0.0    SmbWitness
Function        N:
Function        New-AutologgerConfig                               1.0.0.0    EventTracin...
Function        New-DAEntryPointTableItem                          1.0.0.0    DirectAcces...
Function        New-DscChecksum                                    1.1        PSDesiredSt...
Function        New-EapConfiguration                               2.0.0.0    VpnClient
Function        New-EtwTraceSession                                1.0.0.0    EventTracin...
Function        New-FileShare                                      2.0.0.0    Storage
Function        New-Fixture                                        3.4.0      Pester
Function        New-Guid                                           3.1.0.0    Microsoft.P...
Function        New-HgsGuardian                                    1.0.0.0    HgsClient
Function        New-HgsKeyProtector                                1.0.0.0    HgsClient
Function        New-IscsiTargetPortal                              1.0.0.0    iSCSI
Function        New-IseSnippet                                     1.0.0.0    ISE
Function        New-MaskingSet                                     2.0.0.0    Storage
Function        New-NetAdapterAdvancedProperty                     2.0.0.0    NetAdapter
Function        New-NetEventSession                                1.0.0.0    NetEventPac...
Function        New-NetFirewallRule                                2.0.0.0    NetSecurity
Function        New-NetIPAddress                                   1.0.0.0    NetTCPIP
Function        New-NetIPHttpsConfiguration                        1.0.0.0    NetworkTran...
Function        New-NetIPsecDospSetting                            2.0.0.0    NetSecurity
Function        New-NetIPsecMainModeCryptoSet                      2.0.0.0    NetSecurity
Function        New-NetIPsecMainModeRule                           2.0.0.0    NetSecurity
Function        New-NetIPsecPhase1AuthSet                          2.0.0.0    NetSecurity
Function        New-NetIPsecPhase2AuthSet                          2.0.0.0    NetSecurity
Function        New-NetIPsecQuickModeCryptoSet                     2.0.0.0    NetSecurity
Function        New-NetIPsecRule                                   2.0.0.0    NetSecurity
Function        New-NetLbfoTeam                                    2.0.0.0    NetLbfo
Function        New-NetNat                                         1.0.0.0    NetNat
Function        New-NetNatTransitionConfiguration                  1.0.0.0    NetworkTran...
Function        New-NetNeighbor                                    1.0.0.0    NetTCPIP
Function        New-NetQosPolicy                                   2.0.0.0    NetQos
Function        New-NetRoute                                       1.0.0.0    NetTCPIP
Function        New-NetSwitchTeam                                  1.0.0.0    NetSwitchTeam
Function        New-NetTransportFilter                             1.0.0.0    NetTCPIP
Function        New-NetworkSwitchVlan                              1.0.0.0    NetworkSwit...
Function        New-Partition                                      2.0.0.0    Storage
Function        New-PesterOption                                   3.4.0      Pester
Function        New-PSWorkflowSession                              2.0.0.0    PSWorkflow
Function        New-ScheduledTask                                  1.0.0.0    ScheduledTasks
Function        New-ScheduledTaskAction                            1.0.0.0    ScheduledTasks
Function        New-ScheduledTaskPrincipal                         1.0.0.0    ScheduledTasks
Function        New-ScheduledTaskSettingsSet                       1.0.0.0    ScheduledTasks
Function        New-ScheduledTaskTrigger                           1.0.0.0    ScheduledTasks
Function        New-ScriptFileInfo                                 1.0.0.1    PowerShellGet
Function        New-SmbGlobalMapping                               2.0.0.0    SmbShare
Function        New-SmbMapping                                     2.0.0.0    SmbShare
Function        New-SmbMultichannelConstraint                      2.0.0.0    SmbShare
Function        New-SmbShare                                       2.0.0.0    SmbShare
Function        New-StorageBusBinding                              1.0.0.0    StorageBusC...
Function        New-StorageBusCacheStore                           1.0.0.0    StorageBusC...
Function        New-StorageFileServer                              2.0.0.0    Storage
Function        New-StoragePool                                    2.0.0.0    Storage
Function        New-StorageSubsystemVirtualDisk                    2.0.0.0    Storage
Function        New-StorageTier                                    2.0.0.0    Storage
Function        New-TemporaryFile                                  3.1.0.0    Microsoft.P...
Function        New-VirtualDisk                                    2.0.0.0    Storage
Function        New-VirtualDiskClone                               2.0.0.0    Storage
Function        New-VirtualDiskSnapshot                            2.0.0.0    Storage
Function        New-Volume                                         2.0.0.0    Storage
Function        New-VpnServerAddress                               2.0.0.0    VpnClient
Function        O:
Function        Open-NetGPO                                        2.0.0.0    NetSecurity
Function        Optimize-StoragePool                               2.0.0.0    Storage
Function        Optimize-Volume                                    2.0.0.0    Storage
Function        oss
Function        P:
Function        Pause
Function        prompt
Function        PSConsoleHostReadLine                              2.0.0      PSReadline
Function        Publish-BCFileContent                              1.0.0.0    BranchCache
Function        Publish-BCWebContent                               1.0.0.0    BranchCache
Function        Publish-Module                                     1.0.0.1    PowerShellGet
Function        Publish-Script                                     1.0.0.1    PowerShellGet
Function        Q:
Function        R:
Function        Read-PrinterNfcTag                                 1.1        PrintManage...
Function        Register-ClusteredScheduledTask                    1.0.0.0    ScheduledTasks
Function        Register-DnsClient                                 1.0.0.0    DnsClient
Function        Register-IscsiSession                              1.0.0.0    iSCSI
Function        Register-PSRepository                              1.0.0.1    PowerShellGet
Function        Register-ScheduledTask                             1.0.0.0    ScheduledTasks
Function        Register-StorageSubsystem                          2.0.0.0    Storage
Function        Remove-AutologgerConfig                            1.0.0.0    EventTracin...
Function        Remove-BCDataCacheExtension                        1.0.0.0    BranchCache
Function        Remove-BitLockerKeyProtector                       1.0.0.0    BitLocker
Function        Remove-DAEntryPointTableItem                       1.0.0.0    DirectAcces...
Function        Remove-DnsClientNrptRule                           1.0.0.0    DnsClient
Function        Remove-DscConfigurationDocument                    1.1        PSDesiredSt...
Function        Remove-DtcClusterTMMapping                         1.0.0.0    MsDtc
Function        Remove-EtwTraceProvider                            1.0.0.0    EventTracin...
Function        Remove-FileShare                                   2.0.0.0    Storage
Function        Remove-HgsClientHostKey                            1.0.0.0    HgsClient
Function        Remove-HgsGuardian                                 1.0.0.0    HgsClient
Function        Remove-HnsEndpoint                                 1.0.0.1    HostNetwork...
Function        Remove-HnsNamespace                                1.0.0.1    HostNetwork...
Function        Remove-HnsNetwork                                  1.0.0.1    HostNetwork...
Function        Remove-HnsPolicyList                               1.0.0.1    HostNetwork...
Function        Remove-InitiatorId                                 2.0.0.0    Storage
Function        Remove-InitiatorIdFromMaskingSet                   2.0.0.0    Storage
Function        Remove-IscsiTargetPortal                           1.0.0.0    iSCSI
Function        Remove-MaskingSet                                  2.0.0.0    Storage
Function        Remove-MpPreference                                1.0        ConfigDefender
Function        Remove-MpPreference                                1.0        Defender
Function        Remove-MpThreat                                    1.0        ConfigDefender
Function        Remove-MpThreat                                    1.0        Defender
Function        Remove-NetAdapterAdvancedProperty                  2.0.0.0    NetAdapter
Function        Remove-NetEventNetworkAdapter                      1.0.0.0    NetEventPac...
Function        Remove-NetEventPacketCaptureProvider               1.0.0.0    NetEventPac...
Function        Remove-NetEventProvider                            1.0.0.0    NetEventPac...
Function        Remove-NetEventSession                             1.0.0.0    NetEventPac...
Function        Remove-NetEventVFPProvider                         1.0.0.0    NetEventPac...
Function        Remove-NetEventVmNetworkAdapter                    1.0.0.0    NetEventPac...
Function        Remove-NetEventVmSwitch                            1.0.0.0    NetEventPac...
Function        Remove-NetEventVmSwitchProvider                    1.0.0.0    NetEventPac...
Function        Remove-NetEventWFPCaptureProvider                  1.0.0.0    NetEventPac...
Function        Remove-NetFirewallRule                             2.0.0.0    NetSecurity
Function        Remove-NetIPAddress                                1.0.0.0    NetTCPIP
Function        Remove-NetIPHttpsCertBinding                       1.0.0.0    NetworkTran...
Function        Remove-NetIPHttpsConfiguration                     1.0.0.0    NetworkTran...
Function        Remove-NetIPsecDospSetting                         2.0.0.0    NetSecurity
Function        Remove-NetIPsecMainModeCryptoSet                   2.0.0.0    NetSecurity
Function        Remove-NetIPsecMainModeRule                        2.0.0.0    NetSecurity
Function        Remove-NetIPsecMainModeSA                          2.0.0.0    NetSecurity
Function        Remove-NetIPsecPhase1AuthSet                       2.0.0.0    NetSecurity
Function        Remove-NetIPsecPhase2AuthSet                       2.0.0.0    NetSecurity
Function        Remove-NetIPsecQuickModeCryptoSet                  2.0.0.0    NetSecurity
Function        Remove-NetIPsecQuickModeSA                         2.0.0.0    NetSecurity
Function        Remove-NetIPsecRule                                2.0.0.0    NetSecurity
Function        Remove-NetLbfoTeam                                 2.0.0.0    NetLbfo
Function        Remove-NetLbfoTeamMember                           2.0.0.0    NetLbfo
Function        Remove-NetLbfoTeamNic                              2.0.0.0    NetLbfo
Function        Remove-NetNat                                      1.0.0.0    NetNat
Function        Remove-NetNatExternalAddress                       1.0.0.0    NetNat
Function        Remove-NetNatStaticMapping                         1.0.0.0    NetNat
Function        Remove-NetNatTransitionConfiguration               1.0.0.0    NetworkTran...
Function        Remove-NetNeighbor                                 1.0.0.0    NetTCPIP
Function        Remove-NetQosPolicy                                2.0.0.0    NetQos
Function        Remove-NetRoute                                    1.0.0.0    NetTCPIP
Function        Remove-NetSwitchTeam                               1.0.0.0    NetSwitchTeam
Function        Remove-NetSwitchTeamMember                         1.0.0.0    NetSwitchTeam
Function        Remove-NetTransportFilter                          1.0.0.0    NetTCPIP
Function        Remove-NetworkSwitchEthernetPortIPAddress          1.0.0.0    NetworkSwit...
Function        Remove-NetworkSwitchVlan                           1.0.0.0    NetworkSwit...
Function        Remove-OdbcDsn                                     1.0.0.0    Wdac
Function        Remove-Partition                                   2.0.0.0    Storage
Function        Remove-PartitionAccessPath                         2.0.0.0    Storage
Function        Remove-PhysicalDisk                                2.0.0.0    Storage
Function        Remove-Printer                                     1.1        PrintManage...
Function        Remove-PrinterDriver                               1.1        PrintManage...
Function        Remove-PrinterPort                                 1.1        PrintManage...
Function        Remove-PrintJob                                    1.1        PrintManage...
Function        Remove-SmbBandwidthLimit                           2.0.0.0    SmbShare
Function        Remove-SmbGlobalMapping                            2.0.0.0    SmbShare
Function        Remove-SmbMapping                                  2.0.0.0    SmbShare
Function        Remove-SmbMultichannelConstraint                   2.0.0.0    SmbShare
Function        Remove-SmbShare                                    2.0.0.0    SmbShare
Function        Remove-StorageBusBinding                           1.0.0.0    StorageBusC...
Function        Remove-StorageFaultDomain                          2.0.0.0    Storage
Function        Remove-StorageFileServer                           2.0.0.0    Storage
Function        Remove-StorageHealthIntent                         2.0.0.0    Storage
Function        Remove-StorageHealthSetting                        2.0.0.0    Storage
Function        Remove-StoragePool                                 2.0.0.0    Storage
Function        Remove-StorageTier                                 2.0.0.0    Storage
Function        Remove-TargetPortFromMaskingSet                    2.0.0.0    Storage
Function        Remove-VirtualDisk                                 2.0.0.0    Storage
Function        Remove-VirtualDiskFromMaskingSet                   2.0.0.0    Storage
Function        Remove-VpnConnection                               2.0.0.0    VpnClient
Function        Remove-VpnConnectionRoute                          2.0.0.0    VpnClient
Function        Remove-VpnConnectionTriggerApplication             2.0.0.0    VpnClient
Function        Remove-VpnConnectionTriggerDnsConfiguration        2.0.0.0    VpnClient
Function        Remove-VpnConnectionTriggerTrustedNetwork          2.0.0.0    VpnClient
Function        Rename-DAEntryPointTableItem                       1.0.0.0    DirectAcces...
Function        Rename-MaskingSet                                  2.0.0.0    Storage
Function        Rename-NetAdapter                                  2.0.0.0    NetAdapter
Function        Rename-NetFirewallRule                             2.0.0.0    NetSecurity
Function        Rename-NetIPHttpsConfiguration                     1.0.0.0    NetworkTran...
Function        Rename-NetIPsecMainModeCryptoSet                   2.0.0.0    NetSecurity
Function        Rename-NetIPsecMainModeRule                        2.0.0.0    NetSecurity
Function        Rename-NetIPsecPhase1AuthSet                       2.0.0.0    NetSecurity
Function        Rename-NetIPsecPhase2AuthSet                       2.0.0.0    NetSecurity
Function        Rename-NetIPsecQuickModeCryptoSet                  2.0.0.0    NetSecurity
Function        Rename-NetIPsecRule                                2.0.0.0    NetSecurity
Function        Rename-NetLbfoTeam                                 2.0.0.0    NetLbfo
Function        Rename-NetSwitchTeam                               1.0.0.0    NetSwitchTeam
Function        Rename-Printer                                     1.1        PrintManage...
Function        Repair-FileIntegrity                               2.0.0.0    Storage
Function        Repair-VirtualDisk                                 2.0.0.0    Storage
Function        Repair-Volume                                      2.0.0.0    Storage
Function        Reset-BC                                           1.0.0.0    BranchCache
Function        Reset-DAClientExperienceConfiguration              1.0.0.0    DirectAcces...
Function        Reset-DAEntryPointTableItem                        1.0.0.0    DirectAcces...
Function        Reset-DtcLog                                       1.0.0.0    MsDtc
Function        Reset-NCSIPolicyConfiguration                      1.0.0.0    NetworkConn...
Function        Reset-Net6to4Configuration                         1.0.0.0    NetworkTran...
Function        Reset-NetAdapterAdvancedProperty                   2.0.0.0    NetAdapter
Function        Reset-NetDnsTransitionConfiguration                1.0.0.0    NetworkTran...
Function        Reset-NetIPHttpsConfiguration                      1.0.0.0    NetworkTran...
Function        Reset-NetIsatapConfiguration                       1.0.0.0    NetworkTran...
Function        Reset-NetTeredoConfiguration                       1.0.0.0    NetworkTran...
Function        Reset-PhysicalDisk                                 2.0.0.0    Storage
Function        Reset-StorageReliabilityCounter                    2.0.0.0    Storage
Function        Resize-Partition                                   2.0.0.0    Storage
Function        Resize-StorageTier                                 2.0.0.0    Storage
Function        Resize-VirtualDisk                                 2.0.0.0    Storage
Function        Restart-NetAdapter                                 2.0.0.0    NetAdapter
Function        Restart-PcsvDevice                                 1.0.0.0    PcsvDevice
Function        Restart-PrintJob                                   1.1        PrintManage...
Function        Restore-DscConfiguration                           1.1        PSDesiredSt...
Function        Restore-NetworkSwitchConfiguration                 1.0.0.0    NetworkSwit...
Function        Resume-BitLocker                                   1.0.0.0    BitLocker
Function        Resume-PrintJob                                    1.1        PrintManage...
Function        Resume-StorageBusDisk                              1.0.0.0    StorageBusC...
Function        Revoke-FileShareAccess                             2.0.0.0    Storage
Function        Revoke-HgsKeyProtectorAccess                       1.0.0.0    HgsClient
Function        Revoke-SmbShareAccess                              2.0.0.0    SmbShare
Function        S:
Function        SafeGetCommand                                     3.4.0      Pester
Function        Save-EtwTraceSession                               1.0.0.0    EventTracin...
Function        Save-Module                                        1.0.0.1    PowerShellGet
Function        Save-NetGPO                                        2.0.0.0    NetSecurity
Function        Save-NetworkSwitchConfiguration                    1.0.0.0    NetworkSwit...
Function        Save-Script                                        1.0.0.1    PowerShellGet
Function        Send-EtwTraceSession                               1.0.0.0    EventTracin...
Function        Set-AssignedAccess                                 1.0.0.0    AssignedAccess
Function        Set-BCAuthentication                               1.0.0.0    BranchCache
Function        Set-BCCache                                        1.0.0.0    BranchCache
Function        Set-BCDataCacheEntryMaxAge                         1.0.0.0    BranchCache
Function        Set-BCMinSMBLatency                                1.0.0.0    BranchCache
Function        Set-BCSecretKey                                    1.0.0.0    BranchCache
Function        Set-ClusteredScheduledTask                         1.0.0.0    ScheduledTasks
Function        Set-DAClientExperienceConfiguration                1.0.0.0    DirectAcces...
Function        Set-DAEntryPointTableItem                          1.0.0.0    DirectAcces...
Function        Set-Disk                                           2.0.0.0    Storage
Function        Set-DnsClient                                      1.0.0.0    DnsClient
Function        Set-DnsClientGlobalSetting                         1.0.0.0    DnsClient
Function        Set-DnsClientNrptGlobal                            1.0.0.0    DnsClient
Function        Set-DnsClientNrptRule                              1.0.0.0    DnsClient
Function        Set-DnsClientServerAddress                         1.0.0.0    DnsClient
Function        Set-DtcAdvancedHostSetting                         1.0.0.0    MsDtc
Function        Set-DtcAdvancedSetting                             1.0.0.0    MsDtc
Function        Set-DtcClusterDefault                              1.0.0.0    MsDtc
Function        Set-DtcClusterTMMapping                            1.0.0.0    MsDtc
Function        Set-DtcDefault                                     1.0.0.0    MsDtc
Function        Set-DtcLog                                         1.0.0.0    MsDtc
Function        Set-DtcNetworkSetting                              1.0.0.0    MsDtc
Function        Set-DtcTransaction                                 1.0.0.0    MsDtc
Function        Set-DtcTransactionsTraceSession                    1.0.0.0    MsDtc
Function        Set-DtcTransactionsTraceSetting                    1.0.0.0    MsDtc
Function        Set-DynamicParameterVariables                      3.4.0      Pester
Function        Set-EtwTraceProvider                               1.0.0.0    EventTracin...
Function        Set-FileIntegrity                                  2.0.0.0    Storage
Function        Set-FileShare                                      2.0.0.0    Storage
Function        Set-FileStorageTier                                2.0.0.0    Storage
Function        Set-HgsClientConfiguration                         1.0.0.0    HgsClient
Function        Set-HgsClientHostKey                               1.0.0.0    HgsClient
Function        Set-InitiatorPort                                  2.0.0.0    Storage
Function        Set-IscsiChapSecret                                1.0.0.0    iSCSI
Function        Set-LogProperties                                  1.0.0.0    PSDiagnostics
Function        Set-MMAgent                                        1.0        MMAgent
Function        Set-MpPreference                                   1.0        ConfigDefender
Function        Set-MpPreference                                   1.0        Defender
Function        Set-NCSIPolicyConfiguration                        1.0.0.0    NetworkConn...
Function        Set-Net6to4Configuration                           1.0.0.0    NetworkTran...
Function        Set-NetAdapter                                     2.0.0.0    NetAdapter
Function        Set-NetAdapterAdvancedProperty                     2.0.0.0    NetAdapter
Function        Set-NetAdapterBinding                              2.0.0.0    NetAdapter
Function        Set-NetAdapterChecksumOffload                      2.0.0.0    NetAdapter
Function        Set-NetAdapterEncapsulatedPacketTaskOffload        2.0.0.0    NetAdapter
Function        Set-NetAdapterIPsecOffload                         2.0.0.0    NetAdapter
Function        Set-NetAdapterLso                                  2.0.0.0    NetAdapter
Function        Set-NetAdapterPacketDirect                         2.0.0.0    NetAdapter
Function        Set-NetAdapterPowerManagement                      2.0.0.0    NetAdapter
Function        Set-NetAdapterQos                                  2.0.0.0    NetAdapter
Function        Set-NetAdapterRdma                                 2.0.0.0    NetAdapter
Function        Set-NetAdapterRsc                                  2.0.0.0    NetAdapter
Function        Set-NetAdapterRss                                  2.0.0.0    NetAdapter
Function        Set-NetAdapterSriov                                2.0.0.0    NetAdapter
Function        Set-NetAdapterUso                                  2.0.0.0    NetAdapter
Function        Set-NetAdapterVmq                                  2.0.0.0    NetAdapter
Function        Set-NetConnectionProfile                           1.0.0.0    NetConnection
Function        Set-NetDnsTransitionConfiguration                  1.0.0.0    NetworkTran...
Function        Set-NetEventPacketCaptureProvider                  1.0.0.0    NetEventPac...
Function        Set-NetEventProvider                               1.0.0.0    NetEventPac...
Function        Set-NetEventSession                                1.0.0.0    NetEventPac...
Function        Set-NetEventVFPProvider                            1.0.0.0    NetEventPac...
Function        Set-NetEventVmSwitchProvider                       1.0.0.0    NetEventPac...
Function        Set-NetEventWFPCaptureProvider                     1.0.0.0    NetEventPac...
Function        Set-NetFirewallAddressFilter                       2.0.0.0    NetSecurity
Function        Set-NetFirewallApplicationFilter                   2.0.0.0    NetSecurity
Function        Set-NetFirewallInterfaceFilter                     2.0.0.0    NetSecurity
Function        Set-NetFirewallInterfaceTypeFilter                 2.0.0.0    NetSecurity
Function        Set-NetFirewallPortFilter                          2.0.0.0    NetSecurity
Function        Set-NetFirewallProfile                             2.0.0.0    NetSecurity
Function        Set-NetFirewallRule                                2.0.0.0    NetSecurity
Function        Set-NetFirewallSecurityFilter                      2.0.0.0    NetSecurity
Function        Set-NetFirewallServiceFilter                       2.0.0.0    NetSecurity
Function        Set-NetFirewallSetting                             2.0.0.0    NetSecurity
Function        Set-NetIPAddress                                   1.0.0.0    NetTCPIP
Function        Set-NetIPHttpsConfiguration                        1.0.0.0    NetworkTran...
Function        Set-NetIPInterface                                 1.0.0.0    NetTCPIP
Function        Set-NetIPsecDospSetting                            2.0.0.0    NetSecurity
Function        Set-NetIPsecMainModeCryptoSet                      2.0.0.0    NetSecurity
Function        Set-NetIPsecMainModeRule                           2.0.0.0    NetSecurity
Function        Set-NetIPsecPhase1AuthSet                          2.0.0.0    NetSecurity
Function        Set-NetIPsecPhase2AuthSet                          2.0.0.0    NetSecurity
Function        Set-NetIPsecQuickModeCryptoSet                     2.0.0.0    NetSecurity
Function        Set-NetIPsecRule                                   2.0.0.0    NetSecurity
Function        Set-NetIPv4Protocol                                1.0.0.0    NetTCPIP
Function        Set-NetIPv6Protocol                                1.0.0.0    NetTCPIP
Function        Set-NetIsatapConfiguration                         1.0.0.0    NetworkTran...
Function        Set-NetLbfoTeam                                    2.0.0.0    NetLbfo
Function        Set-NetLbfoTeamMember                              2.0.0.0    NetLbfo
Function        Set-NetLbfoTeamNic                                 2.0.0.0    NetLbfo
Function        Set-NetNat                                         1.0.0.0    NetNat
Function        Set-NetNatGlobal                                   1.0.0.0    NetNat
Function        Set-NetNatTransitionConfiguration                  1.0.0.0    NetworkTran...
Function        Set-NetNeighbor                                    1.0.0.0    NetTCPIP
Function        Set-NetOffloadGlobalSetting                        1.0.0.0    NetTCPIP
Function        Set-NetQosPolicy                                   2.0.0.0    NetQos
Function        Set-NetRoute                                       1.0.0.0    NetTCPIP
Function        Set-NetTCPSetting                                  1.0.0.0    NetTCPIP
Function        Set-NetTeredoConfiguration                         1.0.0.0    NetworkTran...
Function        Set-NetUDPSetting                                  1.0.0.0    NetTCPIP
Function        Set-NetworkSwitchEthernetPortIPAddress             1.0.0.0    NetworkSwit...
Function        Set-NetworkSwitchPortMode                          1.0.0.0    NetworkSwit...
Function        Set-NetworkSwitchPortProperty                      1.0.0.0    NetworkSwit...
Function        Set-NetworkSwitchVlanProperty                      1.0.0.0    NetworkSwit...
Function        Set-OdbcDriver                                     1.0.0.0    Wdac
Function        Set-OdbcDsn                                        1.0.0.0    Wdac
Function        Set-Partition                                      2.0.0.0    Storage
Function        Set-PcsvDeviceBootConfiguration                    1.0.0.0    PcsvDevice
Function        Set-PcsvDeviceNetworkConfiguration                 1.0.0.0    PcsvDevice
Function        Set-PcsvDeviceUserPassword                         1.0.0.0    PcsvDevice
Function        Set-PhysicalDisk                                   2.0.0.0    Storage
Function        Set-PrintConfiguration                             1.1        PrintManage...
Function        Set-Printer                                        1.1        PrintManage...
Function        Set-PrinterProperty                                1.1        PrintManage...
Function        Set-PSRepository                                   1.0.0.1    PowerShellGet
Function        Set-ResiliencySetting                              2.0.0.0    Storage
Function        Set-ScheduledTask                                  1.0.0.0    ScheduledTasks
Function        Set-SmbBandwidthLimit                              2.0.0.0    SmbShare
Function        Set-SmbClientConfiguration                         2.0.0.0    SmbShare
Function        Set-SmbPathAcl                                     2.0.0.0    SmbShare
Function        Set-SmbServerConfiguration                         2.0.0.0    SmbShare
Function        Set-SmbShare                                       2.0.0.0    SmbShare
Function        Set-StorageBusProfile                              1.0.0.0    StorageBusC...
Function        Set-StorageFileServer                              2.0.0.0    Storage
Function        Set-StorageHealthSetting                           2.0.0.0    Storage
Function        Set-StoragePool                                    2.0.0.0    Storage
Function        Set-StorageProvider                                2.0.0.0    Storage
Function        Set-StorageSetting                                 2.0.0.0    Storage
Function        Set-StorageSubSystem                               2.0.0.0    Storage
Function        Set-StorageTier                                    2.0.0.0    Storage
Function        Set-TestInconclusive                               3.4.0      Pester
Function        Setup                                              3.4.0      Pester
Function        Set-VirtualDisk                                    2.0.0.0    Storage
Function        Set-Volume                                         2.0.0.0    Storage
Function        Set-VolumeScrubPolicy                              2.0.0.0    Storage
Function        Set-VpnConnection                                  2.0.0.0    VpnClient
Function        Set-VpnConnectionIPsecConfiguration                2.0.0.0    VpnClient
Function        Set-VpnConnectionProxy                             2.0.0.0    VpnClient
Function        Set-VpnConnectionTriggerDnsConfiguration           2.0.0.0    VpnClient
Function        Set-VpnConnectionTriggerTrustedNetwork             2.0.0.0    VpnClient
Function        Should                                             3.4.0      Pester
Function        Show-NetFirewallRule                               2.0.0.0    NetSecurity
Function        Show-NetIPsecRule                                  2.0.0.0    NetSecurity
Function        Show-StorageHistory                                2.0.0.0    Storage
Function        Show-VirtualDisk                                   2.0.0.0    Storage
Function        Start-AppBackgroundTask                            1.0.0.0    AppBackgrou...
Function        Start-AppvVirtualProcess                           1.0.0.0    AppvClient
Function        Start-AutologgerConfig                             1.0.0.0    EventTracin...
Function        Start-Dtc                                          1.0.0.0    MsDtc
Function        Start-DtcTransactionsTraceSession                  1.0.0.0    MsDtc
Function        Start-EtwTraceSession                              1.0.0.0    EventTracin...
Function        Start-MpScan                                       1.0        ConfigDefender
Function        Start-MpScan                                       1.0        Defender
Function        Start-MpWDOScan                                    1.0        ConfigDefender
Function        Start-MpWDOScan                                    1.0        Defender
Function        Start-NetEventSession                              1.0.0.0    NetEventPac...
Function        Start-PcsvDevice                                   1.0.0.0    PcsvDevice
Function        Start-ScheduledTask                                1.0.0.0    ScheduledTasks
Function        Start-StorageDiagnosticLog                         2.0.0.0    Storage
Function        Start-Trace                                        1.0.0.0    PSDiagnostics
Function        Start-WUScan                                       1.0.0.2    WindowsUpda...
Function        Stop-DscConfiguration                              1.1        PSDesiredSt...
Function        Stop-Dtc                                           1.0.0.0    MsDtc
Function        Stop-DtcTransactionsTraceSession                   1.0.0.0    MsDtc
Function        Stop-EtwTraceSession                               1.0.0.0    EventTracin...
Function        Stop-NetEventSession                               1.0.0.0    NetEventPac...
Function        Stop-PcsvDevice                                    1.0.0.0    PcsvDevice
Function        Stop-ScheduledTask                                 1.0.0.0    ScheduledTasks
Function        Stop-StorageDiagnosticLog                          2.0.0.0    Storage
Function        Stop-StorageJob                                    2.0.0.0    Storage
Function        Stop-Trace                                         1.0.0.0    PSDiagnostics
Function        Suspend-BitLocker                                  1.0.0.0    BitLocker
Function        Suspend-PrintJob                                   1.1        PrintManage...
Function        Suspend-StorageBusDisk                             1.0.0.0    StorageBusC...
Function        Sync-NetIPsecRule                                  2.0.0.0    NetSecurity
Function        T:
Function        TabExpansion2
Function        Test-Dtc                                           1.0.0.0    MsDtc
Function        Test-HgsClientConfiguration                        1.0.0.0    HgsClient
Function        Test-NetConnection                                 1.0.0.0    NetTCPIP
Function        Test-ScriptFileInfo                                1.0.0.1    PowerShellGet
Function        U:
Function        Unblock-FileShareAccess                            2.0.0.0    Storage
Function        Unblock-SmbShareAccess                             2.0.0.0    SmbShare
Function        Uninstall-Dtc                                      1.0.0.0    MsDtc
Function        Uninstall-Module                                   1.0.0.1    PowerShellGet
Function        Uninstall-Script                                   1.0.0.1    PowerShellGet
Function        Unlock-BitLocker                                   1.0.0.0    BitLocker
Function        Unregister-AppBackgroundTask                       1.0.0.0    AppBackgrou...
Function        Unregister-ClusteredScheduledTask                  1.0.0.0    ScheduledTasks
Function        Unregister-IscsiSession                            1.0.0.0    iSCSI
Function        Unregister-PSRepository                            1.0.0.1    PowerShellGet
Function        Unregister-ScheduledTask                           1.0.0.0    ScheduledTasks
Function        Unregister-StorageSubsystem                        2.0.0.0    Storage
Function        Update-AutologgerConfig                            1.0.0.0    EventTracin...
Function        Update-Disk                                        2.0.0.0    Storage
Function        Update-DscConfiguration                            1.1        PSDesiredSt...
Function        Update-EtwTraceSession                             1.0.0.0    EventTracin...
Function        Update-HostStorageCache                            2.0.0.0    Storage
Function        Update-IscsiTarget                                 1.0.0.0    iSCSI
Function        Update-IscsiTargetPortal                           1.0.0.0    iSCSI
Function        Update-Module                                      1.0.0.1    PowerShellGet
Function        Update-ModuleManifest                              1.0.0.1    PowerShellGet
Function        Update-MpSignature                                 1.0        ConfigDefender
Function        Update-MpSignature                                 1.0        Defender
Function        Update-NetIPsecRule                                2.0.0.0    NetSecurity
Function        Update-Script                                      1.0.0.1    PowerShellGet
Function        Update-ScriptFileInfo                              1.0.0.1    PowerShellGet
Function        Update-SmbMultichannelConnection                   2.0.0.0    SmbShare
Function        Update-StorageFirmware                             2.0.0.0    Storage
Function        Update-StoragePool                                 2.0.0.0    Storage
Function        Update-StorageProviderCache                        2.0.0.0    Storage
Function        V:
Function        W:
Function        Write-DtcTransactionsTraceSession                  1.0.0.0    MsDtc
Function        Write-PrinterNfcTag                                1.1        PrintManage...
Function        Write-VolumeCache                                  2.0.0.0    Storage
Function        X:
Function        Y:
Function        Z:
```
### 查詢結果如下(第三部分=>cmdlets)
```
Cmdlet          Add-AppvClientConnectionGroup                      1.0.0.0    AppvClient
Cmdlet          Add-AppvClientPackage                              1.0.0.0    AppvClient
Cmdlet          Add-AppvPublishingServer                           1.0.0.0    AppvClient
Cmdlet          Add-AppxPackage                                    2.0.1.0    Appx
Cmdlet          Add-AppxProvisionedPackage                         3.0        Dism
Cmdlet          Add-AppxVolume                                     2.0.1.0    Appx
Cmdlet          Add-BitsFile                                       2.0.0.0    BitsTransfer
Cmdlet          Add-CertificateEnrollmentPolicyServer              1.0.0.0    PKI
Cmdlet          Add-Computer                                       3.1.0.0    Microsoft.P...
Cmdlet          Add-Content                                        3.1.0.0    Microsoft.P...
Cmdlet          Add-History                                        3.0.0.0    Microsoft.P...
Cmdlet          Add-JobTrigger                                     1.1.0.0    PSScheduledJob
Cmdlet          Add-KdsRootKey                                     1.0.0.0    Kds
Cmdlet          Add-LocalGroupMember                               1.0.0.0    Microsoft.P...
Cmdlet          Add-Member                                         3.1.0.0    Microsoft.P...
Cmdlet          Add-PSSnapin                                       3.0.0.0    Microsoft.P...
Cmdlet          Add-SignerRule                                     1.0        ConfigCI
Cmdlet          Add-Type                                           3.1.0.0    Microsoft.P...
Cmdlet          Add-VMAssignableDevice                             2.0.0.0    Hyper-V
Cmdlet          Add-VMDvdDrive                                     2.0.0.0    Hyper-V
Cmdlet          Add-VMFibreChannelHba                              2.0.0.0    Hyper-V
Cmdlet          Add-VMGpuPartitionAdapter                          2.0.0.0    Hyper-V
Cmdlet          Add-VMGroupMember                                  2.0.0.0    Hyper-V
Cmdlet          Add-VMHardDiskDrive                                2.0.0.0    Hyper-V
Cmdlet          Add-VMHostAssignableDevice                         2.0.0.0    Hyper-V
Cmdlet          Add-VMKeyStorageDrive                              2.0.0.0    Hyper-V
Cmdlet          Add-VMMigrationNetwork                             2.0.0.0    Hyper-V
Cmdlet          Add-VMNetworkAdapter                               2.0.0.0    Hyper-V
Cmdlet          Add-VMNetworkAdapterAcl                            2.0.0.0    Hyper-V
Cmdlet          Add-VMNetworkAdapterExtendedAcl                    2.0.0.0    Hyper-V
Cmdlet          Add-VMNetworkAdapterRoutingDomainMapping           2.0.0.0    Hyper-V
Cmdlet          Add-VMPmemController                               2.0.0.0    Hyper-V
Cmdlet          Add-VMRemoteFx3dVideoAdapter                       2.0.0.0    Hyper-V
Cmdlet          Add-VMScsiController                               2.0.0.0    Hyper-V
Cmdlet          Add-VMStoragePath                                  2.0.0.0    Hyper-V
Cmdlet          Add-VMSwitch                                       2.0.0.0    Hyper-V
Cmdlet          Add-VMSwitchExtensionPortFeature                   2.0.0.0    Hyper-V
Cmdlet          Add-VMSwitchExtensionSwitchFeature                 2.0.0.0    Hyper-V
Cmdlet          Add-VMSwitchTeamMember                             2.0.0.0    Hyper-V
Cmdlet          Add-WindowsCapability                              3.0        Dism
Cmdlet          Add-WindowsDriver                                  3.0        Dism
Cmdlet          Add-WindowsImage                                   3.0        Dism
Cmdlet          Add-WindowsPackage                                 3.0        Dism
Cmdlet          Checkpoint-Computer                                3.1.0.0    Microsoft.P...
Cmdlet          Checkpoint-VM                                      2.0.0.0    Hyper-V
Cmdlet          Clear-Content                                      3.1.0.0    Microsoft.P...
Cmdlet          Clear-EventLog                                     3.1.0.0    Microsoft.P...
Cmdlet          Clear-History                                      3.0.0.0    Microsoft.P...
Cmdlet          Clear-Item                                         3.1.0.0    Microsoft.P...
Cmdlet          Clear-ItemProperty                                 3.1.0.0    Microsoft.P...
Cmdlet          Clear-KdsCache                                     1.0.0.0    Kds
Cmdlet          Clear-Recyclebin                                   3.1.0.0    Microsoft.P...
Cmdlet          Clear-Tpm                                          2.0.0.0    TrustedPlat...
Cmdlet          Clear-UevAppxPackage                               2.1.639.0  UEV
Cmdlet          Clear-UevConfiguration                             2.1.639.0  UEV
Cmdlet          Clear-Variable                                     3.1.0.0    Microsoft.P...
Cmdlet          Clear-WindowsCorruptMountPoint                     3.0        Dism
Cmdlet          Compare-Object                                     3.1.0.0    Microsoft.P...
Cmdlet          Compare-VM                                         2.0.0.0    Hyper-V
Cmdlet          Complete-BitsTransfer                              2.0.0.0    BitsTransfer
Cmdlet          Complete-DtcDiagnosticTransaction                  1.0.0.0    MsDtc
Cmdlet          Complete-Transaction                               3.1.0.0    Microsoft.P...
Cmdlet          Complete-VMFailover                                2.0.0.0    Hyper-V
Cmdlet          Confirm-SecureBootUEFI                             2.0.0.0    SecureBoot
Cmdlet          Connect-PSSession                                  3.0.0.0    Microsoft.P...
Cmdlet          Connect-VMNetworkAdapter                           2.0.0.0    Hyper-V
Cmdlet          Connect-VMSan                                      2.0.0.0    Hyper-V
Cmdlet          Connect-WSMan                                      3.0.0.0    Microsoft.W...
Cmdlet          ConvertFrom-CIPolicy                               1.0        ConfigCI
Cmdlet          ConvertFrom-Csv                                    3.1.0.0    Microsoft.P...
Cmdlet          ConvertFrom-Json                                   3.1.0.0    Microsoft.P...
Cmdlet          ConvertFrom-SecureString                           3.0.0.0    Microsoft.P...
Cmdlet          ConvertFrom-String                                 3.1.0.0    Microsoft.P...
Cmdlet          ConvertFrom-StringData                             3.1.0.0    Microsoft.P...
Cmdlet          Convert-Path                                       3.1.0.0    Microsoft.P...
Cmdlet          Convert-String                                     3.1.0.0    Microsoft.P...
Cmdlet          ConvertTo-Csv                                      3.1.0.0    Microsoft.P...
Cmdlet          ConvertTo-Html                                     3.1.0.0    Microsoft.P...
Cmdlet          ConvertTo-Json                                     3.1.0.0    Microsoft.P...
Cmdlet          ConvertTo-ProcessMitigationPolicy                  1.0.11     ProcessMiti...
Cmdlet          ConvertTo-SecureString                             3.0.0.0    Microsoft.P...
Cmdlet          ConvertTo-TpmOwnerAuth                             2.0.0.0    TrustedPlat...
Cmdlet          ConvertTo-Xml                                      3.1.0.0    Microsoft.P...
Cmdlet          Convert-VHD                                        2.0.0.0    Hyper-V
Cmdlet          Copy-Item                                          3.1.0.0    Microsoft.P...
Cmdlet          Copy-ItemProperty                                  3.1.0.0    Microsoft.P...
Cmdlet          Copy-VMFile                                        2.0.0.0    Hyper-V
Cmdlet          Debug-Job                                          3.0.0.0    Microsoft.P...
Cmdlet          Debug-Process                                      3.1.0.0    Microsoft.P...
Cmdlet          Debug-Runspace                                     3.1.0.0    Microsoft.P...
Cmdlet          Debug-VM                                           2.0.0.0    Hyper-V
Cmdlet          Delete-DeliveryOptimizationCache                   1.0.2.0    DeliveryOpt...
Cmdlet          Disable-AppBackgroundTaskDiagnosticLog             1.0.0.0    AppBackgrou...
Cmdlet          Disable-Appv                                       1.0.0.0    AppvClient
Cmdlet          Disable-AppvClientConnectionGroup                  1.0.0.0    AppvClient
Cmdlet          Disable-ComputerRestore                            3.1.0.0    Microsoft.P...
Cmdlet          Disable-JobTrigger                                 1.1.0.0    PSScheduledJob
Cmdlet          Disable-LocalUser                                  1.0.0.0    Microsoft.P...
Cmdlet          Disable-PSBreakpoint                               3.1.0.0    Microsoft.P...
Cmdlet          Disable-PSRemoting                                 3.0.0.0    Microsoft.P...
Cmdlet          Disable-PSSessionConfiguration                     3.0.0.0    Microsoft.P...
Cmdlet          Disable-RunspaceDebug                              3.1.0.0    Microsoft.P...
Cmdlet          Disable-ScheduledJob                               1.1.0.0    PSScheduledJob
Cmdlet          Disable-TlsCipherSuite                             2.0.0.0    TLS
Cmdlet          Disable-TlsEccCurve                                2.0.0.0    TLS
Cmdlet          Disable-TlsSessionTicketKey                        2.0.0.0    TLS
Cmdlet          Disable-TpmAutoProvisioning                        2.0.0.0    TrustedPlat...
Cmdlet          Disable-Uev                                        2.1.639.0  UEV
Cmdlet          Disable-UevAppxPackage                             2.1.639.0  UEV
Cmdlet          Disable-UevTemplate                                2.1.639.0  UEV
Cmdlet          Disable-VMConsoleSupport                           2.0.0.0    Hyper-V
Cmdlet          Disable-VMEventing                                 2.0.0.0    Hyper-V
Cmdlet          Disable-VMIntegrationService                       2.0.0.0    Hyper-V
Cmdlet          Disable-VMMigration                                2.0.0.0    Hyper-V
Cmdlet          Disable-VMRemoteFXPhysicalVideoAdapter             2.0.0.0    Hyper-V
Cmdlet          Disable-VMResourceMetering                         2.0.0.0    Hyper-V
Cmdlet          Disable-VMSwitchExtension                          2.0.0.0    Hyper-V
Cmdlet          Disable-VMTPM                                      2.0.0.0    Hyper-V
Cmdlet          Disable-WindowsErrorReporting                      1.0        WindowsErro...
Cmdlet          Disable-WindowsOptionalFeature                     3.0        Dism
Cmdlet          Disable-WSManCredSSP                               3.0.0.0    Microsoft.W...
Cmdlet          Disconnect-PSSession                               3.0.0.0    Microsoft.P...
Cmdlet          Disconnect-VMNetworkAdapter                        2.0.0.0    Hyper-V
Cmdlet          Disconnect-VMSan                                   2.0.0.0    Hyper-V
Cmdlet          Disconnect-WSMan                                   3.0.0.0    Microsoft.W...
Cmdlet          Dismount-AppxVolume                                2.0.1.0    Appx
Cmdlet          Dismount-VHD                                       2.0.0.0    Hyper-V
Cmdlet          Dismount-VMHostAssignableDevice                    2.0.0.0    Hyper-V
Cmdlet          Dismount-WindowsImage                              3.0        Dism
Cmdlet          Edit-CIPolicyRule                                  1.0        ConfigCI
Cmdlet          Enable-AppBackgroundTaskDiagnosticLog              1.0.0.0    AppBackgrou...
Cmdlet          Enable-Appv                                        1.0.0.0    AppvClient
Cmdlet          Enable-AppvClientConnectionGroup                   1.0.0.0    AppvClient
Cmdlet          Enable-ComputerRestore                             3.1.0.0    Microsoft.P...
Cmdlet          Enable-JobTrigger                                  1.1.0.0    PSScheduledJob
Cmdlet          Enable-LocalUser                                   1.0.0.0    Microsoft.P...
Cmdlet          Enable-PSBreakpoint                                3.1.0.0    Microsoft.P...
Cmdlet          Enable-PSRemoting                                  3.0.0.0    Microsoft.P...
Cmdlet          Enable-PSSessionConfiguration                      3.0.0.0    Microsoft.P...
Cmdlet          Enable-RunspaceDebug                               3.1.0.0    Microsoft.P...
Cmdlet          Enable-ScheduledJob                                1.1.0.0    PSScheduledJob
Cmdlet          Enable-TlsCipherSuite                              2.0.0.0    TLS
Cmdlet          Enable-TlsEccCurve                                 2.0.0.0    TLS
Cmdlet          Enable-TlsSessionTicketKey                         2.0.0.0    TLS
Cmdlet          Enable-TpmAutoProvisioning                         2.0.0.0    TrustedPlat...
Cmdlet          Enable-Uev                                         2.1.639.0  UEV
Cmdlet          Enable-UevAppxPackage                              2.1.639.0  UEV
Cmdlet          Enable-UevTemplate                                 2.1.639.0  UEV
Cmdlet          Enable-VMConsoleSupport                            2.0.0.0    Hyper-V
Cmdlet          Enable-VMEventing                                  2.0.0.0    Hyper-V
Cmdlet          Enable-VMIntegrationService                        2.0.0.0    Hyper-V
Cmdlet          Enable-VMMigration                                 2.0.0.0    Hyper-V
Cmdlet          Enable-VMRemoteFXPhysicalVideoAdapter              2.0.0.0    Hyper-V
Cmdlet          Enable-VMReplication                               2.0.0.0    Hyper-V
Cmdlet          Enable-VMResourceMetering                          2.0.0.0    Hyper-V
Cmdlet          Enable-VMSwitchExtension                           2.0.0.0    Hyper-V
Cmdlet          Enable-VMTPM                                       2.0.0.0    Hyper-V
Cmdlet          Enable-WindowsErrorReporting                       1.0        WindowsErro...
Cmdlet          Enable-WindowsOptionalFeature                      3.0        Dism
Cmdlet          Enable-WSManCredSSP                                3.0.0.0    Microsoft.W...
Cmdlet          Enter-PSHostProcess                                3.0.0.0    Microsoft.P...
Cmdlet          Enter-PSSession                                    3.0.0.0    Microsoft.P...
Cmdlet          Exit-PSHostProcess                                 3.0.0.0    Microsoft.P...
Cmdlet          Exit-PSSession                                     3.0.0.0    Microsoft.P...
Cmdlet          Expand-WindowsCustomDataImage                      3.0        Dism
Cmdlet          Expand-WindowsImage                                3.0        Dism
Cmdlet          Export-Alias                                       3.1.0.0    Microsoft.P...
Cmdlet          Export-BinaryMiLog                                 1.0.0.0    CimCmdlets
Cmdlet          Export-Certificate                                 1.0.0.0    PKI
Cmdlet          Export-Clixml                                      3.1.0.0    Microsoft.P...
Cmdlet          Export-Console                                     3.0.0.0    Microsoft.P...
Cmdlet          Export-Counter                                     3.0.0.0    Microsoft.P...
Cmdlet          Export-Csv                                         3.1.0.0    Microsoft.P...
Cmdlet          Export-FormatData                                  3.1.0.0    Microsoft.P...
Cmdlet          Export-ModuleMember                                3.0.0.0    Microsoft.P...
Cmdlet          Export-PfxCertificate                              1.0.0.0    PKI
Cmdlet          Export-ProvisioningPackage                         3.0        Provisioning
Cmdlet          Export-PSSession                                   3.1.0.0    Microsoft.P...
Cmdlet          Export-StartLayout                                 1.0.0.0    StartLayout
Cmdlet          Export-StartLayoutEdgeAssets                       1.0.0.0    StartLayout
Cmdlet          Export-TlsSessionTicketKey                         2.0.0.0    TLS
Cmdlet          Export-Trace                                       3.0        Provisioning
Cmdlet          Export-UevConfiguration                            2.1.639.0  UEV
Cmdlet          Export-UevPackage                                  2.1.639.0  UEV
Cmdlet          Export-VM                                          2.0.0.0    Hyper-V
Cmdlet          Export-VMSnapshot                                  2.0.0.0    Hyper-V
Cmdlet          Export-WindowsCapabilitySource                     3.0        Dism
Cmdlet          Export-WindowsDriver                               3.0        Dism
Cmdlet          Export-WindowsImage                                3.0        Dism
Cmdlet          Find-Package                                       1.0.0.1    PackageMana...
Cmdlet          Find-PackageProvider                               1.0.0.1    PackageMana...
Cmdlet          ForEach-Object                                     3.0.0.0    Microsoft.P...
Cmdlet          Format-Custom                                      3.1.0.0    Microsoft.P...
Cmdlet          Format-List                                        3.1.0.0    Microsoft.P...
Cmdlet          Format-SecureBootUEFI                              2.0.0.0    SecureBoot
Cmdlet          Format-Table                                       3.1.0.0    Microsoft.P...
Cmdlet          Format-Wide                                        3.1.0.0    Microsoft.P...
Cmdlet          Get-Acl                                            3.0.0.0    Microsoft.P...
Cmdlet          Get-Alias                                          3.1.0.0    Microsoft.P...
Cmdlet          Get-AppLockerFileInformation                       2.0.0.0    AppLocker
Cmdlet          Get-AppLockerPolicy                                2.0.0.0    AppLocker
Cmdlet          Get-AppvClientApplication                          1.0.0.0    AppvClient
Cmdlet          Get-AppvClientConfiguration                        1.0.0.0    AppvClient
Cmdlet          Get-AppvClientConnectionGroup                      1.0.0.0    AppvClient
Cmdlet          Get-AppvClientMode                                 1.0.0.0    AppvClient
Cmdlet          Get-AppvClientPackage                              1.0.0.0    AppvClient
Cmdlet          Get-AppvPublishingServer                           1.0.0.0    AppvClient
Cmdlet          Get-AppvStatus                                     1.0.0.0    AppvClient
Cmdlet          Get-AppxDefaultVolume                              2.0.1.0    Appx
Cmdlet          Get-AppxPackage                                    2.0.1.0    Appx
Cmdlet          Get-AppxPackageManifest                            2.0.1.0    Appx
Cmdlet          Get-AppxProvisionedPackage                         3.0        Dism
Cmdlet          Get-AppxVolume                                     2.0.1.0    Appx
Cmdlet          Get-AuthenticodeSignature                          3.0.0.0    Microsoft.P...
Cmdlet          Get-BitsTransfer                                   2.0.0.0    BitsTransfer
Cmdlet          Get-Certificate                                    1.0.0.0    PKI
Cmdlet          Get-CertificateAutoEnrollmentPolicy                1.0.0.0    PKI
Cmdlet          Get-CertificateEnrollmentPolicyServer              1.0.0.0    PKI
Cmdlet          Get-CertificateNotificationTask                    1.0.0.0    PKI
Cmdlet          Get-ChildItem                                      3.1.0.0    Microsoft.P...
Cmdlet          Get-CimAssociatedInstance                          1.0.0.0    CimCmdlets
Cmdlet          Get-CimClass                                       1.0.0.0    CimCmdlets
Cmdlet          Get-CimInstance                                    1.0.0.0    CimCmdlets
Cmdlet          Get-CimSession                                     1.0.0.0    CimCmdlets
Cmdlet          Get-CIPolicy                                       1.0        ConfigCI
Cmdlet          Get-CIPolicyIdInfo                                 1.0        ConfigCI
Cmdlet          Get-CIPolicyInfo                                   1.0        ConfigCI
Cmdlet          Get-Clipboard                                      3.1.0.0    Microsoft.P...
Cmdlet          Get-CmsMessage                                     3.0.0.0    Microsoft.P...
Cmdlet          Get-Command                                        3.0.0.0    Microsoft.P...
Cmdlet          Get-ComputerInfo                                   3.1.0.0    Microsoft.P...
Cmdlet          Get-ComputerRestorePoint                           3.1.0.0    Microsoft.P...
Cmdlet          Get-Content                                        3.1.0.0    Microsoft.P...
Cmdlet          Get-ControlPanelItem                               3.1.0.0    Microsoft.P...
Cmdlet          Get-Counter                                        3.0.0.0    Microsoft.P...
Cmdlet          Get-Credential                                     3.0.0.0    Microsoft.P...
Cmdlet          Get-Culture                                        3.1.0.0    Microsoft.P...
Cmdlet          Get-DAPolicyChange                                 2.0.0.0    NetSecurity
Cmdlet          Get-Date                                           3.1.0.0    Microsoft.P...
Cmdlet          Get-DeliveryOptimizationLog                        1.0.2.0    DeliveryOpt...
Cmdlet          Get-DeliveryOptimizationPerfSnap                   1.0.2.0    DeliveryOpt...
Cmdlet          Get-DeliveryOptimizationPerfSnapThisMonth          1.0.2.0    DeliveryOpt...
Cmdlet          Get-DeliveryOptimizationStatus                     1.0.2.0    DeliveryOpt...
Cmdlet          Get-DOConfig                                       1.0.2.0    DeliveryOpt...
Cmdlet          Get-DODownloadMode                                 1.0.2.0    DeliveryOpt...
Cmdlet          Get-DOPercentageMaxBackgroundBandwidth             1.0.2.0    DeliveryOpt...
Cmdlet          Get-DOPercentageMaxForegroundBandwidth             1.0.2.0    DeliveryOpt...
Cmdlet          Get-Event                                          3.1.0.0    Microsoft.P...
Cmdlet          Get-EventLog                                       3.1.0.0    Microsoft.P...
Cmdlet          Get-EventSubscriber                                3.1.0.0    Microsoft.P...
Cmdlet          Get-ExecutionPolicy                                3.0.0.0    Microsoft.P...
Cmdlet          Get-FormatData                                     3.1.0.0    Microsoft.P...
Cmdlet          Get-Help                                           3.0.0.0    Microsoft.P...
Cmdlet          Get-HgsAttestationBaselinePolicy                   1.0.0.0    HgsClient
Cmdlet          Get-HgsTrace                                       1.0.0.0    HgsDiagnostics
Cmdlet          Get-HgsTraceFileData                               1.0.0.0    HgsDiagnostics
Cmdlet          Get-History                                        3.0.0.0    Microsoft.P...
Cmdlet          Get-Host                                           3.1.0.0    Microsoft.P...
Cmdlet          Get-HotFix                                         3.1.0.0    Microsoft.P...
Cmdlet          Get-Item                                           3.1.0.0    Microsoft.P...
Cmdlet          Get-ItemProperty                                   3.1.0.0    Microsoft.P...
Cmdlet          Get-ItemPropertyValue                              3.1.0.0    Microsoft.P...
Cmdlet          Get-Job                                            3.0.0.0    Microsoft.P...
Cmdlet          Get-JobTrigger                                     1.1.0.0    PSScheduledJob
Cmdlet          Get-KdsConfiguration                               1.0.0.0    Kds
Cmdlet          Get-KdsRootKey                                     1.0.0.0    Kds
Cmdlet          Get-LocalGroup                                     1.0.0.0    Microsoft.P...
Cmdlet          Get-LocalGroupMember                               1.0.0.0    Microsoft.P...
Cmdlet          Get-LocalUser                                      1.0.0.0    Microsoft.P...
Cmdlet          Get-Location                                       3.1.0.0    Microsoft.P...
Cmdlet          Get-Member                                         3.1.0.0    Microsoft.P...
Cmdlet          Get-Module                                         3.0.0.0    Microsoft.P...
Cmdlet          Get-NonRemovableAppsPolicy                         3.0        Dism
Cmdlet          Get-Package                                        1.0.0.1    PackageMana...
Cmdlet          Get-PackageProvider                                1.0.0.1    PackageMana...
Cmdlet          Get-PackageSource                                  1.0.0.1    PackageMana...
Cmdlet          Get-PfxCertificate                                 3.0.0.0    Microsoft.P...
Cmdlet          Get-PfxData                                        1.0.0.0    PKI
Cmdlet          Get-PmemDisk                                       1.0.0.0    PersistentM...
Cmdlet          Get-PmemPhysicalDevice                             1.0.0.0    PersistentM...
Cmdlet          Get-PmemUnusedRegion                               1.0.0.0    PersistentM...
Cmdlet          Get-Process                                        3.1.0.0    Microsoft.P...
Cmdlet          Get-ProcessMitigation                              1.0.11     ProcessMiti...
Cmdlet          Get-ProvisioningPackage                            3.0        Provisioning
Cmdlet          Get-PSBreakpoint                                   3.1.0.0    Microsoft.P...
Cmdlet          Get-PSCallStack                                    3.1.0.0    Microsoft.P...
Cmdlet          Get-PSDrive                                        3.1.0.0    Microsoft.P...
Cmdlet          Get-PSHostProcessInfo                              3.0.0.0    Microsoft.P...
Cmdlet          Get-PSProvider                                     3.1.0.0    Microsoft.P...
Cmdlet          Get-PSReadLineKeyHandler                           2.0.0      PSReadline
Cmdlet          Get-PSReadLineOption                               2.0.0      PSReadline
Cmdlet          Get-PSSession                                      3.0.0.0    Microsoft.P...
Cmdlet          Get-PSSessionCapability                            3.0.0.0    Microsoft.P...
Cmdlet          Get-PSSessionConfiguration                         3.0.0.0    Microsoft.P...
Cmdlet          Get-PSSnapin                                       3.0.0.0    Microsoft.P...
Cmdlet          Get-Random                                         3.1.0.0    Microsoft.P...
Cmdlet          Get-Runspace                                       3.1.0.0    Microsoft.P...
Cmdlet          Get-RunspaceDebug                                  3.1.0.0    Microsoft.P...
Cmdlet          Get-ScheduledJob                                   1.1.0.0    PSScheduledJob
Cmdlet          Get-ScheduledJobOption                             1.1.0.0    PSScheduledJob
Cmdlet          Get-SecureBootPolicy                               2.0.0.0    SecureBoot
Cmdlet          Get-SecureBootUEFI                                 2.0.0.0    SecureBoot
Cmdlet          Get-Service                                        3.1.0.0    Microsoft.P...
Cmdlet          Get-SystemDriver                                   1.0        ConfigCI
Cmdlet          Get-TimeZone                                       3.1.0.0    Microsoft.P...
Cmdlet          Get-TlsCipherSuite                                 2.0.0.0    TLS
Cmdlet          Get-TlsEccCurve                                    2.0.0.0    TLS
Cmdlet          Get-Tpm                                            2.0.0.0    TrustedPlat...
Cmdlet          Get-TpmEndorsementKeyInfo                          2.0.0.0    TrustedPlat...
Cmdlet          Get-TpmSupportedFeature                            2.0.0.0    TrustedPlat...
Cmdlet          Get-TraceSource                                    3.1.0.0    Microsoft.P...
Cmdlet          Get-Transaction                                    3.1.0.0    Microsoft.P...
Cmdlet          Get-TroubleshootingPack                            1.0.0.0    Troubleshoo...
Cmdlet          Get-TrustedProvisioningCertificate                 3.0        Provisioning
Cmdlet          Get-TypeData                                       3.1.0.0    Microsoft.P...
Cmdlet          Get-UevAppxPackage                                 2.1.639.0  UEV
Cmdlet          Get-UevConfiguration                               2.1.639.0  UEV
Cmdlet          Get-UevStatus                                      2.1.639.0  UEV
Cmdlet          Get-UevTemplate                                    2.1.639.0  UEV
Cmdlet          Get-UevTemplateProgram                             2.1.639.0  UEV
Cmdlet          Get-UICulture                                      3.1.0.0    Microsoft.P...
Cmdlet          Get-Unique                                         3.1.0.0    Microsoft.P...
Cmdlet          Get-Variable                                       3.1.0.0    Microsoft.P...
Cmdlet          Get-VHD                                            2.0.0.0    Hyper-V
Cmdlet          Get-VHDSet                                         2.0.0.0    Hyper-V
Cmdlet          Get-VHDSnapshot                                    2.0.0.0    Hyper-V
Cmdlet          Get-VM                                             2.0.0.0    Hyper-V
Cmdlet          Get-VMAssignableDevice                             2.0.0.0    Hyper-V
Cmdlet          Get-VMBios                                         2.0.0.0    Hyper-V
Cmdlet          Get-VMComPort                                      2.0.0.0    Hyper-V
Cmdlet          Get-VMConnectAccess                                2.0.0.0    Hyper-V
Cmdlet          Get-VMDvdDrive                                     2.0.0.0    Hyper-V
Cmdlet          Get-VMFibreChannelHba                              2.0.0.0    Hyper-V
Cmdlet          Get-VMFirmware                                     2.0.0.0    Hyper-V
Cmdlet          Get-VMFloppyDiskDrive                              2.0.0.0    Hyper-V
Cmdlet          Get-VMGpuPartitionAdapter                          2.0.0.0    Hyper-V
Cmdlet          Get-VMGroup                                        2.0.0.0    Hyper-V
Cmdlet          Get-VMHardDiskDrive                                2.0.0.0    Hyper-V
Cmdlet          Get-VMHost                                         2.0.0.0    Hyper-V
Cmdlet          Get-VMHostAssignableDevice                         2.0.0.0    Hyper-V
Cmdlet          Get-VMHostCluster                                  2.0.0.0    Hyper-V
Cmdlet          Get-VMHostNumaNode                                 2.0.0.0    Hyper-V
Cmdlet          Get-VMHostNumaNodeStatus                           2.0.0.0    Hyper-V
Cmdlet          Get-VMHostSupportedVersion                         2.0.0.0    Hyper-V
Cmdlet          Get-VMIdeController                                2.0.0.0    Hyper-V
Cmdlet          Get-VMIntegrationService                           2.0.0.0    Hyper-V
Cmdlet          Get-VMKeyProtector                                 2.0.0.0    Hyper-V
Cmdlet          Get-VMKeyStorageDrive                              2.0.0.0    Hyper-V
Cmdlet          Get-VMMemory                                       2.0.0.0    Hyper-V
Cmdlet          Get-VMMigrationNetwork                             2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapter                               2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterAcl                            2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterExtendedAcl                    2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterFailoverConfiguration          2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterIsolation                      2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterRdma                           2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterRoutingDomainMapping           2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterTeamMapping                    2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterVlan                           2.0.0.0    Hyper-V
Cmdlet          Get-VMPartitionableGpu                             2.0.0.0    Hyper-V
Cmdlet          Get-VMPmemController                               2.0.0.0    Hyper-V
Cmdlet          Get-VMProcessor                                    2.0.0.0    Hyper-V
Cmdlet          Get-VMRemoteFx3dVideoAdapter                       2.0.0.0    Hyper-V
Cmdlet          Get-VMRemoteFXPhysicalVideoAdapter                 2.0.0.0    Hyper-V
Cmdlet          Get-VMReplication                                  2.0.0.0    Hyper-V
Cmdlet          Get-VMReplicationAuthorizationEntry                2.0.0.0    Hyper-V
Cmdlet          Get-VMReplicationServer                            2.0.0.0    Hyper-V
Cmdlet          Get-VMResourcePool                                 2.0.0.0    Hyper-V
Cmdlet          Get-VMSan                                          2.0.0.0    Hyper-V
Cmdlet          Get-VMScsiController                               2.0.0.0    Hyper-V
Cmdlet          Get-VMSecurity                                     2.0.0.0    Hyper-V
Cmdlet          Get-VMSnapshot                                     2.0.0.0    Hyper-V
Cmdlet          Get-VMStoragePath                                  2.0.0.0    Hyper-V
Cmdlet          Get-VMStorageSettings                              2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitch                                       2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitchExtension                              2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitchExtensionPortData                      2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitchExtensionPortFeature                   2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitchExtensionSwitchData                    2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitchExtensionSwitchFeature                 2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitchTeam                                   2.0.0.0    Hyper-V
Cmdlet          Get-VMSystemSwitchExtension                        2.0.0.0    Hyper-V
Cmdlet          Get-VMSystemSwitchExtensionPortFeature             2.0.0.0    Hyper-V
Cmdlet          Get-VMSystemSwitchExtensionSwitchFeature           2.0.0.0    Hyper-V
Cmdlet          Get-VMVideo                                        2.0.0.0    Hyper-V
Cmdlet          Get-WheaMemoryPolicy                               2.0.0.0    Whea
Cmdlet          Get-WIMBootEntry                                   3.0        Dism
Cmdlet          Get-WinAcceptLanguageFromLanguageListOptOut        2.0.0.0    International
Cmdlet          Get-WinCultureFromLanguageListOptOut               2.0.0.0    International
Cmdlet          Get-WinDefaultInputMethodOverride                  2.0.0.0    International
Cmdlet          Get-WindowsCapability                              3.0        Dism
Cmdlet          Get-WindowsDeveloperLicense                        1.0.0.0    WindowsDeve...
Cmdlet          Get-WindowsDriver                                  3.0        Dism
Cmdlet          Get-WindowsEdition                                 3.0        Dism
Cmdlet          Get-WindowsErrorReporting                          1.0        WindowsErro...
Cmdlet          Get-WindowsImage                                   3.0        Dism
Cmdlet          Get-WindowsImageContent                            3.0        Dism
Cmdlet          Get-WindowsOptionalFeature                         3.0        Dism
Cmdlet          Get-WindowsPackage                                 3.0        Dism
Cmdlet          Get-WindowsSearchSetting                           1.0.0.0    WindowsSearch
Cmdlet          Get-WinEvent                                       3.0.0.0    Microsoft.P...
Cmdlet          Get-WinHomeLocation                                2.0.0.0    International
Cmdlet          Get-WinLanguageBarOption                           2.0.0.0    International
Cmdlet          Get-WinSystemLocale                                2.0.0.0    International
Cmdlet          Get-WinUILanguageOverride                          2.0.0.0    International
Cmdlet          Get-WinUserLanguageList                            2.0.0.0    International
Cmdlet          Get-WmiObject                                      3.1.0.0    Microsoft.P...
Cmdlet          Get-WSManCredSSP                                   3.0.0.0    Microsoft.W...
Cmdlet          Get-WSManInstance                                  3.0.0.0    Microsoft.W...
Cmdlet          Grant-VMConnectAccess                              2.0.0.0    Hyper-V
Cmdlet          Group-Object                                       3.1.0.0    Microsoft.P...
Cmdlet          Import-Alias                                       3.1.0.0    Microsoft.P...
Cmdlet          Import-BinaryMiLog                                 1.0.0.0    CimCmdlets
Cmdlet          Import-Certificate                                 1.0.0.0    PKI
Cmdlet          Import-Clixml                                      3.1.0.0    Microsoft.P...
Cmdlet          Import-Counter                                     3.0.0.0    Microsoft.P...
Cmdlet          Import-Csv                                         3.1.0.0    Microsoft.P...
Cmdlet          Import-LocalizedData                               3.1.0.0    Microsoft.P...
Cmdlet          Import-Module                                      3.0.0.0    Microsoft.P...
Cmdlet          Import-PackageProvider                             1.0.0.1    PackageMana...
Cmdlet          Import-PfxCertificate                              1.0.0.0    PKI
Cmdlet          Import-PSSession                                   3.1.0.0    Microsoft.P...
Cmdlet          Import-StartLayout                                 1.0.0.0    StartLayout
Cmdlet          Import-TpmOwnerAuth                                2.0.0.0    TrustedPlat...
Cmdlet          Import-UevConfiguration                            2.1.639.0  UEV
Cmdlet          Import-VM                                          2.0.0.0    Hyper-V
Cmdlet          Import-VMInitialReplication                        2.0.0.0    Hyper-V
Cmdlet          Initialize-PmemPhysicalDevice                      1.0.0.0    PersistentM...
Cmdlet          Initialize-Tpm                                     2.0.0.0    TrustedPlat...
Cmdlet          Install-Package                                    1.0.0.1    PackageMana...
Cmdlet          Install-PackageProvider                            1.0.0.1    PackageMana...
Cmdlet          Install-ProvisioningPackage                        3.0        Provisioning
Cmdlet          Install-TrustedProvisioningCertificate             3.0        Provisioning
Cmdlet          Invoke-CimMethod                                   1.0.0.0    CimCmdlets
Cmdlet          Invoke-Command                                     3.0.0.0    Microsoft.P...
Cmdlet          Invoke-CommandInDesktopPackage                     2.0.1.0    Appx
Cmdlet          Invoke-DscResource                                 1.1        PSDesiredSt...
Cmdlet          Invoke-Expression                                  3.1.0.0    Microsoft.P...
Cmdlet          Invoke-History                                     3.0.0.0    Microsoft.P...
Cmdlet          Invoke-Item                                        3.1.0.0    Microsoft.P...
Cmdlet          Invoke-RestMethod                                  3.1.0.0    Microsoft.P...
Cmdlet          Invoke-TroubleshootingPack                         1.0.0.0    Troubleshoo...
Cmdlet          Invoke-WebRequest                                  3.1.0.0    Microsoft.P...
Cmdlet          Invoke-WmiMethod                                   3.1.0.0    Microsoft.P...
Cmdlet          Invoke-WSManAction                                 3.0.0.0    Microsoft.W...
Cmdlet          Join-DtcDiagnosticResourceManager                  1.0.0.0    MsDtc
Cmdlet          Join-Path                                          3.1.0.0    Microsoft.P...
Cmdlet          Limit-EventLog                                     3.1.0.0    Microsoft.P...
Cmdlet          Measure-Command                                    3.1.0.0    Microsoft.P...
Cmdlet          Measure-Object                                     3.1.0.0    Microsoft.P...
Cmdlet          Measure-VM                                         2.0.0.0    Hyper-V
Cmdlet          Measure-VMReplication                              2.0.0.0    Hyper-V
Cmdlet          Measure-VMResourcePool                             2.0.0.0    Hyper-V
Cmdlet          Merge-CIPolicy                                     1.0        ConfigCI
Cmdlet          Merge-VHD                                          2.0.0.0    Hyper-V
Cmdlet          Mount-AppvClientConnectionGroup                    1.0.0.0    AppvClient
Cmdlet          Mount-AppvClientPackage                            1.0.0.0    AppvClient
Cmdlet          Mount-AppxVolume                                   2.0.1.0    Appx
Cmdlet          Mount-VHD                                          2.0.0.0    Hyper-V
Cmdlet          Mount-VMHostAssignableDevice                       2.0.0.0    Hyper-V
Cmdlet          Mount-WindowsImage                                 3.0        Dism
Cmdlet          Move-AppxPackage                                   2.0.1.0    Appx
Cmdlet          Move-Item                                          3.1.0.0    Microsoft.P...
Cmdlet          Move-ItemProperty                                  3.1.0.0    Microsoft.P...
Cmdlet          Move-VM                                            2.0.0.0    Hyper-V
Cmdlet          Move-VMStorage                                     2.0.0.0    Hyper-V
Cmdlet          New-Alias                                          3.1.0.0    Microsoft.P...
Cmdlet          New-AppLockerPolicy                                2.0.0.0    AppLocker
Cmdlet          New-CertificateNotificationTask                    1.0.0.0    PKI
Cmdlet          New-CimInstance                                    1.0.0.0    CimCmdlets
Cmdlet          New-CimSession                                     1.0.0.0    CimCmdlets
Cmdlet          New-CimSessionOption                               1.0.0.0    CimCmdlets
Cmdlet          New-CIPolicy                                       1.0        ConfigCI
Cmdlet          New-CIPolicyRule                                   1.0        ConfigCI
Cmdlet          New-DtcDiagnosticTransaction                       1.0.0.0    MsDtc
Cmdlet          New-Event                                          3.1.0.0    Microsoft.P...
Cmdlet          New-EventLog                                       3.1.0.0    Microsoft.P...
Cmdlet          New-FileCatalog                                    3.0.0.0    Microsoft.P...
Cmdlet          New-HgsTraceTarget                                 1.0.0.0    HgsDiagnostics
Cmdlet          New-Item                                           3.1.0.0    Microsoft.P...
Cmdlet          New-ItemProperty                                   3.1.0.0    Microsoft.P...
Cmdlet          New-JobTrigger                                     1.1.0.0    PSScheduledJob
Cmdlet          New-LocalGroup                                     1.0.0.0    Microsoft.P...
Cmdlet          New-LocalUser                                      1.0.0.0    Microsoft.P...
Cmdlet          New-Module                                         3.0.0.0    Microsoft.P...
Cmdlet          New-ModuleManifest                                 3.0.0.0    Microsoft.P...
Cmdlet          New-NetIPsecAuthProposal                           2.0.0.0    NetSecurity
Cmdlet          New-NetIPsecMainModeCryptoProposal                 2.0.0.0    NetSecurity
Cmdlet          New-NetIPsecQuickModeCryptoProposal                2.0.0.0    NetSecurity
Cmdlet          New-Object                                         3.1.0.0    Microsoft.P...
Cmdlet          New-PmemDisk                                       1.0.0.0    PersistentM...
Cmdlet          New-ProvisioningRepro                              3.0        Provisioning
Cmdlet          New-PSDrive                                        3.1.0.0    Microsoft.P...
Cmdlet          New-PSRoleCapabilityFile                           3.0.0.0    Microsoft.P...
Cmdlet          New-PSSession                                      3.0.0.0    Microsoft.P...
Cmdlet          New-PSSessionConfigurationFile                     3.0.0.0    Microsoft.P...
Cmdlet          New-PSSessionOption                                3.0.0.0    Microsoft.P...
Cmdlet          New-PSTransportOption                              3.0.0.0    Microsoft.P...
Cmdlet          New-PSWorkflowExecutionOption                      2.0.0.0    PSWorkflow
Cmdlet          New-ScheduledJobOption                             1.1.0.0    PSScheduledJob
Cmdlet          New-SelfSignedCertificate                          1.0.0.0    PKI
Cmdlet          New-Service                                        3.1.0.0    Microsoft.P...
Cmdlet          New-TimeSpan                                       3.1.0.0    Microsoft.P...
Cmdlet          New-TlsSessionTicketKey                            2.0.0.0    TLS
Cmdlet          New-Variable                                       3.1.0.0    Microsoft.P...
Cmdlet          New-VFD                                            2.0.0.0    Hyper-V
Cmdlet          New-VHD                                            2.0.0.0    Hyper-V
Cmdlet          New-VM                                             2.0.0.0    Hyper-V
Cmdlet          New-VMGroup                                        2.0.0.0    Hyper-V
Cmdlet          New-VMReplicationAuthorizationEntry                2.0.0.0    Hyper-V
Cmdlet          New-VMResourcePool                                 2.0.0.0    Hyper-V
Cmdlet          New-VMSan                                          2.0.0.0    Hyper-V
Cmdlet          New-VMSwitch                                       2.0.0.0    Hyper-V
Cmdlet          New-WebServiceProxy                                3.1.0.0    Microsoft.P...
Cmdlet          New-WindowsCustomImage                             3.0        Dism
Cmdlet          New-WindowsImage                                   3.0        Dism
Cmdlet          New-WinEvent                                       3.0.0.0    Microsoft.P...
Cmdlet          New-WinUserLanguageList                            2.0.0.0    International
Cmdlet          New-WSManInstance                                  3.0.0.0    Microsoft.W...
Cmdlet          New-WSManSessionOption                             3.0.0.0    Microsoft.W...
Cmdlet          Optimize-AppxProvisionedPackages                   3.0        Dism
Cmdlet          Optimize-VHD                                       2.0.0.0    Hyper-V
Cmdlet          Optimize-VHDSet                                    2.0.0.0    Hyper-V
Cmdlet          Optimize-WindowsImage                              3.0        Dism
Cmdlet          Out-Default                                        3.0.0.0    Microsoft.P...
Cmdlet          Out-File                                           3.1.0.0    Microsoft.P...
Cmdlet          Out-GridView                                       3.1.0.0    Microsoft.P...
Cmdlet          Out-Host                                           3.0.0.0    Microsoft.P...
Cmdlet          Out-Null                                           3.0.0.0    Microsoft.P...
Cmdlet          Out-Printer                                        3.1.0.0    Microsoft.P...
Cmdlet          Out-String                                         3.1.0.0    Microsoft.P...
Cmdlet          Pop-Location                                       3.1.0.0    Microsoft.P...
Cmdlet          Protect-CmsMessage                                 3.0.0.0    Microsoft.P...
Cmdlet          Publish-AppvClientPackage                          1.0.0.0    AppvClient
Cmdlet          Publish-DscConfiguration                           1.1        PSDesiredSt...
Cmdlet          Push-Location                                      3.1.0.0    Microsoft.P...
Cmdlet          Read-Host                                          3.1.0.0    Microsoft.P...
Cmdlet          Receive-DtcDiagnosticTransaction                   1.0.0.0    MsDtc
Cmdlet          Receive-Job                                        3.0.0.0    Microsoft.P...
Cmdlet          Receive-PSSession                                  3.0.0.0    Microsoft.P...
Cmdlet          Register-ArgumentCompleter                         3.0.0.0    Microsoft.P...
Cmdlet          Register-CimIndicationEvent                        1.0.0.0    CimCmdlets
Cmdlet          Register-EngineEvent                               3.1.0.0    Microsoft.P...
Cmdlet          Register-ObjectEvent                               3.1.0.0    Microsoft.P...
Cmdlet          Register-PackageSource                             1.0.0.1    PackageMana...
Cmdlet          Register-PSSessionConfiguration                    3.0.0.0    Microsoft.P...
Cmdlet          Register-ScheduledJob                              1.1.0.0    PSScheduledJob
Cmdlet          Register-UevTemplate                               2.1.639.0  UEV
Cmdlet          Register-WmiEvent                                  3.1.0.0    Microsoft.P...
Cmdlet          Remove-AppvClientConnectionGroup                   1.0.0.0    AppvClient
Cmdlet          Remove-AppvClientPackage                           1.0.0.0    AppvClient
Cmdlet          Remove-AppvPublishingServer                        1.0.0.0    AppvClient
Cmdlet          Remove-AppxPackage                                 2.0.1.0    Appx
Cmdlet          Remove-AppxProvisionedPackage                      3.0        Dism
Cmdlet          Remove-AppxVolume                                  2.0.1.0    Appx
Cmdlet          Remove-BitsTransfer                                2.0.0.0    BitsTransfer
Cmdlet          Remove-CertificateEnrollmentPolicyServer           1.0.0.0    PKI
Cmdlet          Remove-CertificateNotificationTask                 1.0.0.0    PKI
Cmdlet          Remove-CimInstance                                 1.0.0.0    CimCmdlets
Cmdlet          Remove-CimSession                                  1.0.0.0    CimCmdlets
Cmdlet          Remove-CIPolicyRule                                1.0        ConfigCI
Cmdlet          Remove-Computer                                    3.1.0.0    Microsoft.P...
Cmdlet          Remove-Event                                       3.1.0.0    Microsoft.P...
Cmdlet          Remove-EventLog                                    3.1.0.0    Microsoft.P...
Cmdlet          Remove-Item                                        3.1.0.0    Microsoft.P...
Cmdlet          Remove-ItemProperty                                3.1.0.0    Microsoft.P...
Cmdlet          Remove-Job                                         3.0.0.0    Microsoft.P...
Cmdlet          Remove-JobTrigger                                  1.1.0.0    PSScheduledJob
Cmdlet          Remove-LocalGroup                                  1.0.0.0    Microsoft.P...
Cmdlet          Remove-LocalGroupMember                            1.0.0.0    Microsoft.P...
Cmdlet          Remove-LocalUser                                   1.0.0.0    Microsoft.P...
Cmdlet          Remove-Module                                      3.0.0.0    Microsoft.P...
Cmdlet          Remove-PmemDisk                                    1.0.0.0    PersistentM...
Cmdlet          Remove-PSBreakpoint                                3.1.0.0    Microsoft.P...
Cmdlet          Remove-PSDrive                                     3.1.0.0    Microsoft.P...
Cmdlet          Remove-PSReadLineKeyHandler                        2.0.0      PSReadline
Cmdlet          Remove-PSSession                                   3.0.0.0    Microsoft.P...
Cmdlet          Remove-PSSnapin                                    3.0.0.0    Microsoft.P...
Cmdlet          Remove-TypeData                                    3.1.0.0    Microsoft.P...
Cmdlet          Remove-Variable                                    3.1.0.0    Microsoft.P...
Cmdlet          Remove-VHDSnapshot                                 2.0.0.0    Hyper-V
Cmdlet          Remove-VM                                          2.0.0.0    Hyper-V
Cmdlet          Remove-VMAssignableDevice                          2.0.0.0    Hyper-V
Cmdlet          Remove-VMDvdDrive                                  2.0.0.0    Hyper-V
Cmdlet          Remove-VMFibreChannelHba                           2.0.0.0    Hyper-V
Cmdlet          Remove-VMGpuPartitionAdapter                       2.0.0.0    Hyper-V
Cmdlet          Remove-VMGroup                                     2.0.0.0    Hyper-V
Cmdlet          Remove-VMGroupMember                               2.0.0.0    Hyper-V
Cmdlet          Remove-VMHardDiskDrive                             2.0.0.0    Hyper-V
Cmdlet          Remove-VMHostAssignableDevice                      2.0.0.0    Hyper-V
Cmdlet          Remove-VMKeyStorageDrive                           2.0.0.0    Hyper-V
Cmdlet          Remove-VMMigrationNetwork                          2.0.0.0    Hyper-V
Cmdlet          Remove-VMNetworkAdapter                            2.0.0.0    Hyper-V
Cmdlet          Remove-VMNetworkAdapterAcl                         2.0.0.0    Hyper-V
Cmdlet          Remove-VMNetworkAdapterExtendedAcl                 2.0.0.0    Hyper-V
Cmdlet          Remove-VMNetworkAdapterRoutingDomainMapping        2.0.0.0    Hyper-V
Cmdlet          Remove-VMNetworkAdapterTeamMapping                 2.0.0.0    Hyper-V
Cmdlet          Remove-VMPmemController                            2.0.0.0    Hyper-V
Cmdlet          Remove-VMRemoteFx3dVideoAdapter                    2.0.0.0    Hyper-V
Cmdlet          Remove-VMReplication                               2.0.0.0    Hyper-V
Cmdlet          Remove-VMReplicationAuthorizationEntry             2.0.0.0    Hyper-V
Cmdlet          Remove-VMResourcePool                              2.0.0.0    Hyper-V
Cmdlet          Remove-VMSan                                       2.0.0.0    Hyper-V
Cmdlet          Remove-VMSavedState                                2.0.0.0    Hyper-V
Cmdlet          Remove-VMScsiController                            2.0.0.0    Hyper-V
Cmdlet          Remove-VMSnapshot                                  2.0.0.0    Hyper-V
Cmdlet          Remove-VMStoragePath                               2.0.0.0    Hyper-V
Cmdlet          Remove-VMSwitch                                    2.0.0.0    Hyper-V
Cmdlet          Remove-VMSwitchExtensionPortFeature                2.0.0.0    Hyper-V
Cmdlet          Remove-VMSwitchExtensionSwitchFeature              2.0.0.0    Hyper-V
Cmdlet          Remove-VMSwitchTeamMember                          2.0.0.0    Hyper-V
Cmdlet          Remove-WindowsCapability                           3.0        Dism
Cmdlet          Remove-WindowsDriver                               3.0        Dism
Cmdlet          Remove-WindowsImage                                3.0        Dism
Cmdlet          Remove-WindowsPackage                              3.0        Dism
Cmdlet          Remove-WmiObject                                   3.1.0.0    Microsoft.P...
Cmdlet          Remove-WSManInstance                               3.0.0.0    Microsoft.W...
Cmdlet          Rename-Computer                                    3.1.0.0    Microsoft.P...
Cmdlet          Rename-Item                                        3.1.0.0    Microsoft.P...
Cmdlet          Rename-ItemProperty                                3.1.0.0    Microsoft.P...
Cmdlet          Rename-LocalGroup                                  1.0.0.0    Microsoft.P...
Cmdlet          Rename-LocalUser                                   1.0.0.0    Microsoft.P...
Cmdlet          Rename-VM                                          2.0.0.0    Hyper-V
Cmdlet          Rename-VMGroup                                     2.0.0.0    Hyper-V
Cmdlet          Rename-VMNetworkAdapter                            2.0.0.0    Hyper-V
Cmdlet          Rename-VMResourcePool                              2.0.0.0    Hyper-V
Cmdlet          Rename-VMSan                                       2.0.0.0    Hyper-V
Cmdlet          Rename-VMSnapshot                                  2.0.0.0    Hyper-V
Cmdlet          Rename-VMSwitch                                    2.0.0.0    Hyper-V
Cmdlet          Repair-AppvClientConnectionGroup                   1.0.0.0    AppvClient
Cmdlet          Repair-AppvClientPackage                           1.0.0.0    AppvClient
Cmdlet          Repair-UevTemplateIndex                            2.1.639.0  UEV
Cmdlet          Repair-VM                                          2.0.0.0    Hyper-V
Cmdlet          Repair-WindowsImage                                3.0        Dism
Cmdlet          Reset-ComputerMachinePassword                      3.1.0.0    Microsoft.P...
Cmdlet          Reset-VMReplicationStatistics                      2.0.0.0    Hyper-V
Cmdlet          Reset-VMResourceMetering                           2.0.0.0    Hyper-V
Cmdlet          Resize-VHD                                         2.0.0.0    Hyper-V
Cmdlet          Resolve-DnsName                                    1.0.0.0    DnsClient
Cmdlet          Resolve-Path                                       3.1.0.0    Microsoft.P...
Cmdlet          Restart-Computer                                   3.1.0.0    Microsoft.P...
Cmdlet          Restart-Service                                    3.1.0.0    Microsoft.P...
Cmdlet          Restart-VM                                         2.0.0.0    Hyper-V
Cmdlet          Restore-Computer                                   3.1.0.0    Microsoft.P...
Cmdlet          Restore-UevBackup                                  2.1.639.0  UEV
Cmdlet          Restore-UevUserSetting                             2.1.639.0  UEV
Cmdlet          Restore-VMSnapshot                                 2.0.0.0    Hyper-V
Cmdlet          Resume-BitsTransfer                                2.0.0.0    BitsTransfer
Cmdlet          Resume-Job                                         3.0.0.0    Microsoft.P...
Cmdlet          Resume-ProvisioningSession                         3.0        Provisioning
Cmdlet          Resume-Service                                     3.1.0.0    Microsoft.P...
Cmdlet          Resume-VM                                          2.0.0.0    Hyper-V
Cmdlet          Resume-VMReplication                               2.0.0.0    Hyper-V
Cmdlet          Revoke-VMConnectAccess                             2.0.0.0    Hyper-V
Cmdlet          Save-Help                                          3.0.0.0    Microsoft.P...
Cmdlet          Save-Package                                       1.0.0.1    PackageMana...
Cmdlet          Save-VM                                            2.0.0.0    Hyper-V
Cmdlet          Save-WindowsImage                                  3.0        Dism
Cmdlet          Select-Object                                      3.1.0.0    Microsoft.P...
Cmdlet          Select-String                                      3.1.0.0    Microsoft.P...
Cmdlet          Select-Xml                                         3.1.0.0    Microsoft.P...
Cmdlet          Send-AppvClientReport                              1.0.0.0    AppvClient
Cmdlet          Send-DtcDiagnosticTransaction                      1.0.0.0    MsDtc
Cmdlet          Send-MailMessage                                   3.1.0.0    Microsoft.P...
Cmdlet          Set-Acl                                            3.0.0.0    Microsoft.P...
Cmdlet          Set-Alias                                          3.1.0.0    Microsoft.P...
Cmdlet          Set-AppBackgroundTaskResourcePolicy                1.0.0.0    AppBackgrou...
Cmdlet          Set-AppLockerPolicy                                2.0.0.0    AppLocker
Cmdlet          Set-AppvClientConfiguration                        1.0.0.0    AppvClient
Cmdlet          Set-AppvClientMode                                 1.0.0.0    AppvClient
Cmdlet          Set-AppvClientPackage                              1.0.0.0    AppvClient
Cmdlet          Set-AppvPublishingServer                           1.0.0.0    AppvClient
Cmdlet          Set-AppxDefaultVolume                              2.0.1.0    Appx
Cmdlet          Set-AppXProvisionedDataFile                        3.0        Dism
Cmdlet          Set-AuthenticodeSignature                          3.0.0.0    Microsoft.P...
Cmdlet          Set-BitsTransfer                                   2.0.0.0    BitsTransfer
Cmdlet          Set-CertificateAutoEnrollmentPolicy                1.0.0.0    PKI
Cmdlet          Set-CimInstance                                    1.0.0.0    CimCmdlets
Cmdlet          Set-CIPolicyIdInfo                                 1.0        ConfigCI
Cmdlet          Set-CIPolicySetting                                1.0        ConfigCI
Cmdlet          Set-CIPolicyVersion                                1.0        ConfigCI
Cmdlet          Set-Clipboard                                      3.1.0.0    Microsoft.P...
Cmdlet          Set-Content                                        3.1.0.0    Microsoft.P...
Cmdlet          Set-Culture                                        2.0.0.0    International
Cmdlet          Set-Date                                           3.1.0.0    Microsoft.P...
Cmdlet          Set-DeliveryOptimizationStatus                     1.0.2.0    DeliveryOpt...
Cmdlet          Set-DODownloadMode                                 1.0.2.0    DeliveryOpt...
Cmdlet          Set-DOPercentageMaxBackgroundBandwidth             1.0.2.0    DeliveryOpt...
Cmdlet          Set-DOPercentageMaxForegroundBandwidth             1.0.2.0    DeliveryOpt...
Cmdlet          Set-DscLocalConfigurationManager                   1.1        PSDesiredSt...
Cmdlet          Set-ExecutionPolicy                                3.0.0.0    Microsoft.P...
Cmdlet          Set-HVCIOptions                                    1.0        ConfigCI
Cmdlet          Set-Item                                           3.1.0.0    Microsoft.P...
Cmdlet          Set-ItemProperty                                   3.1.0.0    Microsoft.P...
Cmdlet          Set-JobTrigger                                     1.1.0.0    PSScheduledJob
Cmdlet          Set-KdsConfiguration                               1.0.0.0    Kds
Cmdlet          Set-LocalGroup                                     1.0.0.0    Microsoft.P...
Cmdlet          Set-LocalUser                                      1.0.0.0    Microsoft.P...
Cmdlet          Set-Location                                       3.1.0.0    Microsoft.P...
Cmdlet          Set-NonRemovableAppsPolicy                         3.0        Dism
Cmdlet          Set-PackageSource                                  1.0.0.1    PackageMana...
Cmdlet          Set-ProcessMitigation                              1.0.11     ProcessMiti...
Cmdlet          Set-PSBreakpoint                                   3.1.0.0    Microsoft.P...
Cmdlet          Set-PSDebug                                        3.0.0.0    Microsoft.P...
Cmdlet          Set-PSReadLineKeyHandler                           2.0.0      PSReadline
Cmdlet          Set-PSReadLineOption                               2.0.0      PSReadline
Cmdlet          Set-PSSessionConfiguration                         3.0.0.0    Microsoft.P...
Cmdlet          Set-RuleOption                                     1.0        ConfigCI
Cmdlet          Set-ScheduledJob                                   1.1.0.0    PSScheduledJob
Cmdlet          Set-ScheduledJobOption                             1.1.0.0    PSScheduledJob
Cmdlet          Set-SecureBootUEFI                                 2.0.0.0    SecureBoot
Cmdlet          Set-Service                                        3.1.0.0    Microsoft.P...
Cmdlet          Set-StrictMode                                     3.0.0.0    Microsoft.P...
Cmdlet          Set-TimeZone                                       3.1.0.0    Microsoft.P...
Cmdlet          Set-TpmOwnerAuth                                   2.0.0.0    TrustedPlat...
Cmdlet          Set-TraceSource                                    3.1.0.0    Microsoft.P...
Cmdlet          Set-UevConfiguration                               2.1.639.0  UEV
Cmdlet          Set-UevTemplateProfile                             2.1.639.0  UEV
Cmdlet          Set-Variable                                       3.1.0.0    Microsoft.P...
Cmdlet          Set-VHD                                            2.0.0.0    Hyper-V
Cmdlet          Set-VM                                             2.0.0.0    Hyper-V
Cmdlet          Set-VMBios                                         2.0.0.0    Hyper-V
Cmdlet          Set-VMComPort                                      2.0.0.0    Hyper-V
Cmdlet          Set-VMDvdDrive                                     2.0.0.0    Hyper-V
Cmdlet          Set-VMFibreChannelHba                              2.0.0.0    Hyper-V
Cmdlet          Set-VMFirmware                                     2.0.0.0    Hyper-V
Cmdlet          Set-VMFloppyDiskDrive                              2.0.0.0    Hyper-V
Cmdlet          Set-VMGpuPartitionAdapter                          2.0.0.0    Hyper-V
Cmdlet          Set-VMHardDiskDrive                                2.0.0.0    Hyper-V
Cmdlet          Set-VMHost                                         2.0.0.0    Hyper-V
Cmdlet          Set-VMHostCluster                                  2.0.0.0    Hyper-V
Cmdlet          Set-VMKeyProtector                                 2.0.0.0    Hyper-V
Cmdlet          Set-VMKeyStorageDrive                              2.0.0.0    Hyper-V
Cmdlet          Set-VMMemory                                       2.0.0.0    Hyper-V
Cmdlet          Set-VMMigrationNetwork                             2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapter                               2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapterFailoverConfiguration          2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapterIsolation                      2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapterRdma                           2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapterRoutingDomainMapping           2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapterTeamMapping                    2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapterVlan                           2.0.0.0    Hyper-V
Cmdlet          Set-VMPartitionableGpu                             2.0.0.0    Hyper-V
Cmdlet          Set-VMProcessor                                    2.0.0.0    Hyper-V
Cmdlet          Set-VMRemoteFx3dVideoAdapter                       2.0.0.0    Hyper-V
Cmdlet          Set-VMReplication                                  2.0.0.0    Hyper-V
Cmdlet          Set-VMReplicationAuthorizationEntry                2.0.0.0    Hyper-V
Cmdlet          Set-VMReplicationServer                            2.0.0.0    Hyper-V
Cmdlet          Set-VMResourcePool                                 2.0.0.0    Hyper-V
Cmdlet          Set-VMSan                                          2.0.0.0    Hyper-V
Cmdlet          Set-VMSecurity                                     2.0.0.0    Hyper-V
Cmdlet          Set-VMSecurityPolicy                               2.0.0.0    Hyper-V
Cmdlet          Set-VMStorageSettings                              2.0.0.0    Hyper-V
Cmdlet          Set-VMSwitch                                       2.0.0.0    Hyper-V
Cmdlet          Set-VMSwitchExtensionPortFeature                   2.0.0.0    Hyper-V
Cmdlet          Set-VMSwitchExtensionSwitchFeature                 2.0.0.0    Hyper-V
Cmdlet          Set-VMSwitchTeam                                   2.0.0.0    Hyper-V
Cmdlet          Set-VMVideo                                        2.0.0.0    Hyper-V
Cmdlet          Set-WheaMemoryPolicy                               2.0.0.0    Whea
Cmdlet          Set-WinAcceptLanguageFromLanguageListOptOut        2.0.0.0    International
Cmdlet          Set-WinCultureFromLanguageListOptOut               2.0.0.0    International
Cmdlet          Set-WinDefaultInputMethodOverride                  2.0.0.0    International
Cmdlet          Set-WindowsEdition                                 3.0        Dism
Cmdlet          Set-WindowsProductKey                              3.0        Dism
Cmdlet          Set-WindowsSearchSetting                           1.0.0.0    WindowsSearch
Cmdlet          Set-WinHomeLocation                                2.0.0.0    International
Cmdlet          Set-WinLanguageBarOption                           2.0.0.0    International
Cmdlet          Set-WinSystemLocale                                2.0.0.0    International
Cmdlet          Set-WinUILanguageOverride                          2.0.0.0    International
Cmdlet          Set-WinUserLanguageList                            2.0.0.0    International
Cmdlet          Set-WmiInstance                                    3.1.0.0    Microsoft.P...
Cmdlet          Set-WSManInstance                                  3.0.0.0    Microsoft.W...
Cmdlet          Set-WSManQuickConfig                               3.0.0.0    Microsoft.W...
Cmdlet          Show-Command                                       3.1.0.0    Microsoft.P...
Cmdlet          Show-ControlPanelItem                              3.1.0.0    Microsoft.P...
Cmdlet          Show-EventLog                                      3.1.0.0    Microsoft.P...
Cmdlet          Show-WindowsDeveloperLicenseRegistration           1.0.0.0    WindowsDeve...
Cmdlet          Sort-Object                                        3.1.0.0    Microsoft.P...
Cmdlet          Split-Path                                         3.1.0.0    Microsoft.P...
Cmdlet          Split-WindowsImage                                 3.0        Dism
Cmdlet          Start-BitsTransfer                                 2.0.0.0    BitsTransfer
Cmdlet          Start-DscConfiguration                             1.1        PSDesiredSt...
Cmdlet          Start-DtcDiagnosticResourceManager                 1.0.0.0    MsDtc
Cmdlet          Start-Job                                          3.0.0.0    Microsoft.P...
Cmdlet          Start-OSUninstall                                  3.0        Dism
Cmdlet          Start-Process                                      3.1.0.0    Microsoft.P...
Cmdlet          Start-Service                                      3.1.0.0    Microsoft.P...
Cmdlet          Start-Sleep                                        3.1.0.0    Microsoft.P...
Cmdlet          Start-Transaction                                  3.1.0.0    Microsoft.P...
Cmdlet          Start-Transcript                                   3.0.0.0    Microsoft.P...
Cmdlet          Start-VM                                           2.0.0.0    Hyper-V
Cmdlet          Start-VMFailover                                   2.0.0.0    Hyper-V
Cmdlet          Start-VMInitialReplication                         2.0.0.0    Hyper-V
Cmdlet          Start-VMTrace                                      2.0.0.0    Hyper-V
Cmdlet          Stop-AppvClientConnectionGroup                     1.0.0.0    AppvClient
Cmdlet          Stop-AppvClientPackage                             1.0.0.0    AppvClient
Cmdlet          Stop-Computer                                      3.1.0.0    Microsoft.P...
Cmdlet          Stop-DtcDiagnosticResourceManager                  1.0.0.0    MsDtc
Cmdlet          Stop-Job                                           3.0.0.0    Microsoft.P...
Cmdlet          Stop-Process                                       3.1.0.0    Microsoft.P...
Cmdlet          Stop-Service                                       3.1.0.0    Microsoft.P...
Cmdlet          Stop-Transcript                                    3.0.0.0    Microsoft.P...
Cmdlet          Stop-VM                                            2.0.0.0    Hyper-V
Cmdlet          Stop-VMFailover                                    2.0.0.0    Hyper-V
Cmdlet          Stop-VMInitialReplication                          2.0.0.0    Hyper-V
Cmdlet          Stop-VMReplication                                 2.0.0.0    Hyper-V
Cmdlet          Stop-VMTrace                                       2.0.0.0    Hyper-V
Cmdlet          Suspend-BitsTransfer                               2.0.0.0    BitsTransfer
Cmdlet          Suspend-Job                                        3.0.0.0    Microsoft.P...
Cmdlet          Suspend-Service                                    3.1.0.0    Microsoft.P...
Cmdlet          Suspend-VM                                         2.0.0.0    Hyper-V
Cmdlet          Suspend-VMReplication                              2.0.0.0    Hyper-V
Cmdlet          Switch-Certificate                                 1.0.0.0    PKI
Cmdlet          Sync-AppvPublishingServer                          1.0.0.0    AppvClient
Cmdlet          Tee-Object                                         3.1.0.0    Microsoft.P...
Cmdlet          Test-AppLockerPolicy                               2.0.0.0    AppLocker
Cmdlet          Test-Certificate                                   1.0.0.0    PKI
Cmdlet          Test-ComputerSecureChannel                         3.1.0.0    Microsoft.P...
Cmdlet          Test-Connection                                    3.1.0.0    Microsoft.P...
Cmdlet          Test-DscConfiguration                              1.1        PSDesiredSt...
Cmdlet          Test-FileCatalog                                   3.0.0.0    Microsoft.P...
Cmdlet          Test-HgsTraceTarget                                1.0.0.0    HgsDiagnostics
Cmdlet          Test-KdsRootKey                                    1.0.0.0    Kds
Cmdlet          Test-ModuleManifest                                3.0.0.0    Microsoft.P...
Cmdlet          Test-Path                                          3.1.0.0    Microsoft.P...
Cmdlet          Test-PSSessionConfigurationFile                    3.0.0.0    Microsoft.P...
Cmdlet          Test-UevTemplate                                   2.1.639.0  UEV
Cmdlet          Test-VHD                                           2.0.0.0    Hyper-V
Cmdlet          Test-VMNetworkAdapter                              2.0.0.0    Hyper-V
Cmdlet          Test-VMReplicationConnection                       2.0.0.0    Hyper-V
Cmdlet          Test-WSMan                                         3.0.0.0    Microsoft.W...
Cmdlet          Trace-Command                                      3.1.0.0    Microsoft.P...
Cmdlet          Unblock-File                                       3.1.0.0    Microsoft.P...
Cmdlet          Unblock-Tpm                                        2.0.0.0    TrustedPlat...
Cmdlet          Undo-DtcDiagnosticTransaction                      1.0.0.0    MsDtc
Cmdlet          Undo-Transaction                                   3.1.0.0    Microsoft.P...
Cmdlet          Uninstall-Package                                  1.0.0.1    PackageMana...
Cmdlet          Uninstall-ProvisioningPackage                      3.0        Provisioning
Cmdlet          Uninstall-TrustedProvisioningCertificate           3.0        Provisioning
Cmdlet          Unprotect-CmsMessage                               3.0.0.0    Microsoft.P...
Cmdlet          Unpublish-AppvClientPackage                        1.0.0.0    AppvClient
Cmdlet          Unregister-Event                                   3.1.0.0    Microsoft.P...
Cmdlet          Unregister-PackageSource                           1.0.0.1    PackageMana...
Cmdlet          Unregister-PSSessionConfiguration                  3.0.0.0    Microsoft.P...
Cmdlet          Unregister-ScheduledJob                            1.1.0.0    PSScheduledJob
Cmdlet          Unregister-UevTemplate                             2.1.639.0  UEV
Cmdlet          Unregister-WindowsDeveloperLicense                 1.0.0.0    WindowsDeve...
Cmdlet          Update-DscConfiguration                            1.1        PSDesiredSt...
Cmdlet          Update-FormatData                                  3.1.0.0    Microsoft.P...
Cmdlet          Update-Help                                        3.0.0.0    Microsoft.P...
Cmdlet          Update-List                                        3.1.0.0    Microsoft.P...
Cmdlet          Update-TypeData                                    3.1.0.0    Microsoft.P...
Cmdlet          Update-UevTemplate                                 2.1.639.0  UEV
Cmdlet          Update-VMVersion                                   2.0.0.0    Hyper-V
Cmdlet          Update-WIMBootEntry                                3.0        Dism
Cmdlet          Use-Transaction                                    3.1.0.0    Microsoft.P...
Cmdlet          Use-WindowsUnattend                                3.0        Dism
Cmdlet          Wait-Debugger                                      3.1.0.0    Microsoft.P...
Cmdlet          Wait-Event                                         3.1.0.0    Microsoft.P...
Cmdlet          Wait-Job                                           3.0.0.0    Microsoft.P...
Cmdlet          Wait-Process                                       3.1.0.0    Microsoft.P...
Cmdlet          Wait-VM                                            2.0.0.0    Hyper-V
Cmdlet          Where-Object                                       3.0.0.0    Microsoft.P...
Cmdlet          Write-Debug                                        3.1.0.0    Microsoft.P...
Cmdlet          Write-Error                                        3.1.0.0    Microsoft.P...
Cmdlet          Write-EventLog                                     3.1.0.0    Microsoft.P...
Cmdlet          Write-Host                                         3.1.0.0    Microsoft.P...
Cmdlet          Write-Information                                  3.1.0.0    Microsoft.P...
Cmdlet          Write-Output                                       3.1.0.0    Microsoft.P...
Cmdlet          Write-Progress                                     3.1.0.0    Microsoft.P...
Cmdlet          Write-Verbose                                      3.1.0.0    Microsoft.P...
Cmdlet          Write-Warning                                      3.1.0.0    Microsoft.P...
```
### 使用 Get-Help
```
PS C:\windows\system32> Get-Help

您是否想要執行 Update-Help?
Update-Help Cmdlet 會下載 Windows PowerShell
模組的最新說明檔，並將它們安裝在您的電腦上。如需關於 Update-Help Cmdlet 的詳細資訊，請參閱
https:/go.microsoft.com/fwlink/?LinkId=210614。
[Y] 是(Y)  [N] 否(N)  [S] 暫停(S)  [?] 說明 (預設值為 "Y"): y


主題
    Windows PowerShell 說明系統

簡短描述
    顯示關於 Windows PowerShell Cmdlet 和概念的說明。

完整描述
    Windows PowerShell 說明將描述 Windows PowerShell Cmdlet、
    功能、指令碼及模組，以及說明包括
    Windows PowerShell 語言項目在內的概念。

    Windows PowerShell 未包含說明檔案，但您可以線上讀取
    說明主題，或是使用 Update-Help Cmdlet，將說明檔案
    下載至您的電腦，然後使用 Get-Help Cmdlet，在命令列中
    顯示說明主題。

    您也可以使用 Update-Help Cmdlet，在發行更新的說明檔時
    進行下載，如此，您的本機說明內容就能永遠維持最新狀態。

    不需使用說明檔，Get-Help 會顯示針對 Cmdlet、功能及指令碼
    自動產生的說明。


  線上說明
    您一開始可以在 TechNet Library (網址為
     http://go.microsoft.com/fwlink/?LinkID=108518) 線上尋找適用於 Windows PowerShell 的說明 。

    若要開啟任何 Cmdlet 或功能的線上說明，請輸入：

        Get-Help <Cmdlet-name> -Online

  UPDATE-HELP
    若要在電腦下載並安裝說明檔案：

       1. 利用 [以系統管理員身分執行] 選項來啟動 Windows PowerShell。
       2. 輸入：

          Update-Help

    在安裝說明檔之後，您可以使用 Get-Help Cmdlet 來
    顯示說明主題。 您也可以使用 Update-Help Cmdlet 來
    下載更新的說明檔，如此，您本機的說明檔將永遠維持
    最新狀態。

    如需關於 Update-Help Cmdlet 的詳細資訊，請輸入：

       Get-Help Update-Help -Online

    或移至： http://go.microsoft.com/fwlink/?LinkID=210614


  GET-HELP
    Get-Help Cmdlet 會在您電腦的命令列上顯示來自說明檔中
    內容的說明。 不需使用說明檔，Get-Help 會顯示
    針對 Cmdlet 及功能有關的基本說明。 您也可以使用 Get-Help 來顯示
    Cmdlet 與功能的線上說明。

    若要取得 Cmdlet 的說明，請輸入：

        Get-Help <Cmdlet-name>

    若要取得線上說明，請輸入：

        Get-Help <Cmdlet-name> -Online

    概念性主題的標題會以 "About_" 為開頭。
    若要取得概念或語言項目的說明，請輸入：

        Get-Help About_<topic-name>

    若要搜尋所有說明檔中的字詞或片語，請輸入：

        Get-Help <search-term>

    如需關於 Get-Help Cmdlet 的詳細資訊，請輸入：

        Get-Help Get-Help -Online

    或移至： http://go.microsoft.com/fwlink/?LinkID=113316


  範例：
      Save-Help              ：從網際網路下載說明檔，並將它們
                               儲存於檔案共用上。
      Update-Help              ：從網際網路或檔案共用下載並安裝
                               說明檔。
      Get-Help Get-Process   ：顯示關於 Get-Process Cmdlet 的說明。
      Get-Help Get-Process -Online
                             ： 開啟 Get-Process Cmdlet 的線上說明。                         
      Help Get-Process       ：一次在一個頁面上顯示 Get-Process 的說明。
      Get-Process -?         ：顯示關於 Get-Process Cmdlet 的說明。
      Get-Help About_Modules ：顯示關於 Windows PowerShell 模組的說明。
      Get-Help remoting      ： 利用字詞 "remoting" 來搜尋說明主題。

  另請參閱：
      about_Updatable_Help
      Get-Help
      Save-Help
      Update-Help
PS C:\windows\system32> Y
```
### 執行 Get-Command -Type Cmdlet
```
PS C:\windows\system32> Get-Command -Type Cmdlet

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Add-AppvClientConnectionGroup                      1.0.0.0    AppvClient
Cmdlet          Add-AppvClientPackage                              1.0.0.0    AppvClient
Cmdlet          Add-AppvPublishingServer                           1.0.0.0    AppvClient
Cmdlet          Add-AppxPackage                                    2.0.1.0    Appx
Cmdlet          Add-AppxProvisionedPackage                         3.0        Dism
Cmdlet          Add-AppxVolume                                     2.0.1.0    Appx
Cmdlet          Add-BitsFile                                       2.0.0.0    BitsTransfer
Cmdlet          Add-CertificateEnrollmentPolicyServer              1.0.0.0    PKI
Cmdlet          Add-Computer                                       3.1.0.0    Microsoft.P...
Cmdlet          Add-Content                                        3.1.0.0    Microsoft.P...
Cmdlet          Add-History                                        3.0.0.0    Microsoft.P...
Cmdlet          Add-JobTrigger                                     1.1.0.0    PSScheduledJob
Cmdlet          Add-KdsRootKey                                     1.0.0.0    Kds
Cmdlet          Add-LocalGroupMember                               1.0.0.0    Microsoft.P...
Cmdlet          Add-Member                                         3.1.0.0    Microsoft.P...
Cmdlet          Add-PSSnapin                                       3.0.0.0    Microsoft.P...
Cmdlet          Add-SignerRule                                     1.0        ConfigCI
Cmdlet          Add-Type                                           3.1.0.0    Microsoft.P...
Cmdlet          Add-VMAssignableDevice                             2.0.0.0    Hyper-V
Cmdlet          Add-VMDvdDrive                                     2.0.0.0    Hyper-V
Cmdlet          Add-VMFibreChannelHba                              2.0.0.0    Hyper-V
Cmdlet          Add-VMGpuPartitionAdapter                          2.0.0.0    Hyper-V
Cmdlet          Add-VMGroupMember                                  2.0.0.0    Hyper-V
Cmdlet          Add-VMHardDiskDrive                                2.0.0.0    Hyper-V
Cmdlet          Add-VMHostAssignableDevice                         2.0.0.0    Hyper-V
Cmdlet          Add-VMKeyStorageDrive                              2.0.0.0    Hyper-V
Cmdlet          Add-VMMigrationNetwork                             2.0.0.0    Hyper-V
Cmdlet          Add-VMNetworkAdapter                               2.0.0.0    Hyper-V
Cmdlet          Add-VMNetworkAdapterAcl                            2.0.0.0    Hyper-V
Cmdlet          Add-VMNetworkAdapterExtendedAcl                    2.0.0.0    Hyper-V
Cmdlet          Add-VMNetworkAdapterRoutingDomainMapping           2.0.0.0    Hyper-V
Cmdlet          Add-VMPmemController                               2.0.0.0    Hyper-V
Cmdlet          Add-VMRemoteFx3dVideoAdapter                       2.0.0.0    Hyper-V
Cmdlet          Add-VMScsiController                               2.0.0.0    Hyper-V
Cmdlet          Add-VMStoragePath                                  2.0.0.0    Hyper-V
Cmdlet          Add-VMSwitch                                       2.0.0.0    Hyper-V
Cmdlet          Add-VMSwitchExtensionPortFeature                   2.0.0.0    Hyper-V
Cmdlet          Add-VMSwitchExtensionSwitchFeature                 2.0.0.0    Hyper-V
Cmdlet          Add-VMSwitchTeamMember                             2.0.0.0    Hyper-V
Cmdlet          Add-WindowsCapability                              3.0        Dism
Cmdlet          Add-WindowsDriver                                  3.0        Dism
Cmdlet          Add-WindowsImage                                   3.0        Dism
Cmdlet          Add-WindowsPackage                                 3.0        Dism
Cmdlet          Checkpoint-Computer                                3.1.0.0    Microsoft.P...
Cmdlet          Checkpoint-VM                                      2.0.0.0    Hyper-V
Cmdlet          Clear-Content                                      3.1.0.0    Microsoft.P...
Cmdlet          Clear-EventLog                                     3.1.0.0    Microsoft.P...
Cmdlet          Clear-History                                      3.0.0.0    Microsoft.P...
Cmdlet          Clear-Item                                         3.1.0.0    Microsoft.P...
Cmdlet          Clear-ItemProperty                                 3.1.0.0    Microsoft.P...
Cmdlet          Clear-KdsCache                                     1.0.0.0    Kds
Cmdlet          Clear-RecycleBin                                   3.1.0.0    Microsoft.P...
Cmdlet          Clear-Tpm                                          2.0.0.0    TrustedPlat...
Cmdlet          Clear-UevAppxPackage                               2.1.639.0  UEV
Cmdlet          Clear-UevConfiguration                             2.1.639.0  UEV
Cmdlet          Clear-Variable                                     3.1.0.0    Microsoft.P...
Cmdlet          Clear-WindowsCorruptMountPoint                     3.0        Dism
Cmdlet          Compare-Object                                     3.1.0.0    Microsoft.P...
Cmdlet          Compare-VM                                         2.0.0.0    Hyper-V
Cmdlet          Complete-BitsTransfer                              2.0.0.0    BitsTransfer
Cmdlet          Complete-DtcDiagnosticTransaction                  1.0.0.0    MsDtc
Cmdlet          Complete-Transaction                               3.1.0.0    Microsoft.P...
Cmdlet          Complete-VMFailover                                2.0.0.0    Hyper-V
Cmdlet          Confirm-SecureBootUEFI                             2.0.0.0    SecureBoot
Cmdlet          Connect-PSSession                                  3.0.0.0    Microsoft.P...
Cmdlet          Connect-VMNetworkAdapter                           2.0.0.0    Hyper-V
Cmdlet          Connect-VMSan                                      2.0.0.0    Hyper-V
Cmdlet          Connect-WSMan                                      3.0.0.0    Microsoft.W...
Cmdlet          ConvertFrom-CIPolicy                               1.0        ConfigCI
Cmdlet          ConvertFrom-Csv                                    3.1.0.0    Microsoft.P...
Cmdlet          ConvertFrom-Json                                   3.1.0.0    Microsoft.P...
Cmdlet          ConvertFrom-SecureString                           3.0.0.0    Microsoft.P...
Cmdlet          ConvertFrom-String                                 3.1.0.0    Microsoft.P...
Cmdlet          ConvertFrom-StringData                             3.1.0.0    Microsoft.P...
Cmdlet          Convert-Path                                       3.1.0.0    Microsoft.P...
Cmdlet          Convert-String                                     3.1.0.0    Microsoft.P...
Cmdlet          ConvertTo-Csv                                      3.1.0.0    Microsoft.P...
Cmdlet          ConvertTo-Html                                     3.1.0.0    Microsoft.P...
Cmdlet          ConvertTo-Json                                     3.1.0.0    Microsoft.P...
Cmdlet          ConvertTo-ProcessMitigationPolicy                  1.0.11     ProcessMiti...
Cmdlet          ConvertTo-SecureString                             3.0.0.0    Microsoft.P...
Cmdlet          ConvertTo-TpmOwnerAuth                             2.0.0.0    TrustedPlat...
Cmdlet          ConvertTo-Xml                                      3.1.0.0    Microsoft.P...
Cmdlet          Convert-VHD                                        2.0.0.0    Hyper-V
Cmdlet          Copy-Item                                          3.1.0.0    Microsoft.P...
Cmdlet          Copy-ItemProperty                                  3.1.0.0    Microsoft.P...
Cmdlet          Copy-VMFile                                        2.0.0.0    Hyper-V
Cmdlet          Debug-Job                                          3.0.0.0    Microsoft.P...
Cmdlet          Debug-Process                                      3.1.0.0    Microsoft.P...
Cmdlet          Debug-Runspace                                     3.1.0.0    Microsoft.P...
Cmdlet          Debug-VM                                           2.0.0.0    Hyper-V
Cmdlet          Delete-DeliveryOptimizationCache                   1.0.2.0    DeliveryOpt...
Cmdlet          Disable-AppBackgroundTaskDiagnosticLog             1.0.0.0    AppBackgrou...
Cmdlet          Disable-Appv                                       1.0.0.0    AppvClient
Cmdlet          Disable-AppvClientConnectionGroup                  1.0.0.0    AppvClient
Cmdlet          Disable-ComputerRestore                            3.1.0.0    Microsoft.P...
Cmdlet          Disable-JobTrigger                                 1.1.0.0    PSScheduledJob
Cmdlet          Disable-LocalUser                                  1.0.0.0    Microsoft.P...
Cmdlet          Disable-PSBreakpoint                               3.1.0.0    Microsoft.P...
Cmdlet          Disable-PSRemoting                                 3.0.0.0    Microsoft.P...
Cmdlet          Disable-PSSessionConfiguration                     3.0.0.0    Microsoft.P...
Cmdlet          Disable-RunspaceDebug                              3.1.0.0    Microsoft.P...
Cmdlet          Disable-ScheduledJob                               1.1.0.0    PSScheduledJob
Cmdlet          Disable-TlsCipherSuite                             2.0.0.0    TLS
Cmdlet          Disable-TlsEccCurve                                2.0.0.0    TLS
Cmdlet          Disable-TlsSessionTicketKey                        2.0.0.0    TLS
Cmdlet          Disable-TpmAutoProvisioning                        2.0.0.0    TrustedPlat...
Cmdlet          Disable-Uev                                        2.1.639.0  UEV
Cmdlet          Disable-UevAppxPackage                             2.1.639.0  UEV
Cmdlet          Disable-UevTemplate                                2.1.639.0  UEV
Cmdlet          Disable-VMConsoleSupport                           2.0.0.0    Hyper-V
Cmdlet          Disable-VMEventing                                 2.0.0.0    Hyper-V
Cmdlet          Disable-VMIntegrationService                       2.0.0.0    Hyper-V
Cmdlet          Disable-VMMigration                                2.0.0.0    Hyper-V
Cmdlet          Disable-VMRemoteFXPhysicalVideoAdapter             2.0.0.0    Hyper-V
Cmdlet          Disable-VMResourceMetering                         2.0.0.0    Hyper-V
Cmdlet          Disable-VMSwitchExtension                          2.0.0.0    Hyper-V
Cmdlet          Disable-VMTPM                                      2.0.0.0    Hyper-V
Cmdlet          Disable-WindowsErrorReporting                      1.0        WindowsErro...
Cmdlet          Disable-WindowsOptionalFeature                     3.0        Dism
Cmdlet          Disable-WSManCredSSP                               3.0.0.0    Microsoft.W...
Cmdlet          Disconnect-PSSession                               3.0.0.0    Microsoft.P...
Cmdlet          Disconnect-VMNetworkAdapter                        2.0.0.0    Hyper-V
Cmdlet          Disconnect-VMSan                                   2.0.0.0    Hyper-V
Cmdlet          Disconnect-WSMan                                   3.0.0.0    Microsoft.W...
Cmdlet          Dismount-AppxVolume                                2.0.1.0    Appx
Cmdlet          Dismount-VHD                                       2.0.0.0    Hyper-V
Cmdlet          Dismount-VMHostAssignableDevice                    2.0.0.0    Hyper-V
Cmdlet          Dismount-WindowsImage                              3.0        Dism
Cmdlet          Edit-CIPolicyRule                                  1.0        ConfigCI
Cmdlet          Enable-AppBackgroundTaskDiagnosticLog              1.0.0.0    AppBackgrou...
Cmdlet          Enable-Appv                                        1.0.0.0    AppvClient
Cmdlet          Enable-AppvClientConnectionGroup                   1.0.0.0    AppvClient
Cmdlet          Enable-ComputerRestore                             3.1.0.0    Microsoft.P...
Cmdlet          Enable-JobTrigger                                  1.1.0.0    PSScheduledJob
Cmdlet          Enable-LocalUser                                   1.0.0.0    Microsoft.P...
Cmdlet          Enable-PSBreakpoint                                3.1.0.0    Microsoft.P...
Cmdlet          Enable-PSRemoting                                  3.0.0.0    Microsoft.P...
Cmdlet          Enable-PSSessionConfiguration                      3.0.0.0    Microsoft.P...
Cmdlet          Enable-RunspaceDebug                               3.1.0.0    Microsoft.P...
Cmdlet          Enable-ScheduledJob                                1.1.0.0    PSScheduledJob
Cmdlet          Enable-TlsCipherSuite                              2.0.0.0    TLS
Cmdlet          Enable-TlsEccCurve                                 2.0.0.0    TLS
Cmdlet          Enable-TlsSessionTicketKey                         2.0.0.0    TLS
Cmdlet          Enable-TpmAutoProvisioning                         2.0.0.0    TrustedPlat...
Cmdlet          Enable-Uev                                         2.1.639.0  UEV
Cmdlet          Enable-UevAppxPackage                              2.1.639.0  UEV
Cmdlet          Enable-UevTemplate                                 2.1.639.0  UEV
Cmdlet          Enable-VMConsoleSupport                            2.0.0.0    Hyper-V
Cmdlet          Enable-VMEventing                                  2.0.0.0    Hyper-V
Cmdlet          Enable-VMIntegrationService                        2.0.0.0    Hyper-V
Cmdlet          Enable-VMMigration                                 2.0.0.0    Hyper-V
Cmdlet          Enable-VMRemoteFXPhysicalVideoAdapter              2.0.0.0    Hyper-V
Cmdlet          Enable-VMReplication                               2.0.0.0    Hyper-V
Cmdlet          Enable-VMResourceMetering                          2.0.0.0    Hyper-V
Cmdlet          Enable-VMSwitchExtension                           2.0.0.0    Hyper-V
Cmdlet          Enable-VMTPM                                       2.0.0.0    Hyper-V
Cmdlet          Enable-WindowsErrorReporting                       1.0        WindowsErro...
Cmdlet          Enable-WindowsOptionalFeature                      3.0        Dism
Cmdlet          Enable-WSManCredSSP                                3.0.0.0    Microsoft.W...
Cmdlet          Enter-PSHostProcess                                3.0.0.0    Microsoft.P...
Cmdlet          Enter-PSSession                                    3.0.0.0    Microsoft.P...
Cmdlet          Exit-PSHostProcess                                 3.0.0.0    Microsoft.P...
Cmdlet          Exit-PSSession                                     3.0.0.0    Microsoft.P...
Cmdlet          Expand-WindowsCustomDataImage                      3.0        Dism
Cmdlet          Expand-WindowsImage                                3.0        Dism
Cmdlet          Export-Alias                                       3.1.0.0    Microsoft.P...
Cmdlet          Export-BinaryMiLog                                 1.0.0.0    CimCmdlets
Cmdlet          Export-Certificate                                 1.0.0.0    PKI
Cmdlet          Export-Clixml                                      3.1.0.0    Microsoft.P...
Cmdlet          Export-Console                                     3.0.0.0    Microsoft.P...
Cmdlet          Export-Counter                                     3.0.0.0    Microsoft.P...
Cmdlet          Export-Csv                                         3.1.0.0    Microsoft.P...
Cmdlet          Export-FormatData                                  3.1.0.0    Microsoft.P...
Cmdlet          Export-ModuleMember                                3.0.0.0    Microsoft.P...
Cmdlet          Export-PfxCertificate                              1.0.0.0    PKI
Cmdlet          Export-ProvisioningPackage                         3.0        Provisioning
Cmdlet          Export-PSSession                                   3.1.0.0    Microsoft.P...
Cmdlet          Export-StartLayout                                 1.0.0.0    StartLayout
Cmdlet          Export-StartLayoutEdgeAssets                       1.0.0.0    StartLayout
Cmdlet          Export-TlsSessionTicketKey                         2.0.0.0    TLS
Cmdlet          Export-Trace                                       3.0        Provisioning
Cmdlet          Export-UevConfiguration                            2.1.639.0  UEV
Cmdlet          Export-UevPackage                                  2.1.639.0  UEV
Cmdlet          Export-VM                                          2.0.0.0    Hyper-V
Cmdlet          Export-VMSnapshot                                  2.0.0.0    Hyper-V
Cmdlet          Export-WindowsCapabilitySource                     3.0        Dism
Cmdlet          Export-WindowsDriver                               3.0        Dism
Cmdlet          Export-WindowsImage                                3.0        Dism
Cmdlet          Find-Package                                       1.0.0.1    PackageMana...
Cmdlet          Find-PackageProvider                               1.0.0.1    PackageMana...
Cmdlet          ForEach-Object                                     3.0.0.0    Microsoft.P...
Cmdlet          Format-Custom                                      3.1.0.0    Microsoft.P...
Cmdlet          Format-List                                        3.1.0.0    Microsoft.P...
Cmdlet          Format-SecureBootUEFI                              2.0.0.0    SecureBoot
Cmdlet          Format-Table                                       3.1.0.0    Microsoft.P...
Cmdlet          Format-Wide                                        3.1.0.0    Microsoft.P...
Cmdlet          Get-Acl                                            3.0.0.0    Microsoft.P...
Cmdlet          Get-Alias                                          3.1.0.0    Microsoft.P...
Cmdlet          Get-AppLockerFileInformation                       2.0.0.0    AppLocker
Cmdlet          Get-AppLockerPolicy                                2.0.0.0    AppLocker
Cmdlet          Get-AppvClientApplication                          1.0.0.0    AppvClient
Cmdlet          Get-AppvClientConfiguration                        1.0.0.0    AppvClient
Cmdlet          Get-AppvClientConnectionGroup                      1.0.0.0    AppvClient
Cmdlet          Get-AppvClientMode                                 1.0.0.0    AppvClient
Cmdlet          Get-AppvClientPackage                              1.0.0.0    AppvClient
Cmdlet          Get-AppvPublishingServer                           1.0.0.0    AppvClient
Cmdlet          Get-AppvStatus                                     1.0.0.0    AppvClient
Cmdlet          Get-AppxDefaultVolume                              2.0.1.0    Appx
Cmdlet          Get-AppxPackage                                    2.0.1.0    Appx
Cmdlet          Get-AppxPackageManifest                            2.0.1.0    Appx
Cmdlet          Get-AppxProvisionedPackage                         3.0        Dism
Cmdlet          Get-AppxVolume                                     2.0.1.0    Appx
Cmdlet          Get-AuthenticodeSignature                          3.0.0.0    Microsoft.P...
Cmdlet          Get-BitsTransfer                                   2.0.0.0    BitsTransfer
Cmdlet          Get-Certificate                                    1.0.0.0    PKI
Cmdlet          Get-CertificateAutoEnrollmentPolicy                1.0.0.0    PKI
Cmdlet          Get-CertificateEnrollmentPolicyServer              1.0.0.0    PKI
Cmdlet          Get-CertificateNotificationTask                    1.0.0.0    PKI
Cmdlet          Get-ChildItem                                      3.1.0.0    Microsoft.P...
Cmdlet          Get-CimAssociatedInstance                          1.0.0.0    CimCmdlets
Cmdlet          Get-CimClass                                       1.0.0.0    CimCmdlets
Cmdlet          Get-CimInstance                                    1.0.0.0    CimCmdlets
Cmdlet          Get-CimSession                                     1.0.0.0    CimCmdlets
Cmdlet          Get-CIPolicy                                       1.0        ConfigCI
Cmdlet          Get-CIPolicyIdInfo                                 1.0        ConfigCI
Cmdlet          Get-CIPolicyInfo                                   1.0        ConfigCI
Cmdlet          Get-Clipboard                                      3.1.0.0    Microsoft.P...
Cmdlet          Get-CmsMessage                                     3.0.0.0    Microsoft.P...
Cmdlet          Get-Command                                        3.0.0.0    Microsoft.P...
Cmdlet          Get-ComputerInfo                                   3.1.0.0    Microsoft.P...
Cmdlet          Get-ComputerRestorePoint                           3.1.0.0    Microsoft.P...
Cmdlet          Get-Content                                        3.1.0.0    Microsoft.P...
Cmdlet          Get-ControlPanelItem                               3.1.0.0    Microsoft.P...
Cmdlet          Get-Counter                                        3.0.0.0    Microsoft.P...
Cmdlet          Get-Credential                                     3.0.0.0    Microsoft.P...
Cmdlet          Get-Culture                                        3.1.0.0    Microsoft.P...
Cmdlet          Get-DAPolicyChange                                 2.0.0.0    NetSecurity
Cmdlet          Get-Date                                           3.1.0.0    Microsoft.P...
Cmdlet          Get-DeliveryOptimizationLog                        1.0.2.0    DeliveryOpt...
Cmdlet          Get-DeliveryOptimizationPerfSnap                   1.0.2.0    DeliveryOpt...
Cmdlet          Get-DeliveryOptimizationPerfSnapThisMonth          1.0.2.0    DeliveryOpt...
Cmdlet          Get-DeliveryOptimizationStatus                     1.0.2.0    DeliveryOpt...
Cmdlet          Get-DOConfig                                       1.0.2.0    DeliveryOpt...
Cmdlet          Get-DODownloadMode                                 1.0.2.0    DeliveryOpt...
Cmdlet          Get-DOPercentageMaxBackgroundBandwidth             1.0.2.0    DeliveryOpt...
Cmdlet          Get-DOPercentageMaxForegroundBandwidth             1.0.2.0    DeliveryOpt...
Cmdlet          Get-Event                                          3.1.0.0    Microsoft.P...
Cmdlet          Get-EventLog                                       3.1.0.0    Microsoft.P...
Cmdlet          Get-EventSubscriber                                3.1.0.0    Microsoft.P...
Cmdlet          Get-ExecutionPolicy                                3.0.0.0    Microsoft.P...
Cmdlet          Get-FormatData                                     3.1.0.0    Microsoft.P...
Cmdlet          Get-Help                                           3.0.0.0    Microsoft.P...
Cmdlet          Get-HgsAttestationBaselinePolicy                   1.0.0.0    HgsClient
Cmdlet          Get-HgsTrace                                       1.0.0.0    HgsDiagnostics
Cmdlet          Get-HgsTraceFileData                               1.0.0.0    HgsDiagnostics
Cmdlet          Get-History                                        3.0.0.0    Microsoft.P...
Cmdlet          Get-Host                                           3.1.0.0    Microsoft.P...
Cmdlet          Get-HotFix                                         3.1.0.0    Microsoft.P...
Cmdlet          Get-Item                                           3.1.0.0    Microsoft.P...
Cmdlet          Get-ItemProperty                                   3.1.0.0    Microsoft.P...
Cmdlet          Get-ItemPropertyValue                              3.1.0.0    Microsoft.P...
Cmdlet          Get-Job                                            3.0.0.0    Microsoft.P...
Cmdlet          Get-JobTrigger                                     1.1.0.0    PSScheduledJob
Cmdlet          Get-KdsConfiguration                               1.0.0.0    Kds
Cmdlet          Get-KdsRootKey                                     1.0.0.0    Kds
Cmdlet          Get-LocalGroup                                     1.0.0.0    Microsoft.P...
Cmdlet          Get-LocalGroupMember                               1.0.0.0    Microsoft.P...
Cmdlet          Get-LocalUser                                      1.0.0.0    Microsoft.P...
Cmdlet          Get-Location                                       3.1.0.0    Microsoft.P...
Cmdlet          Get-Member                                         3.1.0.0    Microsoft.P...
Cmdlet          Get-Module                                         3.0.0.0    Microsoft.P...
Cmdlet          Get-NonRemovableAppsPolicy                         3.0        Dism
Cmdlet          Get-Package                                        1.0.0.1    PackageMana...
Cmdlet          Get-PackageProvider                                1.0.0.1    PackageMana...
Cmdlet          Get-PackageSource                                  1.0.0.1    PackageMana...
Cmdlet          Get-PfxCertificate                                 3.0.0.0    Microsoft.P...
Cmdlet          Get-PfxData                                        1.0.0.0    PKI
Cmdlet          Get-PmemDisk                                       1.0.0.0    PersistentM...
Cmdlet          Get-PmemPhysicalDevice                             1.0.0.0    PersistentM...
Cmdlet          Get-PmemUnusedRegion                               1.0.0.0    PersistentM...
Cmdlet          Get-Process                                        3.1.0.0    Microsoft.P...
Cmdlet          Get-ProcessMitigation                              1.0.11     ProcessMiti...
Cmdlet          Get-ProvisioningPackage                            3.0        Provisioning
Cmdlet          Get-PSBreakpoint                                   3.1.0.0    Microsoft.P...
Cmdlet          Get-PSCallStack                                    3.1.0.0    Microsoft.P...
Cmdlet          Get-PSDrive                                        3.1.0.0    Microsoft.P...
Cmdlet          Get-PSHostProcessInfo                              3.0.0.0    Microsoft.P...
Cmdlet          Get-PSProvider                                     3.1.0.0    Microsoft.P...
Cmdlet          Get-PSReadLineKeyHandler                           2.0.0      PSReadline
Cmdlet          Get-PSReadLineOption                               2.0.0      PSReadline
Cmdlet          Get-PSSession                                      3.0.0.0    Microsoft.P...
Cmdlet          Get-PSSessionCapability                            3.0.0.0    Microsoft.P...
Cmdlet          Get-PSSessionConfiguration                         3.0.0.0    Microsoft.P...
Cmdlet          Get-PSSnapin                                       3.0.0.0    Microsoft.P...
Cmdlet          Get-Random                                         3.1.0.0    Microsoft.P...
Cmdlet          Get-Runspace                                       3.1.0.0    Microsoft.P...
Cmdlet          Get-RunspaceDebug                                  3.1.0.0    Microsoft.P...
Cmdlet          Get-ScheduledJob                                   1.1.0.0    PSScheduledJob
Cmdlet          Get-ScheduledJobOption                             1.1.0.0    PSScheduledJob
Cmdlet          Get-SecureBootPolicy                               2.0.0.0    SecureBoot
Cmdlet          Get-SecureBootUEFI                                 2.0.0.0    SecureBoot
Cmdlet          Get-Service                                        3.1.0.0    Microsoft.P...
Cmdlet          Get-SystemDriver                                   1.0        ConfigCI
Cmdlet          Get-TimeZone                                       3.1.0.0    Microsoft.P...
Cmdlet          Get-TlsCipherSuite                                 2.0.0.0    TLS
Cmdlet          Get-TlsEccCurve                                    2.0.0.0    TLS
Cmdlet          Get-Tpm                                            2.0.0.0    TrustedPlat...
Cmdlet          Get-TpmEndorsementKeyInfo                          2.0.0.0    TrustedPlat...
Cmdlet          Get-TpmSupportedFeature                            2.0.0.0    TrustedPlat...
Cmdlet          Get-TraceSource                                    3.1.0.0    Microsoft.P...
Cmdlet          Get-Transaction                                    3.1.0.0    Microsoft.P...
Cmdlet          Get-TroubleshootingPack                            1.0.0.0    Troubleshoo...
Cmdlet          Get-TrustedProvisioningCertificate                 3.0        Provisioning
Cmdlet          Get-TypeData                                       3.1.0.0    Microsoft.P...
Cmdlet          Get-UevAppxPackage                                 2.1.639.0  UEV
Cmdlet          Get-UevConfiguration                               2.1.639.0  UEV
Cmdlet          Get-UevStatus                                      2.1.639.0  UEV
Cmdlet          Get-UevTemplate                                    2.1.639.0  UEV
Cmdlet          Get-UevTemplateProgram                             2.1.639.0  UEV
Cmdlet          Get-UICulture                                      3.1.0.0    Microsoft.P...
Cmdlet          Get-Unique                                         3.1.0.0    Microsoft.P...
Cmdlet          Get-Variable                                       3.1.0.0    Microsoft.P...
Cmdlet          Get-VHD                                            2.0.0.0    Hyper-V
Cmdlet          Get-VHDSet                                         2.0.0.0    Hyper-V
Cmdlet          Get-VHDSnapshot                                    2.0.0.0    Hyper-V
Cmdlet          Get-VM                                             2.0.0.0    Hyper-V
Cmdlet          Get-VMAssignableDevice                             2.0.0.0    Hyper-V
Cmdlet          Get-VMBios                                         2.0.0.0    Hyper-V
Cmdlet          Get-VMComPort                                      2.0.0.0    Hyper-V
Cmdlet          Get-VMConnectAccess                                2.0.0.0    Hyper-V
Cmdlet          Get-VMDvdDrive                                     2.0.0.0    Hyper-V
Cmdlet          Get-VMFibreChannelHba                              2.0.0.0    Hyper-V
Cmdlet          Get-VMFirmware                                     2.0.0.0    Hyper-V
Cmdlet          Get-VMFloppyDiskDrive                              2.0.0.0    Hyper-V
Cmdlet          Get-VMGpuPartitionAdapter                          2.0.0.0    Hyper-V
Cmdlet          Get-VMGroup                                        2.0.0.0    Hyper-V
Cmdlet          Get-VMHardDiskDrive                                2.0.0.0    Hyper-V
Cmdlet          Get-VMHost                                         2.0.0.0    Hyper-V
Cmdlet          Get-VMHostAssignableDevice                         2.0.0.0    Hyper-V
Cmdlet          Get-VMHostCluster                                  2.0.0.0    Hyper-V
Cmdlet          Get-VMHostNumaNode                                 2.0.0.0    Hyper-V
Cmdlet          Get-VMHostNumaNodeStatus                           2.0.0.0    Hyper-V
Cmdlet          Get-VMHostSupportedVersion                         2.0.0.0    Hyper-V
Cmdlet          Get-VMIdeController                                2.0.0.0    Hyper-V
Cmdlet          Get-VMIntegrationService                           2.0.0.0    Hyper-V
Cmdlet          Get-VMKeyProtector                                 2.0.0.0    Hyper-V
Cmdlet          Get-VMKeyStorageDrive                              2.0.0.0    Hyper-V
Cmdlet          Get-VMMemory                                       2.0.0.0    Hyper-V
Cmdlet          Get-VMMigrationNetwork                             2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapter                               2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterAcl                            2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterExtendedAcl                    2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterFailoverConfiguration          2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterIsolation                      2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterRdma                           2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterRoutingDomainMapping           2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterTeamMapping                    2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterVlan                           2.0.0.0    Hyper-V
Cmdlet          Get-VMPartitionableGpu                             2.0.0.0    Hyper-V
Cmdlet          Get-VMPmemController                               2.0.0.0    Hyper-V
Cmdlet          Get-VMProcessor                                    2.0.0.0    Hyper-V
Cmdlet          Get-VMRemoteFx3dVideoAdapter                       2.0.0.0    Hyper-V
Cmdlet          Get-VMRemoteFXPhysicalVideoAdapter                 2.0.0.0    Hyper-V
Cmdlet          Get-VMReplication                                  2.0.0.0    Hyper-V
Cmdlet          Get-VMReplicationAuthorizationEntry                2.0.0.0    Hyper-V
Cmdlet          Get-VMReplicationServer                            2.0.0.0    Hyper-V
Cmdlet          Get-VMResourcePool                                 2.0.0.0    Hyper-V
Cmdlet          Get-VMSan                                          2.0.0.0    Hyper-V
Cmdlet          Get-VMScsiController                               2.0.0.0    Hyper-V
Cmdlet          Get-VMSecurity                                     2.0.0.0    Hyper-V
Cmdlet          Get-VMSnapshot                                     2.0.0.0    Hyper-V
Cmdlet          Get-VMStoragePath                                  2.0.0.0    Hyper-V
Cmdlet          Get-VMStorageSettings                              2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitch                                       2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitchExtension                              2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitchExtensionPortData                      2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitchExtensionPortFeature                   2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitchExtensionSwitchData                    2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitchExtensionSwitchFeature                 2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitchTeam                                   2.0.0.0    Hyper-V
Cmdlet          Get-VMSystemSwitchExtension                        2.0.0.0    Hyper-V
Cmdlet          Get-VMSystemSwitchExtensionPortFeature             2.0.0.0    Hyper-V
Cmdlet          Get-VMSystemSwitchExtensionSwitchFeature           2.0.0.0    Hyper-V
Cmdlet          Get-VMVideo                                        2.0.0.0    Hyper-V
Cmdlet          Get-WheaMemoryPolicy                               2.0.0.0    Whea
Cmdlet          Get-WIMBootEntry                                   3.0        Dism
Cmdlet          Get-WinAcceptLanguageFromLanguageListOptOut        2.0.0.0    International
Cmdlet          Get-WinCultureFromLanguageListOptOut               2.0.0.0    International
Cmdlet          Get-WinDefaultInputMethodOverride                  2.0.0.0    International
Cmdlet          Get-WindowsCapability                              3.0        Dism
Cmdlet          Get-WindowsDeveloperLicense                        1.0.0.0    WindowsDeve...
Cmdlet          Get-WindowsDriver                                  3.0        Dism
Cmdlet          Get-WindowsEdition                                 3.0        Dism
Cmdlet          Get-WindowsErrorReporting                          1.0        WindowsErro...
Cmdlet          Get-WindowsImage                                   3.0        Dism
Cmdlet          Get-WindowsImageContent                            3.0        Dism
Cmdlet          Get-WindowsOptionalFeature                         3.0        Dism
Cmdlet          Get-WindowsPackage                                 3.0        Dism
Cmdlet          Get-WindowsSearchSetting                           1.0.0.0    WindowsSearch
Cmdlet          Get-WinEvent                                       3.0.0.0    Microsoft.P...
Cmdlet          Get-WinHomeLocation                                2.0.0.0    International
Cmdlet          Get-WinLanguageBarOption                           2.0.0.0    International
Cmdlet          Get-WinSystemLocale                                2.0.0.0    International
Cmdlet          Get-WinUILanguageOverride                          2.0.0.0    International
Cmdlet          Get-WinUserLanguageList                            2.0.0.0    International
Cmdlet          Get-WmiObject                                      3.1.0.0    Microsoft.P...
Cmdlet          Get-WSManCredSSP                                   3.0.0.0    Microsoft.W...
Cmdlet          Get-WSManInstance                                  3.0.0.0    Microsoft.W...
Cmdlet          Grant-VMConnectAccess                              2.0.0.0    Hyper-V
Cmdlet          Group-Object                                       3.1.0.0    Microsoft.P...
Cmdlet          Import-Alias                                       3.1.0.0    Microsoft.P...
Cmdlet          Import-BinaryMiLog                                 1.0.0.0    CimCmdlets
Cmdlet          Import-Certificate                                 1.0.0.0    PKI
Cmdlet          Import-Clixml                                      3.1.0.0    Microsoft.P...
Cmdlet          Import-Counter                                     3.0.0.0    Microsoft.P...
Cmdlet          Import-Csv                                         3.1.0.0    Microsoft.P...
Cmdlet          Import-LocalizedData                               3.1.0.0    Microsoft.P...
Cmdlet          Import-Module                                      3.0.0.0    Microsoft.P...
Cmdlet          Import-PackageProvider                             1.0.0.1    PackageMana...
Cmdlet          Import-PfxCertificate                              1.0.0.0    PKI
Cmdlet          Import-PSSession                                   3.1.0.0    Microsoft.P...
Cmdlet          Import-StartLayout                                 1.0.0.0    StartLayout
Cmdlet          Import-TpmOwnerAuth                                2.0.0.0    TrustedPlat...
Cmdlet          Import-UevConfiguration                            2.1.639.0  UEV
Cmdlet          Import-VM                                          2.0.0.0    Hyper-V
Cmdlet          Import-VMInitialReplication                        2.0.0.0    Hyper-V
Cmdlet          Initialize-PmemPhysicalDevice                      1.0.0.0    PersistentM...
Cmdlet          Initialize-Tpm                                     2.0.0.0    TrustedPlat...
Cmdlet          Install-Package                                    1.0.0.1    PackageMana...
Cmdlet          Install-PackageProvider                            1.0.0.1    PackageMana...
Cmdlet          Install-ProvisioningPackage                        3.0        Provisioning
Cmdlet          Install-TrustedProvisioningCertificate             3.0        Provisioning
Cmdlet          Invoke-CimMethod                                   1.0.0.0    CimCmdlets
Cmdlet          Invoke-Command                                     3.0.0.0    Microsoft.P...
Cmdlet          Invoke-CommandInDesktopPackage                     2.0.1.0    Appx
Cmdlet          Invoke-DscResource                                 1.1        PSDesiredSt...
Cmdlet          Invoke-Expression                                  3.1.0.0    Microsoft.P...
Cmdlet          Invoke-History                                     3.0.0.0    Microsoft.P...
Cmdlet          Invoke-Item                                        3.1.0.0    Microsoft.P...
Cmdlet          Invoke-RestMethod                                  3.1.0.0    Microsoft.P...
Cmdlet          Invoke-TroubleshootingPack                         1.0.0.0    Troubleshoo...
Cmdlet          Invoke-WebRequest                                  3.1.0.0    Microsoft.P...
Cmdlet          Invoke-WmiMethod                                   3.1.0.0    Microsoft.P...
Cmdlet          Invoke-WSManAction                                 3.0.0.0    Microsoft.W...
Cmdlet          Join-DtcDiagnosticResourceManager                  1.0.0.0    MsDtc
Cmdlet          Join-Path                                          3.1.0.0    Microsoft.P...
Cmdlet          Limit-EventLog                                     3.1.0.0    Microsoft.P...
Cmdlet          Measure-Command                                    3.1.0.0    Microsoft.P...
Cmdlet          Measure-Object                                     3.1.0.0    Microsoft.P...
Cmdlet          Measure-VM                                         2.0.0.0    Hyper-V
Cmdlet          Measure-VMReplication                              2.0.0.0    Hyper-V
Cmdlet          Measure-VMResourcePool                             2.0.0.0    Hyper-V
Cmdlet          Merge-CIPolicy                                     1.0        ConfigCI
Cmdlet          Merge-VHD                                          2.0.0.0    Hyper-V
Cmdlet          Mount-AppvClientConnectionGroup                    1.0.0.0    AppvClient
Cmdlet          Mount-AppvClientPackage                            1.0.0.0    AppvClient
Cmdlet          Mount-AppxVolume                                   2.0.1.0    Appx
Cmdlet          Mount-VHD                                          2.0.0.0    Hyper-V
Cmdlet          Mount-VMHostAssignableDevice                       2.0.0.0    Hyper-V
Cmdlet          Mount-WindowsImage                                 3.0        Dism
Cmdlet          Move-AppxPackage                                   2.0.1.0    Appx
Cmdlet          Move-Item                                          3.1.0.0    Microsoft.P...
Cmdlet          Move-ItemProperty                                  3.1.0.0    Microsoft.P...
Cmdlet          Move-VM                                            2.0.0.0    Hyper-V
Cmdlet          Move-VMStorage                                     2.0.0.0    Hyper-V
Cmdlet          New-Alias                                          3.1.0.0    Microsoft.P...
Cmdlet          New-AppLockerPolicy                                2.0.0.0    AppLocker
Cmdlet          New-CertificateNotificationTask                    1.0.0.0    PKI
Cmdlet          New-CimInstance                                    1.0.0.0    CimCmdlets
Cmdlet          New-CimSession                                     1.0.0.0    CimCmdlets
Cmdlet          New-CimSessionOption                               1.0.0.0    CimCmdlets
Cmdlet          New-CIPolicy                                       1.0        ConfigCI
Cmdlet          New-CIPolicyRule                                   1.0        ConfigCI
Cmdlet          New-DtcDiagnosticTransaction                       1.0.0.0    MsDtc
Cmdlet          New-Event                                          3.1.0.0    Microsoft.P...
Cmdlet          New-EventLog                                       3.1.0.0    Microsoft.P...
Cmdlet          New-FileCatalog                                    3.0.0.0    Microsoft.P...
Cmdlet          New-HgsTraceTarget                                 1.0.0.0    HgsDiagnostics
Cmdlet          New-Item                                           3.1.0.0    Microsoft.P...
Cmdlet          New-ItemProperty                                   3.1.0.0    Microsoft.P...
Cmdlet          New-JobTrigger                                     1.1.0.0    PSScheduledJob
Cmdlet          New-LocalGroup                                     1.0.0.0    Microsoft.P...
Cmdlet          New-LocalUser                                      1.0.0.0    Microsoft.P...
Cmdlet          New-Module                                         3.0.0.0    Microsoft.P...
Cmdlet          New-ModuleManifest                                 3.0.0.0    Microsoft.P...
Cmdlet          New-NetIPsecAuthProposal                           2.0.0.0    NetSecurity
Cmdlet          New-NetIPsecMainModeCryptoProposal                 2.0.0.0    NetSecurity
Cmdlet          New-NetIPsecQuickModeCryptoProposal                2.0.0.0    NetSecurity
Cmdlet          New-Object                                         3.1.0.0    Microsoft.P...
Cmdlet          New-PmemDisk                                       1.0.0.0    PersistentM...
Cmdlet          New-ProvisioningRepro                              3.0        Provisioning
Cmdlet          New-PSDrive                                        3.1.0.0    Microsoft.P...
Cmdlet          New-PSRoleCapabilityFile                           3.0.0.0    Microsoft.P...
Cmdlet          New-PSSession                                      3.0.0.0    Microsoft.P...
Cmdlet          New-PSSessionConfigurationFile                     3.0.0.0    Microsoft.P...
Cmdlet          New-PSSessionOption                                3.0.0.0    Microsoft.P...
Cmdlet          New-PSTransportOption                              3.0.0.0    Microsoft.P...
Cmdlet          New-PSWorkflowExecutionOption                      2.0.0.0    PSWorkflow
Cmdlet          New-ScheduledJobOption                             1.1.0.0    PSScheduledJob
Cmdlet          New-SelfSignedCertificate                          1.0.0.0    PKI
Cmdlet          New-Service                                        3.1.0.0    Microsoft.P...
Cmdlet          New-TimeSpan                                       3.1.0.0    Microsoft.P...
Cmdlet          New-TlsSessionTicketKey                            2.0.0.0    TLS
Cmdlet          New-Variable                                       3.1.0.0    Microsoft.P...
Cmdlet          New-VFD                                            2.0.0.0    Hyper-V
Cmdlet          New-VHD                                            2.0.0.0    Hyper-V
Cmdlet          New-VM                                             2.0.0.0    Hyper-V
Cmdlet          New-VMGroup                                        2.0.0.0    Hyper-V
Cmdlet          New-VMReplicationAuthorizationEntry                2.0.0.0    Hyper-V
Cmdlet          New-VMResourcePool                                 2.0.0.0    Hyper-V
Cmdlet          New-VMSan                                          2.0.0.0    Hyper-V
Cmdlet          New-VMSwitch                                       2.0.0.0    Hyper-V
Cmdlet          New-WebServiceProxy                                3.1.0.0    Microsoft.P...
Cmdlet          New-WindowsCustomImage                             3.0        Dism
Cmdlet          New-WindowsImage                                   3.0        Dism
Cmdlet          New-WinEvent                                       3.0.0.0    Microsoft.P...
Cmdlet          New-WinUserLanguageList                            2.0.0.0    International
Cmdlet          New-WSManInstance                                  3.0.0.0    Microsoft.W...
Cmdlet          New-WSManSessionOption                             3.0.0.0    Microsoft.W...
Cmdlet          Optimize-AppxProvisionedPackages                   3.0        Dism
Cmdlet          Optimize-VHD                                       2.0.0.0    Hyper-V
Cmdlet          Optimize-VHDSet                                    2.0.0.0    Hyper-V
Cmdlet          Optimize-WindowsImage                              3.0        Dism
Cmdlet          Out-Default                                        3.0.0.0    Microsoft.P...
Cmdlet          Out-File                                           3.1.0.0    Microsoft.P...
Cmdlet          Out-GridView                                       3.1.0.0    Microsoft.P...
Cmdlet          Out-Host                                           3.0.0.0    Microsoft.P...
Cmdlet          Out-Null                                           3.0.0.0    Microsoft.P...
Cmdlet          Out-Printer                                        3.1.0.0    Microsoft.P...
Cmdlet          Out-String                                         3.1.0.0    Microsoft.P...
Cmdlet          Pop-Location                                       3.1.0.0    Microsoft.P...
Cmdlet          Protect-CmsMessage                                 3.0.0.0    Microsoft.P...
Cmdlet          Publish-AppvClientPackage                          1.0.0.0    AppvClient
Cmdlet          Publish-DscConfiguration                           1.1        PSDesiredSt...
Cmdlet          Push-Location                                      3.1.0.0    Microsoft.P...
Cmdlet          Read-Host                                          3.1.0.0    Microsoft.P...
Cmdlet          Receive-DtcDiagnosticTransaction                   1.0.0.0    MsDtc
Cmdlet          Receive-Job                                        3.0.0.0    Microsoft.P...
Cmdlet          Receive-PSSession                                  3.0.0.0    Microsoft.P...
Cmdlet          Register-ArgumentCompleter                         3.0.0.0    Microsoft.P...
Cmdlet          Register-CimIndicationEvent                        1.0.0.0    CimCmdlets
Cmdlet          Register-EngineEvent                               3.1.0.0    Microsoft.P...
Cmdlet          Register-ObjectEvent                               3.1.0.0    Microsoft.P...
Cmdlet          Register-PackageSource                             1.0.0.1    PackageMana...
Cmdlet          Register-PSSessionConfiguration                    3.0.0.0    Microsoft.P...
Cmdlet          Register-ScheduledJob                              1.1.0.0    PSScheduledJob
Cmdlet          Register-UevTemplate                               2.1.639.0  UEV
Cmdlet          Register-WmiEvent                                  3.1.0.0    Microsoft.P...
Cmdlet          Remove-AppvClientConnectionGroup                   1.0.0.0    AppvClient
Cmdlet          Remove-AppvClientPackage                           1.0.0.0    AppvClient
Cmdlet          Remove-AppvPublishingServer                        1.0.0.0    AppvClient
Cmdlet          Remove-AppxPackage                                 2.0.1.0    Appx
Cmdlet          Remove-AppxProvisionedPackage                      3.0        Dism
Cmdlet          Remove-AppxVolume                                  2.0.1.0    Appx
Cmdlet          Remove-BitsTransfer                                2.0.0.0    BitsTransfer
Cmdlet          Remove-CertificateEnrollmentPolicyServer           1.0.0.0    PKI
Cmdlet          Remove-CertificateNotificationTask                 1.0.0.0    PKI
Cmdlet          Remove-CimInstance                                 1.0.0.0    CimCmdlets
Cmdlet          Remove-CimSession                                  1.0.0.0    CimCmdlets
Cmdlet          Remove-CIPolicyRule                                1.0        ConfigCI
Cmdlet          Remove-Computer                                    3.1.0.0    Microsoft.P...
Cmdlet          Remove-Event                                       3.1.0.0    Microsoft.P...
Cmdlet          Remove-EventLog                                    3.1.0.0    Microsoft.P...
Cmdlet          Remove-Item                                        3.1.0.0    Microsoft.P...
Cmdlet          Remove-ItemProperty                                3.1.0.0    Microsoft.P...
Cmdlet          Remove-Job                                         3.0.0.0    Microsoft.P...
Cmdlet          Remove-JobTrigger                                  1.1.0.0    PSScheduledJob
Cmdlet          Remove-LocalGroup                                  1.0.0.0    Microsoft.P...
Cmdlet          Remove-LocalGroupMember                            1.0.0.0    Microsoft.P...
Cmdlet          Remove-LocalUser                                   1.0.0.0    Microsoft.P...
Cmdlet          Remove-Module                                      3.0.0.0    Microsoft.P...
Cmdlet          Remove-PmemDisk                                    1.0.0.0    PersistentM...
Cmdlet          Remove-PSBreakpoint                                3.1.0.0    Microsoft.P...
Cmdlet          Remove-PSDrive                                     3.1.0.0    Microsoft.P...
Cmdlet          Remove-PSReadLineKeyHandler                        2.0.0      PSReadline
Cmdlet          Remove-PSSession                                   3.0.0.0    Microsoft.P...
Cmdlet          Remove-PSSnapin                                    3.0.0.0    Microsoft.P...
Cmdlet          Remove-TypeData                                    3.1.0.0    Microsoft.P...
Cmdlet          Remove-Variable                                    3.1.0.0    Microsoft.P...
Cmdlet          Remove-VHDSnapshot                                 2.0.0.0    Hyper-V
Cmdlet          Remove-VM                                          2.0.0.0    Hyper-V
Cmdlet          Remove-VMAssignableDevice                          2.0.0.0    Hyper-V
Cmdlet          Remove-VMDvdDrive                                  2.0.0.0    Hyper-V
Cmdlet          Remove-VMFibreChannelHba                           2.0.0.0    Hyper-V
Cmdlet          Remove-VMGpuPartitionAdapter                       2.0.0.0    Hyper-V
Cmdlet          Remove-VMGroup                                     2.0.0.0    Hyper-V
Cmdlet          Remove-VMGroupMember                               2.0.0.0    Hyper-V
Cmdlet          Remove-VMHardDiskDrive                             2.0.0.0    Hyper-V
Cmdlet          Remove-VMHostAssignableDevice                      2.0.0.0    Hyper-V
Cmdlet          Remove-VMKeyStorageDrive                           2.0.0.0    Hyper-V
Cmdlet          Remove-VMMigrationNetwork                          2.0.0.0    Hyper-V
Cmdlet          Remove-VMNetworkAdapter                            2.0.0.0    Hyper-V
Cmdlet          Remove-VMNetworkAdapterAcl                         2.0.0.0    Hyper-V
Cmdlet          Remove-VMNetworkAdapterExtendedAcl                 2.0.0.0    Hyper-V
Cmdlet          Remove-VMNetworkAdapterRoutingDomainMapping        2.0.0.0    Hyper-V
Cmdlet          Remove-VMNetworkAdapterTeamMapping                 2.0.0.0    Hyper-V
Cmdlet          Remove-VMPmemController                            2.0.0.0    Hyper-V
Cmdlet          Remove-VMRemoteFx3dVideoAdapter                    2.0.0.0    Hyper-V
Cmdlet          Remove-VMReplication                               2.0.0.0    Hyper-V
Cmdlet          Remove-VMReplicationAuthorizationEntry             2.0.0.0    Hyper-V
Cmdlet          Remove-VMResourcePool                              2.0.0.0    Hyper-V
Cmdlet          Remove-VMSan                                       2.0.0.0    Hyper-V
Cmdlet          Remove-VMSavedState                                2.0.0.0    Hyper-V
Cmdlet          Remove-VMScsiController                            2.0.0.0    Hyper-V
Cmdlet          Remove-VMSnapshot                                  2.0.0.0    Hyper-V
Cmdlet          Remove-VMStoragePath                               2.0.0.0    Hyper-V
Cmdlet          Remove-VMSwitch                                    2.0.0.0    Hyper-V
Cmdlet          Remove-VMSwitchExtensionPortFeature                2.0.0.0    Hyper-V
Cmdlet          Remove-VMSwitchExtensionSwitchFeature              2.0.0.0    Hyper-V
Cmdlet          Remove-VMSwitchTeamMember                          2.0.0.0    Hyper-V
Cmdlet          Remove-WindowsCapability                           3.0        Dism
Cmdlet          Remove-WindowsDriver                               3.0        Dism
Cmdlet          Remove-WindowsImage                                3.0        Dism
Cmdlet          Remove-WindowsPackage                              3.0        Dism
Cmdlet          Remove-WmiObject                                   3.1.0.0    Microsoft.P...
Cmdlet          Remove-WSManInstance                               3.0.0.0    Microsoft.W...
Cmdlet          Rename-Computer                                    3.1.0.0    Microsoft.P...
Cmdlet          Rename-Item                                        3.1.0.0    Microsoft.P...
Cmdlet          Rename-ItemProperty                                3.1.0.0    Microsoft.P...
Cmdlet          Rename-LocalGroup                                  1.0.0.0    Microsoft.P...
Cmdlet          Rename-LocalUser                                   1.0.0.0    Microsoft.P...
Cmdlet          Rename-VM                                          2.0.0.0    Hyper-V
Cmdlet          Rename-VMGroup                                     2.0.0.0    Hyper-V
Cmdlet          Rename-VMNetworkAdapter                            2.0.0.0    Hyper-V
Cmdlet          Rename-VMResourcePool                              2.0.0.0    Hyper-V
Cmdlet          Rename-VMSan                                       2.0.0.0    Hyper-V
Cmdlet          Rename-VMSnapshot                                  2.0.0.0    Hyper-V
Cmdlet          Rename-VMSwitch                                    2.0.0.0    Hyper-V
Cmdlet          Repair-AppvClientConnectionGroup                   1.0.0.0    AppvClient
Cmdlet          Repair-AppvClientPackage                           1.0.0.0    AppvClient
Cmdlet          Repair-UevTemplateIndex                            2.1.639.0  UEV
Cmdlet          Repair-VM                                          2.0.0.0    Hyper-V
Cmdlet          Repair-WindowsImage                                3.0        Dism
Cmdlet          Reset-ComputerMachinePassword                      3.1.0.0    Microsoft.P...
Cmdlet          Reset-VMReplicationStatistics                      2.0.0.0    Hyper-V
Cmdlet          Reset-VMResourceMetering                           2.0.0.0    Hyper-V
Cmdlet          Resize-VHD                                         2.0.0.0    Hyper-V
Cmdlet          Resolve-DnsName                                    1.0.0.0    DnsClient
Cmdlet          Resolve-Path                                       3.1.0.0    Microsoft.P...
Cmdlet          Restart-Computer                                   3.1.0.0    Microsoft.P...
Cmdlet          Restart-Service                                    3.1.0.0    Microsoft.P...
Cmdlet          Restart-VM                                         2.0.0.0    Hyper-V
Cmdlet          Restore-Computer                                   3.1.0.0    Microsoft.P...
Cmdlet          Restore-UevBackup                                  2.1.639.0  UEV
Cmdlet          Restore-UevUserSetting                             2.1.639.0  UEV
Cmdlet          Restore-VMSnapshot                                 2.0.0.0    Hyper-V
Cmdlet          Resume-BitsTransfer                                2.0.0.0    BitsTransfer
Cmdlet          Resume-Job                                         3.0.0.0    Microsoft.P...
Cmdlet          Resume-ProvisioningSession                         3.0        Provisioning
Cmdlet          Resume-Service                                     3.1.0.0    Microsoft.P...
Cmdlet          Resume-VM                                          2.0.0.0    Hyper-V
Cmdlet          Resume-VMReplication                               2.0.0.0    Hyper-V
Cmdlet          Revoke-VMConnectAccess                             2.0.0.0    Hyper-V
Cmdlet          Save-Help                                          3.0.0.0    Microsoft.P...
Cmdlet          Save-Package                                       1.0.0.1    PackageMana...
Cmdlet          Save-VM                                            2.0.0.0    Hyper-V
Cmdlet          Save-WindowsImage                                  3.0        Dism
Cmdlet          Select-Object                                      3.1.0.0    Microsoft.P...
Cmdlet          Select-String                                      3.1.0.0    Microsoft.P...
Cmdlet          Select-Xml                                         3.1.0.0    Microsoft.P...
Cmdlet          Send-AppvClientReport                              1.0.0.0    AppvClient
Cmdlet          Send-DtcDiagnosticTransaction                      1.0.0.0    MsDtc
Cmdlet          Send-MailMessage                                   3.1.0.0    Microsoft.P...
Cmdlet          Set-Acl                                            3.0.0.0    Microsoft.P...
Cmdlet          Set-Alias                                          3.1.0.0    Microsoft.P...
Cmdlet          Set-AppBackgroundTaskResourcePolicy                1.0.0.0    AppBackgrou...
Cmdlet          Set-AppLockerPolicy                                2.0.0.0    AppLocker
Cmdlet          Set-AppvClientConfiguration                        1.0.0.0    AppvClient
Cmdlet          Set-AppvClientMode                                 1.0.0.0    AppvClient
Cmdlet          Set-AppvClientPackage                              1.0.0.0    AppvClient
Cmdlet          Set-AppvPublishingServer                           1.0.0.0    AppvClient
Cmdlet          Set-AppxDefaultVolume                              2.0.1.0    Appx
Cmdlet          Set-AppXProvisionedDataFile                        3.0        Dism
Cmdlet          Set-AuthenticodeSignature                          3.0.0.0    Microsoft.P...
Cmdlet          Set-BitsTransfer                                   2.0.0.0    BitsTransfer
Cmdlet          Set-CertificateAutoEnrollmentPolicy                1.0.0.0    PKI
Cmdlet          Set-CimInstance                                    1.0.0.0    CimCmdlets
Cmdlet          Set-CIPolicyIdInfo                                 1.0        ConfigCI
Cmdlet          Set-CIPolicySetting                                1.0        ConfigCI
Cmdlet          Set-CIPolicyVersion                                1.0        ConfigCI
Cmdlet          Set-Clipboard                                      3.1.0.0    Microsoft.P...
Cmdlet          Set-Content                                        3.1.0.0    Microsoft.P...
Cmdlet          Set-Culture                                        2.0.0.0    International
Cmdlet          Set-Date                                           3.1.0.0    Microsoft.P...
Cmdlet          Set-DeliveryOptimizationStatus                     1.0.2.0    DeliveryOpt...
Cmdlet          Set-DODownloadMode                                 1.0.2.0    DeliveryOpt...
Cmdlet          Set-DOPercentageMaxBackgroundBandwidth             1.0.2.0    DeliveryOpt...
Cmdlet          Set-DOPercentageMaxForegroundBandwidth             1.0.2.0    DeliveryOpt...
Cmdlet          Set-DscLocalConfigurationManager                   1.1        PSDesiredSt...
Cmdlet          Set-ExecutionPolicy                                3.0.0.0    Microsoft.P...
Cmdlet          Set-HVCIOptions                                    1.0        ConfigCI
Cmdlet          Set-Item                                           3.1.0.0    Microsoft.P...
Cmdlet          Set-ItemProperty                                   3.1.0.0    Microsoft.P...
Cmdlet          Set-JobTrigger                                     1.1.0.0    PSScheduledJob
Cmdlet          Set-KdsConfiguration                               1.0.0.0    Kds
Cmdlet          Set-LocalGroup                                     1.0.0.0    Microsoft.P...
Cmdlet          Set-LocalUser                                      1.0.0.0    Microsoft.P...
Cmdlet          Set-Location                                       3.1.0.0    Microsoft.P...
Cmdlet          Set-NonRemovableAppsPolicy                         3.0        Dism
Cmdlet          Set-PackageSource                                  1.0.0.1    PackageMana...
Cmdlet          Set-ProcessMitigation                              1.0.11     ProcessMiti...
Cmdlet          Set-PSBreakpoint                                   3.1.0.0    Microsoft.P...
Cmdlet          Set-PSDebug                                        3.0.0.0    Microsoft.P...
Cmdlet          Set-PSReadLineKeyHandler                           2.0.0      PSReadline
Cmdlet          Set-PSReadLineOption                               2.0.0      PSReadline
Cmdlet          Set-PSSessionConfiguration                         3.0.0.0    Microsoft.P...
Cmdlet          Set-RuleOption                                     1.0        ConfigCI
Cmdlet          Set-ScheduledJob                                   1.1.0.0    PSScheduledJob
Cmdlet          Set-ScheduledJobOption                             1.1.0.0    PSScheduledJob
Cmdlet          Set-SecureBootUEFI                                 2.0.0.0    SecureBoot
Cmdlet          Set-Service                                        3.1.0.0    Microsoft.P...
Cmdlet          Set-StrictMode                                     3.0.0.0    Microsoft.P...
Cmdlet          Set-TimeZone                                       3.1.0.0    Microsoft.P...
Cmdlet          Set-TpmOwnerAuth                                   2.0.0.0    TrustedPlat...
Cmdlet          Set-TraceSource                                    3.1.0.0    Microsoft.P...
Cmdlet          Set-UevConfiguration                               2.1.639.0  UEV
Cmdlet          Set-UevTemplateProfile                             2.1.639.0  UEV
Cmdlet          Set-Variable                                       3.1.0.0    Microsoft.P...
Cmdlet          Set-VHD                                            2.0.0.0    Hyper-V
Cmdlet          Set-VM                                             2.0.0.0    Hyper-V
Cmdlet          Set-VMBios                                         2.0.0.0    Hyper-V
Cmdlet          Set-VMComPort                                      2.0.0.0    Hyper-V
Cmdlet          Set-VMDvdDrive                                     2.0.0.0    Hyper-V
Cmdlet          Set-VMFibreChannelHba                              2.0.0.0    Hyper-V
Cmdlet          Set-VMFirmware                                     2.0.0.0    Hyper-V
Cmdlet          Set-VMFloppyDiskDrive                              2.0.0.0    Hyper-V
Cmdlet          Set-VMGpuPartitionAdapter                          2.0.0.0    Hyper-V
Cmdlet          Set-VMHardDiskDrive                                2.0.0.0    Hyper-V
Cmdlet          Set-VMHost                                         2.0.0.0    Hyper-V
Cmdlet          Set-VMHostCluster                                  2.0.0.0    Hyper-V
Cmdlet          Set-VMKeyProtector                                 2.0.0.0    Hyper-V
Cmdlet          Set-VMKeyStorageDrive                              2.0.0.0    Hyper-V
Cmdlet          Set-VMMemory                                       2.0.0.0    Hyper-V
Cmdlet          Set-VMMigrationNetwork                             2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapter                               2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapterFailoverConfiguration          2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapterIsolation                      2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapterRdma                           2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapterRoutingDomainMapping           2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapterTeamMapping                    2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapterVlan                           2.0.0.0    Hyper-V
Cmdlet          Set-VMPartitionableGpu                             2.0.0.0    Hyper-V
Cmdlet          Set-VMProcessor                                    2.0.0.0    Hyper-V
Cmdlet          Set-VMRemoteFx3dVideoAdapter                       2.0.0.0    Hyper-V
Cmdlet          Set-VMReplication                                  2.0.0.0    Hyper-V
Cmdlet          Set-VMReplicationAuthorizationEntry                2.0.0.0    Hyper-V
Cmdlet          Set-VMReplicationServer                            2.0.0.0    Hyper-V
Cmdlet          Set-VMResourcePool                                 2.0.0.0    Hyper-V
Cmdlet          Set-VMSan                                          2.0.0.0    Hyper-V
Cmdlet          Set-VMSecurity                                     2.0.0.0    Hyper-V
Cmdlet          Set-VMSecurityPolicy                               2.0.0.0    Hyper-V
Cmdlet          Set-VMStorageSettings                              2.0.0.0    Hyper-V
Cmdlet          Set-VMSwitch                                       2.0.0.0    Hyper-V
Cmdlet          Set-VMSwitchExtensionPortFeature                   2.0.0.0    Hyper-V
Cmdlet          Set-VMSwitchExtensionSwitchFeature                 2.0.0.0    Hyper-V
Cmdlet          Set-VMSwitchTeam                                   2.0.0.0    Hyper-V
Cmdlet          Set-VMVideo                                        2.0.0.0    Hyper-V
Cmdlet          Set-WheaMemoryPolicy                               2.0.0.0    Whea
Cmdlet          Set-WinAcceptLanguageFromLanguageListOptOut        2.0.0.0    International
Cmdlet          Set-WinCultureFromLanguageListOptOut               2.0.0.0    International
Cmdlet          Set-WinDefaultInputMethodOverride                  2.0.0.0    International
Cmdlet          Set-WindowsEdition                                 3.0        Dism
Cmdlet          Set-WindowsProductKey                              3.0        Dism
Cmdlet          Set-WindowsSearchSetting                           1.0.0.0    WindowsSearch
Cmdlet          Set-WinHomeLocation                                2.0.0.0    International
Cmdlet          Set-WinLanguageBarOption                           2.0.0.0    International
Cmdlet          Set-WinSystemLocale                                2.0.0.0    International
Cmdlet          Set-WinUILanguageOverride                          2.0.0.0    International
Cmdlet          Set-WinUserLanguageList                            2.0.0.0    International
Cmdlet          Set-WmiInstance                                    3.1.0.0    Microsoft.P...
Cmdlet          Set-WSManInstance                                  3.0.0.0    Microsoft.W...
Cmdlet          Set-WSManQuickConfig                               3.0.0.0    Microsoft.W...
Cmdlet          Show-Command                                       3.1.0.0    Microsoft.P...
Cmdlet          Show-ControlPanelItem                              3.1.0.0    Microsoft.P...
Cmdlet          Show-EventLog                                      3.1.0.0    Microsoft.P...
Cmdlet          Show-WindowsDeveloperLicenseRegistration           1.0.0.0    WindowsDeve...
Cmdlet          Sort-Object                                        3.1.0.0    Microsoft.P...
Cmdlet          Split-Path                                         3.1.0.0    Microsoft.P...
Cmdlet          Split-WindowsImage                                 3.0        Dism
Cmdlet          Start-BitsTransfer                                 2.0.0.0    BitsTransfer
Cmdlet          Start-DscConfiguration                             1.1        PSDesiredSt...
Cmdlet          Start-DtcDiagnosticResourceManager                 1.0.0.0    MsDtc
Cmdlet          Start-Job                                          3.0.0.0    Microsoft.P...
Cmdlet          Start-OSUninstall                                  3.0        Dism
Cmdlet          Start-Process                                      3.1.0.0    Microsoft.P...
Cmdlet          Start-Service                                      3.1.0.0    Microsoft.P...
Cmdlet          Start-Sleep                                        3.1.0.0    Microsoft.P...
Cmdlet          Start-Transaction                                  3.1.0.0    Microsoft.P...
Cmdlet          Start-Transcript                                   3.0.0.0    Microsoft.P...
Cmdlet          Start-VM                                           2.0.0.0    Hyper-V
Cmdlet          Start-VMFailover                                   2.0.0.0    Hyper-V
Cmdlet          Start-VMInitialReplication                         2.0.0.0    Hyper-V
Cmdlet          Start-VMTrace                                      2.0.0.0    Hyper-V
Cmdlet          Stop-AppvClientConnectionGroup                     1.0.0.0    AppvClient
Cmdlet          Stop-AppvClientPackage                             1.0.0.0    AppvClient
Cmdlet          Stop-Computer                                      3.1.0.0    Microsoft.P...
Cmdlet          Stop-DtcDiagnosticResourceManager                  1.0.0.0    MsDtc
Cmdlet          Stop-Job                                           3.0.0.0    Microsoft.P...
Cmdlet          Stop-Process                                       3.1.0.0    Microsoft.P...
Cmdlet          Stop-Service                                       3.1.0.0    Microsoft.P...
Cmdlet          Stop-Transcript                                    3.0.0.0    Microsoft.P...
Cmdlet          Stop-VM                                            2.0.0.0    Hyper-V
Cmdlet          Stop-VMFailover                                    2.0.0.0    Hyper-V
Cmdlet          Stop-VMInitialReplication                          2.0.0.0    Hyper-V
Cmdlet          Stop-VMReplication                                 2.0.0.0    Hyper-V
Cmdlet          Stop-VMTrace                                       2.0.0.0    Hyper-V
Cmdlet          Suspend-BitsTransfer                               2.0.0.0    BitsTransfer
Cmdlet          Suspend-Job                                        3.0.0.0    Microsoft.P...
Cmdlet          Suspend-Service                                    3.1.0.0    Microsoft.P...
Cmdlet          Suspend-VM                                         2.0.0.0    Hyper-V
Cmdlet          Suspend-VMReplication                              2.0.0.0    Hyper-V
Cmdlet          Switch-Certificate                                 1.0.0.0    PKI
Cmdlet          Sync-AppvPublishingServer                          1.0.0.0    AppvClient
Cmdlet          Tee-Object                                         3.1.0.0    Microsoft.P...
Cmdlet          Test-AppLockerPolicy                               2.0.0.0    AppLocker
Cmdlet          Test-Certificate                                   1.0.0.0    PKI
Cmdlet          Test-ComputerSecureChannel                         3.1.0.0    Microsoft.P...
Cmdlet          Test-Connection                                    3.1.0.0    Microsoft.P...
Cmdlet          Test-DscConfiguration                              1.1        PSDesiredSt...
Cmdlet          Test-FileCatalog                                   3.0.0.0    Microsoft.P...
Cmdlet          Test-HgsTraceTarget                                1.0.0.0    HgsDiagnostics
Cmdlet          Test-KdsRootKey                                    1.0.0.0    Kds
Cmdlet          Test-ModuleManifest                                3.0.0.0    Microsoft.P...
Cmdlet          Test-Path                                          3.1.0.0    Microsoft.P...
Cmdlet          Test-PSSessionConfigurationFile                    3.0.0.0    Microsoft.P...
Cmdlet          Test-UevTemplate                                   2.1.639.0  UEV
Cmdlet          Test-VHD                                           2.0.0.0    Hyper-V
Cmdlet          Test-VMNetworkAdapter                              2.0.0.0    Hyper-V
Cmdlet          Test-VMReplicationConnection                       2.0.0.0    Hyper-V
Cmdlet          Test-WSMan                                         3.0.0.0    Microsoft.W...
Cmdlet          Trace-Command                                      3.1.0.0    Microsoft.P...
Cmdlet          Unblock-File                                       3.1.0.0    Microsoft.P...
Cmdlet          Unblock-Tpm                                        2.0.0.0    TrustedPlat...
Cmdlet          Undo-DtcDiagnosticTransaction                      1.0.0.0    MsDtc
Cmdlet          Undo-Transaction                                   3.1.0.0    Microsoft.P...
Cmdlet          Uninstall-Package                                  1.0.0.1    PackageMana...
Cmdlet          Uninstall-ProvisioningPackage                      3.0        Provisioning
Cmdlet          Uninstall-TrustedProvisioningCertificate           3.0        Provisioning
Cmdlet          Unprotect-CmsMessage                               3.0.0.0    Microsoft.P...
Cmdlet          Unpublish-AppvClientPackage                        1.0.0.0    AppvClient
Cmdlet          Unregister-Event                                   3.1.0.0    Microsoft.P...
Cmdlet          Unregister-PackageSource                           1.0.0.1    PackageMana...
Cmdlet          Unregister-PSSessionConfiguration                  3.0.0.0    Microsoft.P...
Cmdlet          Unregister-ScheduledJob                            1.1.0.0    PSScheduledJob
Cmdlet          Unregister-UevTemplate                             2.1.639.0  UEV
Cmdlet          Unregister-WindowsDeveloperLicense                 1.0.0.0    WindowsDeve...
Cmdlet          Update-FormatData                                  3.1.0.0    Microsoft.P...
Cmdlet          Update-Help                                        3.0.0.0    Microsoft.P...
Cmdlet          Update-List                                        3.1.0.0    Microsoft.P...
Cmdlet          Update-TypeData                                    3.1.0.0    Microsoft.P...
Cmdlet          Update-UevTemplate                                 2.1.639.0  UEV
Cmdlet          Update-VMVersion                                   2.0.0.0    Hyper-V
Cmdlet          Update-WIMBootEntry                                3.0        Dism
Cmdlet          Use-Transaction                                    3.1.0.0    Microsoft.P...
Cmdlet          Use-WindowsUnattend                                3.0        Dism
Cmdlet          Wait-Debugger                                      3.1.0.0    Microsoft.P...
Cmdlet          Wait-Event                                         3.1.0.0    Microsoft.P...
Cmdlet          Wait-Job                                           3.0.0.0    Microsoft.P...
Cmdlet          Wait-Process                                       3.1.0.0    Microsoft.P...
Cmdlet          Wait-VM                                            2.0.0.0    Hyper-V
Cmdlet          Where-Object                                       3.0.0.0    Microsoft.P...
Cmdlet          Write-Debug                                        3.1.0.0    Microsoft.P...
Cmdlet          Write-Error                                        3.1.0.0    Microsoft.P...
Cmdlet          Write-EventLog                                     3.1.0.0    Microsoft.P...
Cmdlet          Write-Host                                         3.1.0.0    Microsoft.P...
Cmdlet          Write-Information                                  3.1.0.0    Microsoft.P...
Cmdlet          Write-Output                                       3.1.0.0    Microsoft.P...
Cmdlet          Write-Progress                                     3.1.0.0    Microsoft.P...
Cmdlet          Write-Verbose                                      3.1.0.0    Microsoft.P...
Cmdlet          Write-Warning                                      3.1.0.0    Microsoft.P...
```
### Get-Command -Type Cmdlet使用
```PS C:\windows\system32> Get-Command -Type Cmdlet                                                   
CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Add-AppvClientConnectionGroup                      1.0.0.0    AppvClient
Cmdlet          Add-AppvClientPackage                              1.0.0.0    AppvClient
Cmdlet          Add-AppvPublishingServer                           1.0.0.0    AppvClient
Cmdlet          Add-AppxPackage                                    2.0.1.0    Appx
Cmdlet          Add-AppxProvisionedPackage                         3.0        Dism
Cmdlet          Add-AppxVolume                                     2.0.1.0    Appx
Cmdlet          Add-BitsFile                                       2.0.0.0    BitsTransfer
Cmdlet          Add-CertificateEnrollmentPolicyServer              1.0.0.0    PKI
Cmdlet          Add-Computer                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Add-Content                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Add-History                                        3.0.0.0    Microsoft.PowerSh...
Cmdlet          Add-JobTrigger                                     1.1.0.0    PSScheduledJob
Cmdlet          Add-KdsRootKey                                     1.0.0.0    Kds
Cmdlet          Add-LocalGroupMember                               1.0.0.0    Microsoft.PowerSh...
Cmdlet          Add-Member                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          Add-PSSnapin                                       3.0.0.0    Microsoft.PowerSh...
Cmdlet          Add-SignerRule                                     1.0        ConfigCI
Cmdlet          Add-Type                                           3.1.0.0    Microsoft.PowerSh...
Cmdlet          Add-VMAssignableDevice                             2.0.0.0    Hyper-V
Cmdlet          Add-VMDvdDrive                                     2.0.0.0    Hyper-V
Cmdlet          Add-VMFibreChannelHba                              2.0.0.0    Hyper-V
Cmdlet          Add-VMGpuPartitionAdapter                          2.0.0.0    Hyper-V
Cmdlet          Add-VMGroupMember                                  2.0.0.0    Hyper-V
Cmdlet          Add-VMHardDiskDrive                                2.0.0.0    Hyper-V
Cmdlet          Add-VMHostAssignableDevice                         2.0.0.0    Hyper-V
Cmdlet          Add-VMKeyStorageDrive                              2.0.0.0    Hyper-V
Cmdlet          Add-VMMigrationNetwork                             2.0.0.0    Hyper-V
Cmdlet          Add-VMNetworkAdapter                               2.0.0.0    Hyper-V
Cmdlet          Add-VMNetworkAdapterAcl                            2.0.0.0    Hyper-V
Cmdlet          Add-VMNetworkAdapterExtendedAcl                    2.0.0.0    Hyper-V
Cmdlet          Add-VMNetworkAdapterRoutingDomainMapping           2.0.0.0    Hyper-V
Cmdlet          Add-VMPmemController                               2.0.0.0    Hyper-V
Cmdlet          Add-VMRemoteFx3dVideoAdapter                       2.0.0.0    Hyper-V
Cmdlet          Add-VMScsiController                               2.0.0.0    Hyper-V
Cmdlet          Add-VMStoragePath                                  2.0.0.0    Hyper-V
Cmdlet          Add-VMSwitch                                       2.0.0.0    Hyper-V
Cmdlet          Add-VMSwitchExtensionPortFeature                   2.0.0.0    Hyper-V
Cmdlet          Add-VMSwitchExtensionSwitchFeature                 2.0.0.0    Hyper-V
Cmdlet          Add-VMSwitchTeamMember                             2.0.0.0    Hyper-V
Cmdlet          Add-WindowsCapability                              3.0        Dism
Cmdlet          Add-WindowsDriver                                  3.0        Dism
Cmdlet          Add-WindowsImage                                   3.0        Dism
Cmdlet          Add-WindowsPackage                                 3.0        Dism
Cmdlet          Checkpoint-Computer                                3.1.0.0    Microsoft.PowerSh...
Cmdlet          Checkpoint-VM                                      2.0.0.0    Hyper-V
Cmdlet          Clear-Content                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Clear-EventLog                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          Clear-History                                      3.0.0.0    Microsoft.PowerSh...
Cmdlet          Clear-Item                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          Clear-ItemProperty                                 3.1.0.0    Microsoft.PowerSh...
Cmdlet          Clear-KdsCache                                     1.0.0.0    Kds
Cmdlet          Clear-RecycleBin                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Clear-Tpm                                          2.0.0.0    TrustedPlatformMo...
Cmdlet          Clear-UevAppxPackage                               2.1.639.0  UEV
Cmdlet          Clear-UevConfiguration                             2.1.639.0  UEV
Cmdlet          Clear-Variable                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          Clear-WindowsCorruptMountPoint                     3.0        Dism
Cmdlet          Compare-Object                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          Compare-VM                                         2.0.0.0    Hyper-V
Cmdlet          Complete-BitsTransfer                              2.0.0.0    BitsTransfer
Cmdlet          Complete-DtcDiagnosticTransaction                  1.0.0.0    MsDtc
Cmdlet          Complete-Transaction                               3.1.0.0    Microsoft.PowerSh...
Cmdlet          Complete-VMFailover                                2.0.0.0    Hyper-V
Cmdlet          Confirm-SecureBootUEFI                             2.0.0.0    SecureBoot
Cmdlet          Connect-PSSession                                  3.0.0.0    Microsoft.PowerSh...
Cmdlet          Connect-VMNetworkAdapter                           2.0.0.0    Hyper-V
Cmdlet          Connect-VMSan                                      2.0.0.0    Hyper-V
Cmdlet          Connect-WSMan                                      3.0.0.0    Microsoft.WSMan.M...
Cmdlet          ConvertFrom-CIPolicy                               1.0        ConfigCI
Cmdlet          ConvertFrom-Csv                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          ConvertFrom-Json                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          ConvertFrom-SecureString                           3.0.0.0    Microsoft.PowerSh...
Cmdlet          ConvertFrom-String                                 3.1.0.0    Microsoft.PowerSh...
Cmdlet          ConvertFrom-StringData                             3.1.0.0    Microsoft.PowerSh...
Cmdlet          Convert-Path                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Convert-String                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          ConvertTo-Csv                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          ConvertTo-Html                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          ConvertTo-Json                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          ConvertTo-ProcessMitigationPolicy                  1.0.11     ProcessMitigations
Cmdlet          ConvertTo-SecureString                             3.0.0.0    Microsoft.PowerSh...
Cmdlet          ConvertTo-TpmOwnerAuth                             2.0.0.0    TrustedPlatformMo...
Cmdlet          ConvertTo-Xml                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Convert-VHD                                        2.0.0.0    Hyper-V
Cmdlet          Copy-Item                                          3.1.0.0    Microsoft.PowerSh...
Cmdlet          Copy-ItemProperty                                  3.1.0.0    Microsoft.PowerSh...
Cmdlet          Copy-VMFile                                        2.0.0.0    Hyper-V
Cmdlet          Debug-Job                                          3.0.0.0    Microsoft.PowerSh...
Cmdlet          Debug-Process                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Debug-Runspace                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          Debug-VM                                           2.0.0.0    Hyper-V
Cmdlet          Delete-DeliveryOptimizationCache                   1.0.2.0    DeliveryOptimization
Cmdlet          Disable-AppBackgroundTaskDiagnosticLog             1.0.0.0    AppBackgroundTask
Cmdlet          Disable-Appv                                       1.0.0.0    AppvClient
Cmdlet          Disable-AppvClientConnectionGroup                  1.0.0.0    AppvClient
Cmdlet          Disable-ComputerRestore                            3.1.0.0    Microsoft.PowerSh...
Cmdlet          Disable-JobTrigger                                 1.1.0.0    PSScheduledJob
Cmdlet          Disable-LocalUser                                  1.0.0.0    Microsoft.PowerSh...
Cmdlet          Disable-PSBreakpoint                               3.1.0.0    Microsoft.PowerSh...
Cmdlet          Disable-PSRemoting                                 3.0.0.0    Microsoft.PowerSh...
Cmdlet          Disable-PSSessionConfiguration                     3.0.0.0    Microsoft.PowerSh...
Cmdlet          Disable-RunspaceDebug                              3.1.0.0    Microsoft.PowerSh...
Cmdlet          Disable-ScheduledJob                               1.1.0.0    PSScheduledJob
Cmdlet          Disable-TlsCipherSuite                             2.0.0.0    TLS
Cmdlet          Disable-TlsEccCurve                                2.0.0.0    TLS
Cmdlet          Disable-TlsSessionTicketKey                        2.0.0.0    TLS
Cmdlet          Disable-TpmAutoProvisioning                        2.0.0.0    TrustedPlatformMo...
Cmdlet          Disable-Uev                                        2.1.639.0  UEV
Cmdlet          Disable-UevAppxPackage                             2.1.639.0  UEV
Cmdlet          Disable-UevTemplate                                2.1.639.0  UEV
Cmdlet          Disable-VMConsoleSupport                           2.0.0.0    Hyper-V
Cmdlet          Disable-VMEventing                                 2.0.0.0    Hyper-V
Cmdlet          Disable-VMIntegrationService                       2.0.0.0    Hyper-V
Cmdlet          Disable-VMMigration                                2.0.0.0    Hyper-V
Cmdlet          Disable-VMRemoteFXPhysicalVideoAdapter             2.0.0.0    Hyper-V
Cmdlet          Disable-VMResourceMetering                         2.0.0.0    Hyper-V
Cmdlet          Disable-VMSwitchExtension                          2.0.0.0    Hyper-V
Cmdlet          Disable-VMTPM                                      2.0.0.0    Hyper-V
Cmdlet          Disable-WindowsErrorReporting                      1.0        WindowsErrorRepor...
Cmdlet          Disable-WindowsOptionalFeature                     3.0        Dism
Cmdlet          Disable-WSManCredSSP                               3.0.0.0    Microsoft.WSMan.M...
Cmdlet          Disconnect-PSSession                               3.0.0.0    Microsoft.PowerSh...
Cmdlet          Disconnect-VMNetworkAdapter                        2.0.0.0    Hyper-V
Cmdlet          Disconnect-VMSan                                   2.0.0.0    Hyper-V
Cmdlet          Disconnect-WSMan                                   3.0.0.0    Microsoft.WSMan.M...
Cmdlet          Dismount-AppxVolume                                2.0.1.0    Appx
Cmdlet          Dismount-VHD                                       2.0.0.0    Hyper-V
Cmdlet          Dismount-VMHostAssignableDevice                    2.0.0.0    Hyper-V
Cmdlet          Dismount-WindowsImage                              3.0        Dism
Cmdlet          Edit-CIPolicyRule                                  1.0        ConfigCI
Cmdlet          Enable-AppBackgroundTaskDiagnosticLog              1.0.0.0    AppBackgroundTask
Cmdlet          Enable-Appv                                        1.0.0.0    AppvClient
Cmdlet          Enable-AppvClientConnectionGroup                   1.0.0.0    AppvClient
Cmdlet          Enable-ComputerRestore                             3.1.0.0    Microsoft.PowerSh...
Cmdlet          Enable-JobTrigger                                  1.1.0.0    PSScheduledJob
Cmdlet          Enable-LocalUser                                   1.0.0.0    Microsoft.PowerSh...
Cmdlet          Enable-PSBreakpoint                                3.1.0.0    Microsoft.PowerSh...
Cmdlet          Enable-PSRemoting                                  3.0.0.0    Microsoft.PowerSh...
Cmdlet          Enable-PSSessionConfiguration                      3.0.0.0    Microsoft.PowerSh...
Cmdlet          Enable-RunspaceDebug                               3.1.0.0    Microsoft.PowerSh...
Cmdlet          Enable-ScheduledJob                                1.1.0.0    PSScheduledJob
Cmdlet          Enable-TlsCipherSuite                              2.0.0.0    TLS
Cmdlet          Enable-TlsEccCurve                                 2.0.0.0    TLS
Cmdlet          Enable-TlsSessionTicketKey                         2.0.0.0    TLS
Cmdlet          Enable-TpmAutoProvisioning                         2.0.0.0    TrustedPlatformMo...
Cmdlet          Enable-Uev                                         2.1.639.0  UEV
Cmdlet          Enable-UevAppxPackage                              2.1.639.0  UEV
Cmdlet          Enable-UevTemplate                                 2.1.639.0  UEV
Cmdlet          Enable-VMConsoleSupport                            2.0.0.0    Hyper-V
Cmdlet          Enable-VMEventing                                  2.0.0.0    Hyper-V
Cmdlet          Enable-VMIntegrationService                        2.0.0.0    Hyper-V
Cmdlet          Enable-VMMigration                                 2.0.0.0    Hyper-V
Cmdlet          Enable-VMRemoteFXPhysicalVideoAdapter              2.0.0.0    Hyper-V
Cmdlet          Enable-VMReplication                               2.0.0.0    Hyper-V
Cmdlet          Enable-VMResourceMetering                          2.0.0.0    Hyper-V
Cmdlet          Enable-VMSwitchExtension                           2.0.0.0    Hyper-V
Cmdlet          Enable-VMTPM                                       2.0.0.0    Hyper-V
Cmdlet          Enable-WindowsErrorReporting                       1.0        WindowsErrorRepor...
Cmdlet          Enable-WindowsOptionalFeature                      3.0        Dism
Cmdlet          Enable-WSManCredSSP                                3.0.0.0    Microsoft.WSMan.M...
Cmdlet          Enter-PSHostProcess                                3.0.0.0    Microsoft.PowerSh...
Cmdlet          Enter-PSSession                                    3.0.0.0    Microsoft.PowerSh...
Cmdlet          Exit-PSHostProcess                                 3.0.0.0    Microsoft.PowerSh...
Cmdlet          Exit-PSSession                                     3.0.0.0    Microsoft.PowerSh...
Cmdlet          Expand-WindowsCustomDataImage                      3.0        Dism
Cmdlet          Expand-WindowsImage                                3.0        Dism
Cmdlet          Export-Alias                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Export-BinaryMiLog                                 1.0.0.0    CimCmdlets
Cmdlet          Export-Certificate                                 1.0.0.0    PKI
Cmdlet          Export-Clixml                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Export-Console                                     3.0.0.0    Microsoft.PowerSh...
Cmdlet          Export-Counter                                     3.0.0.0    Microsoft.PowerSh...
Cmdlet          Export-Csv                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          Export-FormatData                                  3.1.0.0    Microsoft.PowerSh...
Cmdlet          Export-ModuleMember                                3.0.0.0    Microsoft.PowerSh...
Cmdlet          Export-PfxCertificate                              1.0.0.0    PKI
Cmdlet          Export-ProvisioningPackage                         3.0        Provisioning
Cmdlet          Export-PSSession                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Export-StartLayout                                 1.0.0.0    StartLayout
Cmdlet          Export-StartLayoutEdgeAssets                       1.0.0.0    StartLayout
Cmdlet          Export-TlsSessionTicketKey                         2.0.0.0    TLS
Cmdlet          Export-Trace                                       3.0        Provisioning
Cmdlet          Export-UevConfiguration                            2.1.639.0  UEV
Cmdlet          Export-UevPackage                                  2.1.639.0  UEV
Cmdlet          Export-VM                                          2.0.0.0    Hyper-V
Cmdlet          Export-VMSnapshot                                  2.0.0.0    Hyper-V
Cmdlet          Export-WindowsCapabilitySource                     3.0        Dism
Cmdlet          Export-WindowsDriver                               3.0        Dism
Cmdlet          Export-WindowsImage                                3.0        Dism
Cmdlet          Find-Package                                       1.0.0.1    PackageManagement
Cmdlet          Find-PackageProvider                               1.0.0.1    PackageManagement
Cmdlet          ForEach-Object                                     3.0.0.0    Microsoft.PowerSh...
Cmdlet          Format-Custom                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Format-List                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Format-SecureBootUEFI                              2.0.0.0    SecureBoot
Cmdlet          Format-Table                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Format-Wide                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Acl                                            3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-Alias                                          3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-AppLockerFileInformation                       2.0.0.0    AppLocker
Cmdlet          Get-AppLockerPolicy                                2.0.0.0    AppLocker
Cmdlet          Get-AppvClientApplication                          1.0.0.0    AppvClient
Cmdlet          Get-AppvClientConfiguration                        1.0.0.0    AppvClient
Cmdlet          Get-AppvClientConnectionGroup                      1.0.0.0    AppvClient
Cmdlet          Get-AppvClientMode                                 1.0.0.0    AppvClient
Cmdlet          Get-AppvClientPackage                              1.0.0.0    AppvClient
Cmdlet          Get-AppvPublishingServer                           1.0.0.0    AppvClient
Cmdlet          Get-AppvStatus                                     1.0.0.0    AppvClient
Cmdlet          Get-AppxDefaultVolume                              2.0.1.0    Appx
Cmdlet          Get-AppxPackage                                    2.0.1.0    Appx
Cmdlet          Get-AppxPackageManifest                            2.0.1.0    Appx
Cmdlet          Get-AppxProvisionedPackage                         3.0        Dism
Cmdlet          Get-AppxVolume                                     2.0.1.0    Appx
Cmdlet          Get-AuthenticodeSignature                          3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-BitsTransfer                                   2.0.0.0    BitsTransfer
Cmdlet          Get-Certificate                                    1.0.0.0    PKI
Cmdlet          Get-CertificateAutoEnrollmentPolicy                1.0.0.0    PKI
Cmdlet          Get-CertificateEnrollmentPolicyServer              1.0.0.0    PKI
Cmdlet          Get-CertificateNotificationTask                    1.0.0.0    PKI
Cmdlet          Get-ChildItem                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-CimAssociatedInstance                          1.0.0.0    CimCmdlets
Cmdlet          Get-CimClass                                       1.0.0.0    CimCmdlets
Cmdlet          Get-CimInstance                                    1.0.0.0    CimCmdlets
Cmdlet          Get-CimSession                                     1.0.0.0    CimCmdlets
Cmdlet          Get-CIPolicy                                       1.0        ConfigCI
Cmdlet          Get-CIPolicyIdInfo                                 1.0        ConfigCI
Cmdlet          Get-CIPolicyInfo                                   1.0        ConfigCI
Cmdlet          Get-Clipboard                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-CmsMessage                                     3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-Command                                        3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-ComputerInfo                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-ComputerRestorePoint                           3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Content                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-ControlPanelItem                               3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Counter                                        3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-Credential                                     3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-Culture                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-DAPolicyChange                                 2.0.0.0    NetSecurity
Cmdlet          Get-Date                                           3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-DeliveryOptimizationLog                        1.0.2.0    DeliveryOptimization
Cmdlet          Get-DeliveryOptimizationPerfSnap                   1.0.2.0    DeliveryOptimization
Cmdlet          Get-DeliveryOptimizationPerfSnapThisMonth          1.0.2.0    DeliveryOptimization
Cmdlet          Get-DeliveryOptimizationStatus                     1.0.2.0    DeliveryOptimization
Cmdlet          Get-DOConfig                                       1.0.2.0    DeliveryOptimization
Cmdlet          Get-DODownloadMode                                 1.0.2.0    DeliveryOptimization
Cmdlet          Get-DOPercentageMaxBackgroundBandwidth             1.0.2.0    DeliveryOptimization
Cmdlet          Get-DOPercentageMaxForegroundBandwidth             1.0.2.0    DeliveryOptimization
Cmdlet          Get-Event                                          3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-EventLog                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-EventSubscriber                                3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-ExecutionPolicy                                3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-FormatData                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Help                                           3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-HgsAttestationBaselinePolicy                   1.0.0.0    HgsClient
Cmdlet          Get-HgsTrace                                       1.0.0.0    HgsDiagnostics
Cmdlet          Get-HgsTraceFileData                               1.0.0.0    HgsDiagnostics
Cmdlet          Get-History                                        3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-Host                                           3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-HotFix                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Item                                           3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-ItemProperty                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-ItemPropertyValue                              3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Job                                            3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-JobTrigger                                     1.1.0.0    PSScheduledJob
Cmdlet          Get-KdsConfiguration                               1.0.0.0    Kds
Cmdlet          Get-KdsRootKey                                     1.0.0.0    Kds
Cmdlet          Get-LocalGroup                                     1.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-LocalGroupMember                               1.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-LocalUser                                      1.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-Location                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Member                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Module                                         3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-NonRemovableAppsPolicy                         3.0        Dism
Cmdlet          Get-Package                                        1.0.0.1    PackageManagement
Cmdlet          Get-PackageProvider                                1.0.0.1    PackageManagement
Cmdlet          Get-PackageSource                                  1.0.0.1    PackageManagement
Cmdlet          Get-PfxCertificate                                 3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-PfxData                                        1.0.0.0    PKI
Cmdlet          Get-PmemDisk                                       1.0.0.0    PersistentMemory
Cmdlet          Get-PmemPhysicalDevice                             1.0.0.0    PersistentMemory
Cmdlet          Get-PmemUnusedRegion                               1.0.0.0    PersistentMemory
Cmdlet          Get-Process                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-ProcessMitigation                              1.0.11     ProcessMitigations
Cmdlet          Get-ProvisioningPackage                            3.0        Provisioning
Cmdlet          Get-PSBreakpoint                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-PSCallStack                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-PSDrive                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-PSHostProcessInfo                              3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-PSProvider                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-PSReadLineKeyHandler                           2.0.0      PSReadline
Cmdlet          Get-PSReadLineOption                               2.0.0      PSReadline
Cmdlet          Get-PSSession                                      3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-PSSessionCapability                            3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-PSSessionConfiguration                         3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-PSSnapin                                       3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-Random                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Runspace                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-RunspaceDebug                                  3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-ScheduledJob                                   1.1.0.0    PSScheduledJob
Cmdlet          Get-ScheduledJobOption                             1.1.0.0    PSScheduledJob
Cmdlet          Get-SecureBootPolicy                               2.0.0.0    SecureBoot
Cmdlet          Get-SecureBootUEFI                                 2.0.0.0    SecureBoot
Cmdlet          Get-Service                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-SystemDriver                                   1.0        ConfigCI
Cmdlet          Get-TimeZone                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-TlsCipherSuite                                 2.0.0.0    TLS
Cmdlet          Get-TlsEccCurve                                    2.0.0.0    TLS
Cmdlet          Get-Tpm                                            2.0.0.0    TrustedPlatformMo...
Cmdlet          Get-TpmEndorsementKeyInfo                          2.0.0.0    TrustedPlatformMo...
Cmdlet          Get-TpmSupportedFeature                            2.0.0.0    TrustedPlatformMo...
Cmdlet          Get-TraceSource                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Transaction                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-TroubleshootingPack                            1.0.0.0    TroubleshootingPack
Cmdlet          Get-TrustedProvisioningCertificate                 3.0        Provisioning
Cmdlet          Get-TypeData                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-UevAppxPackage                                 2.1.639.0  UEV
Cmdlet          Get-UevConfiguration                               2.1.639.0  UEV
Cmdlet          Get-UevStatus                                      2.1.639.0  UEV
Cmdlet          Get-UevTemplate                                    2.1.639.0  UEV
Cmdlet          Get-UevTemplateProgram                             2.1.639.0  UEV
Cmdlet          Get-UICulture                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Unique                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Variable                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-VHD                                            2.0.0.0    Hyper-V
Cmdlet          Get-VHDSet                                         2.0.0.0    Hyper-V
Cmdlet          Get-VHDSnapshot                                    2.0.0.0    Hyper-V
Cmdlet          Get-VM                                             2.0.0.0    Hyper-V
Cmdlet          Get-VMAssignableDevice                             2.0.0.0    Hyper-V
Cmdlet          Get-VMBios                                         2.0.0.0    Hyper-V
Cmdlet          Get-VMComPort                                      2.0.0.0    Hyper-V
Cmdlet          Get-VMConnectAccess                                2.0.0.0    Hyper-V
Cmdlet          Get-VMDvdDrive                                     2.0.0.0    Hyper-V
Cmdlet          Get-VMFibreChannelHba                              2.0.0.0    Hyper-V
Cmdlet          Get-VMFirmware                                     2.0.0.0    Hyper-V
Cmdlet          Get-VMFloppyDiskDrive                              2.0.0.0    Hyper-V
Cmdlet          Get-VMGpuPartitionAdapter                          2.0.0.0    Hyper-V
Cmdlet          Get-VMGroup                                        2.0.0.0    Hyper-V
Cmdlet          Get-VMHardDiskDrive                                2.0.0.0    Hyper-V
Cmdlet          Get-VMHost                                         2.0.0.0    Hyper-V
Cmdlet          Get-VMHostAssignableDevice                         2.0.0.0    Hyper-V
Cmdlet          Get-VMHostCluster                                  2.0.0.0    Hyper-V
Cmdlet          Get-VMHostNumaNode                                 2.0.0.0    Hyper-V
Cmdlet          Get-VMHostNumaNodeStatus                           2.0.0.0    Hyper-V
Cmdlet          Get-VMHostSupportedVersion                         2.0.0.0    Hyper-V
Cmdlet          Get-VMIdeController                                2.0.0.0    Hyper-V
Cmdlet          Get-VMIntegrationService                           2.0.0.0    Hyper-V
Cmdlet          Get-VMKeyProtector                                 2.0.0.0    Hyper-V
Cmdlet          Get-VMKeyStorageDrive                              2.0.0.0    Hyper-V
Cmdlet          Get-VMMemory                                       2.0.0.0    Hyper-V
Cmdlet          Get-VMMigrationNetwork                             2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapter                               2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterAcl                            2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterExtendedAcl                    2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterFailoverConfiguration          2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterIsolation                      2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterRdma                           2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterRoutingDomainMapping           2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterTeamMapping                    2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterVlan                           2.0.0.0    Hyper-V
Cmdlet          Get-VMPartitionableGpu                             2.0.0.0    Hyper-V
Cmdlet          Get-VMPmemController                               2.0.0.0    Hyper-V
Cmdlet          Get-VMProcessor                                    2.0.0.0    Hyper-V
Cmdlet          Get-VMRemoteFx3dVideoAdapter                       2.0.0.0    Hyper-V
Cmdlet          Get-VMRemoteFXPhysicalVideoAdapter                 2.0.0.0    Hyper-V
Cmdlet          Get-VMReplication                                  2.0.0.0    Hyper-V
Cmdlet          Get-VMReplicationAuthorizationEntry                2.0.0.0    Hyper-V
Cmdlet          Get-VMReplicationServer                            2.0.0.0    Hyper-V
Cmdlet          Get-VMResourcePool                                 2.0.0.0    Hyper-V
Cmdlet          Get-VMSan                                          2.0.0.0    Hyper-V
Cmdlet          Get-VMScsiController                               2.0.0.0    Hyper-V
Cmdlet          Get-VMSecurity                                     2.0.0.0    Hyper-V
Cmdlet          Get-VMSnapshot                                     2.0.0.0    Hyper-V
Cmdlet          Get-VMStoragePath                                  2.0.0.0    Hyper-V
Cmdlet          Get-VMStorageSettings                              2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitch                                       2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitchExtension                              2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitchExtensionPortData                      2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitchExtensionPortFeature                   2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitchExtensionSwitchData                    2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitchExtensionSwitchFeature                 2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitchTeam                                   2.0.0.0    Hyper-V
Cmdlet          Get-VMSystemSwitchExtension                        2.0.0.0    Hyper-V
Cmdlet          Get-VMSystemSwitchExtensionPortFeature             2.0.0.0    Hyper-V
Cmdlet          Get-VMSystemSwitchExtensionSwitchFeature           2.0.0.0    Hyper-V
Cmdlet          Get-VMVideo                                        2.0.0.0    Hyper-V
Cmdlet          Get-WheaMemoryPolicy                               2.0.0.0    Whea
Cmdlet          Get-WIMBootEntry                                   3.0        Dism
Cmdlet          Get-WinAcceptLanguageFromLanguageListOptOut        2.0.0.0    International
Cmdlet          Get-WinCultureFromLanguageListOptOut               2.0.0.0    International
Cmdlet          Get-WinDefaultInputMethodOverride                  2.0.0.0    International
Cmdlet          Get-WindowsCapability                              3.0        Dism
Cmdlet          Get-WindowsDeveloperLicense                        1.0.0.0    WindowsDeveloperL...
Cmdlet          Get-WindowsDriver                                  3.0        Dism
Cmdlet          Get-WindowsEdition                                 3.0        Dism
Cmdlet          Get-WindowsErrorReporting                          1.0        WindowsErrorRepor...
Cmdlet          Get-WindowsImage                                   3.0        Dism
Cmdlet          Get-WindowsImageContent                            3.0        Dism
Cmdlet          Get-WindowsOptionalFeature                         3.0        Dism
Cmdlet          Get-WindowsPackage                                 3.0        Dism
Cmdlet          Get-WindowsSearchSetting                           1.0.0.0    WindowsSearch
Cmdlet          Get-WinEvent                                       3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-WinHomeLocation                                2.0.0.0    International
Cmdlet          Get-WinLanguageBarOption                           2.0.0.0    International
Cmdlet          Get-WinSystemLocale                                2.0.0.0    International
Cmdlet          Get-WinUILanguageOverride                          2.0.0.0    International
Cmdlet          Get-WinUserLanguageList                            2.0.0.0    International
Cmdlet          Get-WmiObject                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-WSManCredSSP                                   3.0.0.0    Microsoft.WSMan.M...
Cmdlet          Get-WSManInstance                                  3.0.0.0    Microsoft.WSMan.M...
Cmdlet          Grant-VMConnectAccess                              2.0.0.0    Hyper-V
Cmdlet          Group-Object                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Import-Alias                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Import-BinaryMiLog                                 1.0.0.0    CimCmdlets
Cmdlet          Import-Certificate                                 1.0.0.0    PKI
Cmdlet          Import-Clixml                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Import-Counter                                     3.0.0.0    Microsoft.PowerSh...
Cmdlet          Import-Csv                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          Import-LocalizedData                               3.1.0.0    Microsoft.PowerSh...
Cmdlet          Import-Module                                      3.0.0.0    Microsoft.PowerSh...
Cmdlet          Import-PackageProvider                             1.0.0.1    PackageManagement
Cmdlet          Import-PfxCertificate                              1.0.0.0    PKI
Cmdlet          Import-PSSession                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Import-StartLayout                                 1.0.0.0    StartLayout
Cmdlet          Import-TpmOwnerAuth                                2.0.0.0    TrustedPlatformMo...
Cmdlet          Import-UevConfiguration                            2.1.639.0  UEV
Cmdlet          Import-VM                                          2.0.0.0    Hyper-V
Cmdlet          Import-VMInitialReplication                        2.0.0.0    Hyper-V
Cmdlet          Initialize-PmemPhysicalDevice                      1.0.0.0    PersistentMemory
Cmdlet          Initialize-Tpm                                     2.0.0.0    TrustedPlatformMo...
Cmdlet          Install-Package                                    1.0.0.1    PackageManagement
Cmdlet          Install-PackageProvider                            1.0.0.1    PackageManagement
Cmdlet          Install-ProvisioningPackage                        3.0        Provisioning
Cmdlet          Install-TrustedProvisioningCertificate             3.0        Provisioning
Cmdlet          Invoke-CimMethod                                   1.0.0.0    CimCmdlets
Cmdlet          Invoke-Command                                     3.0.0.0    Microsoft.PowerSh...
Cmdlet          Invoke-CommandInDesktopPackage                     2.0.1.0    Appx
Cmdlet          Invoke-DscResource                                 1.1        PSDesiredStateCon...
Cmdlet          Invoke-Expression                                  3.1.0.0    Microsoft.PowerSh...
Cmdlet          Invoke-History                                     3.0.0.0    Microsoft.PowerSh...
Cmdlet          Invoke-Item                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Invoke-RestMethod                                  3.1.0.0    Microsoft.PowerSh...
Cmdlet          Invoke-TroubleshootingPack                         1.0.0.0    TroubleshootingPack
Cmdlet          Invoke-WebRequest                                  3.1.0.0    Microsoft.PowerSh...
Cmdlet          Invoke-WmiMethod                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Invoke-WSManAction                                 3.0.0.0    Microsoft.WSMan.M...
Cmdlet          Join-DtcDiagnosticResourceManager                  1.0.0.0    MsDtc
Cmdlet          Join-Path                                          3.1.0.0    Microsoft.PowerSh...
Cmdlet          Limit-EventLog                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          Measure-Command                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Measure-Object                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          Measure-VM                                         2.0.0.0    Hyper-V
Cmdlet          Measure-VMReplication                              2.0.0.0    Hyper-V
Cmdlet          Measure-VMResourcePool                             2.0.0.0    Hyper-V
Cmdlet          Merge-CIPolicy                                     1.0        ConfigCI
Cmdlet          Merge-VHD                                          2.0.0.0    Hyper-V
Cmdlet          Mount-AppvClientConnectionGroup                    1.0.0.0    AppvClient
Cmdlet          Mount-AppvClientPackage                            1.0.0.0    AppvClient
Cmdlet          Mount-AppxVolume                                   2.0.1.0    Appx
Cmdlet          Mount-VHD                                          2.0.0.0    Hyper-V
Cmdlet          Mount-VMHostAssignableDevice                       2.0.0.0    Hyper-V
Cmdlet          Mount-WindowsImage                                 3.0        Dism
Cmdlet          Move-AppxPackage                                   2.0.1.0    Appx
Cmdlet          Move-Item                                          3.1.0.0    Microsoft.PowerSh...
Cmdlet          Move-ItemProperty                                  3.1.0.0    Microsoft.PowerSh...
Cmdlet          Move-VM                                            2.0.0.0    Hyper-V
Cmdlet          Move-VMStorage                                     2.0.0.0    Hyper-V
Cmdlet          New-Alias                                          3.1.0.0    Microsoft.PowerSh...
Cmdlet          New-AppLockerPolicy                                2.0.0.0    AppLocker
Cmdlet          New-CertificateNotificationTask                    1.0.0.0    PKI
Cmdlet          New-CimInstance                                    1.0.0.0    CimCmdlets
Cmdlet          New-CimSession                                     1.0.0.0    CimCmdlets
Cmdlet          New-CimSessionOption                               1.0.0.0    CimCmdlets
Cmdlet          New-CIPolicy                                       1.0        ConfigCI
Cmdlet          New-CIPolicyRule                                   1.0        ConfigCI
Cmdlet          New-DtcDiagnosticTransaction                       1.0.0.0    MsDtc
Cmdlet          New-Event                                          3.1.0.0    Microsoft.PowerSh...
Cmdlet          New-EventLog                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          New-FileCatalog                                    3.0.0.0    Microsoft.PowerSh...
Cmdlet          New-HgsTraceTarget                                 1.0.0.0    HgsDiagnostics
Cmdlet          New-Item                                           3.1.0.0    Microsoft.PowerSh...
Cmdlet          New-ItemProperty                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          New-JobTrigger                                     1.1.0.0    PSScheduledJob
Cmdlet          New-LocalGroup                                     1.0.0.0    Microsoft.PowerSh...
Cmdlet          New-LocalUser                                      1.0.0.0    Microsoft.PowerSh...
Cmdlet          New-Module                                         3.0.0.0    Microsoft.PowerSh...
Cmdlet          New-ModuleManifest                                 3.0.0.0    Microsoft.PowerSh...
Cmdlet          New-NetIPsecAuthProposal                           2.0.0.0    NetSecurity
Cmdlet          New-NetIPsecMainModeCryptoProposal                 2.0.0.0    NetSecurity
Cmdlet          New-NetIPsecQuickModeCryptoProposal                2.0.0.0    NetSecurity
Cmdlet          New-Object                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          New-PmemDisk                                       1.0.0.0    PersistentMemory
Cmdlet          New-ProvisioningRepro                              3.0        Provisioning
Cmdlet          New-PSDrive                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          New-PSRoleCapabilityFile                           3.0.0.0    Microsoft.PowerSh...
Cmdlet          New-PSSession                                      3.0.0.0    Microsoft.PowerSh...
Cmdlet          New-PSSessionConfigurationFile                     3.0.0.0    Microsoft.PowerSh...
Cmdlet          New-PSSessionOption                                3.0.0.0    Microsoft.PowerSh...
Cmdlet          New-PSTransportOption                              3.0.0.0    Microsoft.PowerSh...
Cmdlet          New-PSWorkflowExecutionOption                      2.0.0.0    PSWorkflow
Cmdlet          New-ScheduledJobOption                             1.1.0.0    PSScheduledJob
Cmdlet          New-SelfSignedCertificate                          1.0.0.0    PKI
Cmdlet          New-Service                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          New-TimeSpan                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          New-TlsSessionTicketKey                            2.0.0.0    TLS
Cmdlet          New-Variable                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          New-VFD                                            2.0.0.0    Hyper-V
Cmdlet          New-VHD                                            2.0.0.0    Hyper-V
Cmdlet          New-VM                                             2.0.0.0    Hyper-V
Cmdlet          New-VMGroup                                        2.0.0.0    Hyper-V
Cmdlet          New-VMReplicationAuthorizationEntry                2.0.0.0    Hyper-V
Cmdlet          New-VMResourcePool                                 2.0.0.0    Hyper-V
Cmdlet          New-VMSan                                          2.0.0.0    Hyper-V
Cmdlet          New-VMSwitch                                       2.0.0.0    Hyper-V
Cmdlet          New-WebServiceProxy                                3.1.0.0    Microsoft.PowerSh...
Cmdlet          New-WindowsCustomImage                             3.0        Dism
Cmdlet          New-WindowsImage                                   3.0        Dism
Cmdlet          New-WinEvent                                       3.0.0.0    Microsoft.PowerSh...
Cmdlet          New-WinUserLanguageList                            2.0.0.0    International
Cmdlet          New-WSManInstance                                  3.0.0.0    Microsoft.WSMan.M...
Cmdlet          New-WSManSessionOption                             3.0.0.0    Microsoft.WSMan.M...
Cmdlet          Optimize-AppxProvisionedPackages                   3.0        Dism
Cmdlet          Optimize-VHD                                       2.0.0.0    Hyper-V
Cmdlet          Optimize-VHDSet                                    2.0.0.0    Hyper-V
Cmdlet          Optimize-WindowsImage                              3.0        Dism
Cmdlet          Out-Default                                        3.0.0.0    Microsoft.PowerSh...
Cmdlet          Out-File                                           3.1.0.0    Microsoft.PowerSh...
Cmdlet          Out-GridView                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Out-Host                                           3.0.0.0    Microsoft.PowerSh...
Cmdlet          Out-Null                                           3.0.0.0    Microsoft.PowerSh...
Cmdlet          Out-Printer                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Out-String                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          Pop-Location                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Protect-CmsMessage                                 3.0.0.0    Microsoft.PowerSh...
Cmdlet          Publish-AppvClientPackage                          1.0.0.0    AppvClient
Cmdlet          Publish-DscConfiguration                           1.1        PSDesiredStateCon...
Cmdlet          Push-Location                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Read-Host                                          3.1.0.0    Microsoft.PowerSh...
Cmdlet          Receive-DtcDiagnosticTransaction                   1.0.0.0    MsDtc
Cmdlet          Receive-Job                                        3.0.0.0    Microsoft.PowerSh...
Cmdlet          Receive-PSSession                                  3.0.0.0    Microsoft.PowerSh...
Cmdlet          Register-ArgumentCompleter                         3.0.0.0    Microsoft.PowerSh...
Cmdlet          Register-CimIndicationEvent                        1.0.0.0    CimCmdlets
Cmdlet          Register-EngineEvent                               3.1.0.0    Microsoft.PowerSh...
Cmdlet          Register-ObjectEvent                               3.1.0.0    Microsoft.PowerSh...
Cmdlet          Register-PackageSource                             1.0.0.1    PackageManagement
Cmdlet          Register-PSSessionConfiguration                    3.0.0.0    Microsoft.PowerSh...
Cmdlet          Register-ScheduledJob                              1.1.0.0    PSScheduledJob
Cmdlet          Register-UevTemplate                               2.1.639.0  UEV
Cmdlet          Register-WmiEvent                                  3.1.0.0    Microsoft.PowerSh...
Cmdlet          Remove-AppvClientConnectionGroup                   1.0.0.0    AppvClient
Cmdlet          Remove-AppvClientPackage                           1.0.0.0    AppvClient
Cmdlet          Remove-AppvPublishingServer                        1.0.0.0    AppvClient
Cmdlet          Remove-AppxPackage                                 2.0.1.0    Appx
Cmdlet          Remove-AppxProvisionedPackage                      3.0        Dism
Cmdlet          Remove-AppxVolume                                  2.0.1.0    Appx
Cmdlet          Remove-BitsTransfer                                2.0.0.0    BitsTransfer
Cmdlet          Remove-CertificateEnrollmentPolicyServer           1.0.0.0    PKI
Cmdlet          Remove-CertificateNotificationTask                 1.0.0.0    PKI
Cmdlet          Remove-CimInstance                                 1.0.0.0    CimCmdlets
Cmdlet          Remove-CimSession                                  1.0.0.0    CimCmdlets
Cmdlet          Remove-CIPolicyRule                                1.0        ConfigCI
Cmdlet          Remove-Computer                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Remove-Event                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Remove-EventLog                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Remove-Item                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Remove-ItemProperty                                3.1.0.0    Microsoft.PowerSh...
Cmdlet          Remove-Job                                         3.0.0.0    Microsoft.PowerSh...
Cmdlet          Remove-JobTrigger                                  1.1.0.0    PSScheduledJob
Cmdlet          Remove-LocalGroup                                  1.0.0.0    Microsoft.PowerSh...
Cmdlet          Remove-LocalGroupMember                            1.0.0.0    Microsoft.PowerSh...
Cmdlet          Remove-LocalUser                                   1.0.0.0    Microsoft.PowerSh...
Cmdlet          Remove-Module                                      3.0.0.0    Microsoft.PowerSh...
Cmdlet          Remove-PmemDisk                                    1.0.0.0    PersistentMemory
Cmdlet          Remove-PSBreakpoint                                3.1.0.0    Microsoft.PowerSh...
Cmdlet          Remove-PSDrive                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          Remove-PSReadLineKeyHandler                        2.0.0      PSReadline
Cmdlet          Remove-PSSession                                   3.0.0.0    Microsoft.PowerSh...
Cmdlet          Remove-PSSnapin                                    3.0.0.0    Microsoft.PowerSh...
Cmdlet          Remove-TypeData                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Remove-Variable                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Remove-VHDSnapshot                                 2.0.0.0    Hyper-V
Cmdlet          Remove-VM                                          2.0.0.0    Hyper-V
Cmdlet          Remove-VMAssignableDevice                          2.0.0.0    Hyper-V
Cmdlet          Remove-VMDvdDrive                                  2.0.0.0    Hyper-V
Cmdlet          Remove-VMFibreChannelHba                           2.0.0.0    Hyper-V
Cmdlet          Remove-VMGpuPartitionAdapter                       2.0.0.0    Hyper-V
Cmdlet          Remove-VMGroup                                     2.0.0.0    Hyper-V
Cmdlet          Remove-VMGroupMember                               2.0.0.0    Hyper-V
Cmdlet          Remove-VMHardDiskDrive                             2.0.0.0    Hyper-V
Cmdlet          Remove-VMHostAssignableDevice                      2.0.0.0    Hyper-V
Cmdlet          Remove-VMKeyStorageDrive                           2.0.0.0    Hyper-V
Cmdlet          Remove-VMMigrationNetwork                          2.0.0.0    Hyper-V
Cmdlet          Remove-VMNetworkAdapter                            2.0.0.0    Hyper-V
Cmdlet          Remove-VMNetworkAdapterAcl                         2.0.0.0    Hyper-V
Cmdlet          Remove-VMNetworkAdapterExtendedAcl                 2.0.0.0    Hyper-V
Cmdlet          Remove-VMNetworkAdapterRoutingDomainMapping        2.0.0.0    Hyper-V
Cmdlet          Remove-VMNetworkAdapterTeamMapping                 2.0.0.0    Hyper-V
Cmdlet          Remove-VMPmemController                            2.0.0.0    Hyper-V
Cmdlet          Remove-VMRemoteFx3dVideoAdapter                    2.0.0.0    Hyper-V
Cmdlet          Remove-VMReplication                               2.0.0.0    Hyper-V
Cmdlet          Remove-VMReplicationAuthorizationEntry             2.0.0.0    Hyper-V
Cmdlet          Remove-VMResourcePool                              2.0.0.0    Hyper-V
Cmdlet          Remove-VMSan                                       2.0.0.0    Hyper-V
Cmdlet          Remove-VMSavedState                                2.0.0.0    Hyper-V
Cmdlet          Remove-VMScsiController                            2.0.0.0    Hyper-V
Cmdlet          Remove-VMSnapshot                                  2.0.0.0    Hyper-V
Cmdlet          Remove-VMStoragePath                               2.0.0.0    Hyper-V
Cmdlet          Remove-VMSwitch                                    2.0.0.0    Hyper-V
Cmdlet          Remove-VMSwitchExtensionPortFeature                2.0.0.0    Hyper-V
Cmdlet          Remove-VMSwitchExtensionSwitchFeature              2.0.0.0    Hyper-V
Cmdlet          Remove-VMSwitchTeamMember                          2.0.0.0    Hyper-V
Cmdlet          Remove-WindowsCapability                           3.0        Dism
Cmdlet          Remove-WindowsDriver                               3.0        Dism
Cmdlet          Remove-WindowsImage                                3.0        Dism
Cmdlet          Remove-WindowsPackage                              3.0        Dism
Cmdlet          Remove-WmiObject                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Remove-WSManInstance                               3.0.0.0    Microsoft.WSMan.M...
Cmdlet          Rename-Computer                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Rename-Item                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Rename-ItemProperty                                3.1.0.0    Microsoft.PowerSh...
Cmdlet          Rename-LocalGroup                                  1.0.0.0    Microsoft.PowerSh...
Cmdlet          Rename-LocalUser                                   1.0.0.0    Microsoft.PowerSh...
Cmdlet          Rename-VM                                          2.0.0.0    Hyper-V
Cmdlet          Rename-VMGroup                                     2.0.0.0    Hyper-V
Cmdlet          Rename-VMNetworkAdapter                            2.0.0.0    Hyper-V
Cmdlet          Rename-VMResourcePool                              2.0.0.0    Hyper-V
Cmdlet          Rename-VMSan                                       2.0.0.0    Hyper-V
Cmdlet          Rename-VMSnapshot                                  2.0.0.0    Hyper-V
Cmdlet          Rename-VMSwitch                                    2.0.0.0    Hyper-V
Cmdlet          Repair-AppvClientConnectionGroup                   1.0.0.0    AppvClient
Cmdlet          Repair-AppvClientPackage                           1.0.0.0    AppvClient
Cmdlet          Repair-UevTemplateIndex                            2.1.639.0  UEV
Cmdlet          Repair-VM                                          2.0.0.0    Hyper-V
Cmdlet          Repair-WindowsImage                                3.0        Dism
Cmdlet          Reset-ComputerMachinePassword                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Reset-VMReplicationStatistics                      2.0.0.0    Hyper-V
Cmdlet          Reset-VMResourceMetering                           2.0.0.0    Hyper-V
Cmdlet          Resize-VHD                                         2.0.0.0    Hyper-V
Cmdlet          Resolve-DnsName                                    1.0.0.0    DnsClient
Cmdlet          Resolve-Path                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Restart-Computer                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Restart-Service                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Restart-VM                                         2.0.0.0    Hyper-V
Cmdlet          Restore-Computer                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Restore-UevBackup                                  2.1.639.0  UEV
Cmdlet          Restore-UevUserSetting                             2.1.639.0  UEV
Cmdlet          Restore-VMSnapshot                                 2.0.0.0    Hyper-V
Cmdlet          Resume-BitsTransfer                                2.0.0.0    BitsTransfer
Cmdlet          Resume-Job                                         3.0.0.0    Microsoft.PowerSh...
Cmdlet          Resume-ProvisioningSession                         3.0        Provisioning
Cmdlet          Resume-Service                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          Resume-VM                                          2.0.0.0    Hyper-V
Cmdlet          Resume-VMReplication                               2.0.0.0    Hyper-V
Cmdlet          Revoke-VMConnectAccess                             2.0.0.0    Hyper-V
Cmdlet          Save-Help                                          3.0.0.0    Microsoft.PowerSh...
Cmdlet          Save-Package                                       1.0.0.1    PackageManagement
Cmdlet          Save-VM                                            2.0.0.0    Hyper-V
Cmdlet          Save-WindowsImage                                  3.0        Dism
Cmdlet          Select-Object                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Select-String                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Select-Xml                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          Send-AppvClientReport                              1.0.0.0    AppvClient
Cmdlet          Send-DtcDiagnosticTransaction                      1.0.0.0    MsDtc
Cmdlet          Send-MailMessage                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-Acl                                            3.0.0.0    Microsoft.PowerSh...
Cmdlet          Set-Alias                                          3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-AppBackgroundTaskResourcePolicy                1.0.0.0    AppBackgroundTask
Cmdlet          Set-AppLockerPolicy                                2.0.0.0    AppLocker
Cmdlet          Set-AppvClientConfiguration                        1.0.0.0    AppvClient
Cmdlet          Set-AppvClientMode                                 1.0.0.0    AppvClient
Cmdlet          Set-AppvClientPackage                              1.0.0.0    AppvClient
Cmdlet          Set-AppvPublishingServer                           1.0.0.0    AppvClient
Cmdlet          Set-AppxDefaultVolume                              2.0.1.0    Appx
Cmdlet          Set-AppXProvisionedDataFile                        3.0        Dism
Cmdlet          Set-AuthenticodeSignature                          3.0.0.0    Microsoft.PowerSh...
Cmdlet          Set-BitsTransfer                                   2.0.0.0    BitsTransfer
Cmdlet          Set-CertificateAutoEnrollmentPolicy                1.0.0.0    PKI
Cmdlet          Set-CimInstance                                    1.0.0.0    CimCmdlets
Cmdlet          Set-CIPolicyIdInfo                                 1.0        ConfigCI
Cmdlet          Set-CIPolicySetting                                1.0        ConfigCI
Cmdlet          Set-CIPolicyVersion                                1.0        ConfigCI
Cmdlet          Set-Clipboard                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-Content                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-Culture                                        2.0.0.0    International
Cmdlet          Set-Date                                           3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-DeliveryOptimizationStatus                     1.0.2.0    DeliveryOptimization
Cmdlet          Set-DODownloadMode                                 1.0.2.0    DeliveryOptimization
Cmdlet          Set-DOPercentageMaxBackgroundBandwidth             1.0.2.0    DeliveryOptimization
Cmdlet          Set-DOPercentageMaxForegroundBandwidth             1.0.2.0    DeliveryOptimization
Cmdlet          Set-DscLocalConfigurationManager                   1.1        PSDesiredStateCon...
Cmdlet          Set-ExecutionPolicy                                3.0.0.0    Microsoft.PowerSh...
Cmdlet          Set-HVCIOptions                                    1.0        ConfigCI
Cmdlet          Set-Item                                           3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-ItemProperty                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-JobTrigger                                     1.1.0.0    PSScheduledJob
Cmdlet          Set-KdsConfiguration                               1.0.0.0    Kds
Cmdlet          Set-LocalGroup                                     1.0.0.0    Microsoft.PowerSh...
Cmdlet          Set-LocalUser                                      1.0.0.0    Microsoft.PowerSh...
Cmdlet          Set-Location                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-NonRemovableAppsPolicy                         3.0        Dism
Cmdlet          Set-PackageSource                                  1.0.0.1    PackageManagement
Cmdlet          Set-ProcessMitigation                              1.0.11     ProcessMitigations
Cmdlet          Set-PSBreakpoint                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-PSDebug                                        3.0.0.0    Microsoft.PowerSh...
Cmdlet          Set-PSReadLineKeyHandler                           2.0.0      PSReadline
Cmdlet          Set-PSReadLineOption                               2.0.0      PSReadline
Cmdlet          Set-PSSessionConfiguration                         3.0.0.0    Microsoft.PowerSh...
Cmdlet          Set-RuleOption                                     1.0        ConfigCI
Cmdlet          Set-ScheduledJob                                   1.1.0.0    PSScheduledJob
Cmdlet          Set-ScheduledJobOption                             1.1.0.0    PSScheduledJob
Cmdlet          Set-SecureBootUEFI                                 2.0.0.0    SecureBoot
Cmdlet          Set-Service                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-StrictMode                                     3.0.0.0    Microsoft.PowerSh...
Cmdlet          Set-TimeZone                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-TpmOwnerAuth                                   2.0.0.0    TrustedPlatformMo...
Cmdlet          Set-TraceSource                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-UevConfiguration                               2.1.639.0  UEV
Cmdlet          Set-UevTemplateProfile                             2.1.639.0  UEV
Cmdlet          Set-Variable                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-VHD                                            2.0.0.0    Hyper-V
Cmdlet          Set-VM                                             2.0.0.0    Hyper-V
Cmdlet          Set-VMBios                                         2.0.0.0    Hyper-V
Cmdlet          Set-VMComPort                                      2.0.0.0    Hyper-V
Cmdlet          Set-VMDvdDrive                                     2.0.0.0    Hyper-V
Cmdlet          Set-VMFibreChannelHba                              2.0.0.0    Hyper-V
Cmdlet          Set-VMFirmware                                     2.0.0.0    Hyper-V
Cmdlet          Set-VMFloppyDiskDrive                              2.0.0.0    Hyper-V
Cmdlet          Set-VMGpuPartitionAdapter                          2.0.0.0    Hyper-V
Cmdlet          Set-VMHardDiskDrive                                2.0.0.0    Hyper-V
Cmdlet          Set-VMHost                                         2.0.0.0    Hyper-V
Cmdlet          Set-VMHostCluster                                  2.0.0.0    Hyper-V
Cmdlet          Set-VMKeyProtector                                 2.0.0.0    Hyper-V
Cmdlet          Set-VMKeyStorageDrive                              2.0.0.0    Hyper-V
Cmdlet          Set-VMMemory                                       2.0.0.0    Hyper-V
Cmdlet          Set-VMMigrationNetwork                             2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapter                               2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapterFailoverConfiguration          2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapterIsolation                      2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapterRdma                           2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapterRoutingDomainMapping           2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapterTeamMapping                    2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapterVlan                           2.0.0.0    Hyper-V
Cmdlet          Set-VMPartitionableGpu                             2.0.0.0    Hyper-V
Cmdlet          Set-VMProcessor                                    2.0.0.0    Hyper-V
Cmdlet          Set-VMRemoteFx3dVideoAdapter                       2.0.0.0    Hyper-V
Cmdlet          Set-VMReplication                                  2.0.0.0    Hyper-V
Cmdlet          Set-VMReplicationAuthorizationEntry                2.0.0.0    Hyper-V
Cmdlet          Set-VMReplicationServer                            2.0.0.0    Hyper-V
Cmdlet          Set-VMResourcePool                                 2.0.0.0    Hyper-V
Cmdlet          Set-VMSan                                          2.0.0.0    Hyper-V
Cmdlet          Set-VMSecurity                                     2.0.0.0    Hyper-V
Cmdlet          Set-VMSecurityPolicy                               2.0.0.0    Hyper-V
Cmdlet          Set-VMStorageSettings                              2.0.0.0    Hyper-V
Cmdlet          Set-VMSwitch                                       2.0.0.0    Hyper-V
Cmdlet          Set-VMSwitchExtensionPortFeature                   2.0.0.0    Hyper-V
Cmdlet          Set-VMSwitchExtensionSwitchFeature                 2.0.0.0    Hyper-V
Cmdlet          Set-VMSwitchTeam                                   2.0.0.0    Hyper-V
Cmdlet          Set-VMVideo                                        2.0.0.0    Hyper-V
Cmdlet          Set-WheaMemoryPolicy                               2.0.0.0    Whea
Cmdlet          Set-WinAcceptLanguageFromLanguageListOptOut        2.0.0.0    International
Cmdlet          Set-WinCultureFromLanguageListOptOut               2.0.0.0    International
Cmdlet          Set-WinDefaultInputMethodOverride                  2.0.0.0    International
Cmdlet          Set-WindowsEdition                                 3.0        Dism
Cmdlet          Set-WindowsProductKey                              3.0        Dism
Cmdlet          Set-WindowsSearchSetting                           1.0.0.0    WindowsSearch
Cmdlet          Set-WinHomeLocation                                2.0.0.0    International
Cmdlet          Set-WinLanguageBarOption                           2.0.0.0    International
Cmdlet          Set-WinSystemLocale                                2.0.0.0    International
Cmdlet          Set-WinUILanguageOverride                          2.0.0.0    International
Cmdlet          Set-WinUserLanguageList                            2.0.0.0    International
Cmdlet          Set-WmiInstance                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-WSManInstance                                  3.0.0.0    Microsoft.WSMan.M...
Cmdlet          Set-WSManQuickConfig                               3.0.0.0    Microsoft.WSMan.M...
Cmdlet          Show-Command                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Show-ControlPanelItem                              3.1.0.0    Microsoft.PowerSh...
Cmdlet          Show-EventLog                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Show-WindowsDeveloperLicenseRegistration           1.0.0.0    WindowsDeveloperL...
Cmdlet          Sort-Object                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Split-Path                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          Split-WindowsImage                                 3.0        Dism
Cmdlet          Start-BitsTransfer                                 2.0.0.0    BitsTransfer
Cmdlet          Start-DscConfiguration                             1.1        PSDesiredStateCon...
Cmdlet          Start-DtcDiagnosticResourceManager                 1.0.0.0    MsDtc
Cmdlet          Start-Job                                          3.0.0.0    Microsoft.PowerSh...
Cmdlet          Start-OSUninstall                                  3.0        Dism
Cmdlet          Start-Process                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Start-Service                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Start-Sleep                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Start-Transaction                                  3.1.0.0    Microsoft.PowerSh...
Cmdlet          Start-Transcript                                   3.0.0.0    Microsoft.PowerSh...
Cmdlet          Start-VM                                           2.0.0.0    Hyper-V
Cmdlet          Start-VMFailover                                   2.0.0.0    Hyper-V
Cmdlet          Start-VMInitialReplication                         2.0.0.0    Hyper-V
Cmdlet          Start-VMTrace                                      2.0.0.0    Hyper-V
Cmdlet          Stop-AppvClientConnectionGroup                     1.0.0.0    AppvClient
Cmdlet          Stop-AppvClientPackage                             1.0.0.0    AppvClient
Cmdlet          Stop-Computer                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Stop-DtcDiagnosticResourceManager                  1.0.0.0    MsDtc
Cmdlet          Stop-Job                                           3.0.0.0    Microsoft.PowerSh...
Cmdlet          Stop-Process                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Stop-Service                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Stop-Transcript                                    3.0.0.0    Microsoft.PowerSh...
Cmdlet          Stop-VM                                            2.0.0.0    Hyper-V
Cmdlet          Stop-VMFailover                                    2.0.0.0    Hyper-V
Cmdlet          Stop-VMInitialReplication                          2.0.0.0    Hyper-V
Cmdlet          Stop-VMReplication                                 2.0.0.0    Hyper-V
Cmdlet          Stop-VMTrace                                       2.0.0.0    Hyper-V
Cmdlet          Suspend-BitsTransfer                               2.0.0.0    BitsTransfer
Cmdlet          Suspend-Job                                        3.0.0.0    Microsoft.PowerSh...
Cmdlet          Suspend-Service                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Suspend-VM                                         2.0.0.0    Hyper-V
Cmdlet          Suspend-VMReplication                              2.0.0.0    Hyper-V
Cmdlet          Switch-Certificate                                 1.0.0.0    PKI
Cmdlet          Sync-AppvPublishingServer                          1.0.0.0    AppvClient
Cmdlet          Tee-Object                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          Test-AppLockerPolicy                               2.0.0.0    AppLocker
Cmdlet          Test-Certificate                                   1.0.0.0    PKI
Cmdlet          Test-ComputerSecureChannel                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          Test-Connection                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Test-DscConfiguration                              1.1        PSDesiredStateCon...
Cmdlet          Test-FileCatalog                                   3.0.0.0    Microsoft.PowerSh...
Cmdlet          Test-HgsTraceTarget                                1.0.0.0    HgsDiagnostics
Cmdlet          Test-KdsRootKey                                    1.0.0.0    Kds
Cmdlet          Test-ModuleManifest                                3.0.0.0    Microsoft.PowerSh...
Cmdlet          Test-Path                                          3.1.0.0    Microsoft.PowerSh...
Cmdlet          Test-PSSessionConfigurationFile                    3.0.0.0    Microsoft.PowerSh...
Cmdlet          Test-UevTemplate                                   2.1.639.0  UEV
Cmdlet          Test-VHD                                           2.0.0.0    Hyper-V
Cmdlet          Test-VMNetworkAdapter                              2.0.0.0    Hyper-V
Cmdlet          Test-VMReplicationConnection                       2.0.0.0    Hyper-V
Cmdlet          Test-WSMan                                         3.0.0.0    Microsoft.WSMan.M...
Cmdlet          Trace-Command                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Unblock-File                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Unblock-Tpm                                        2.0.0.0    TrustedPlatformMo...
Cmdlet          Undo-DtcDiagnosticTransaction                      1.0.0.0    MsDtc
Cmdlet          Undo-Transaction                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Uninstall-Package                                  1.0.0.1    PackageManagement
Cmdlet          Uninstall-ProvisioningPackage                      3.0        Provisioning
Cmdlet          Uninstall-TrustedProvisioningCertificate           3.0        Provisioning
Cmdlet          Unprotect-CmsMessage                               3.0.0.0    Microsoft.PowerSh...
Cmdlet          Unpublish-AppvClientPackage                        1.0.0.0    AppvClient
Cmdlet          Unregister-Event                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Unregister-PackageSource                           1.0.0.1    PackageManagement
Cmdlet          Unregister-PSSessionConfiguration                  3.0.0.0    Microsoft.PowerSh...
Cmdlet          Unregister-ScheduledJob                            1.1.0.0    PSScheduledJob
Cmdlet          Unregister-UevTemplate                             2.1.639.0  UEV
Cmdlet          Unregister-WindowsDeveloperLicense                 1.0.0.0    WindowsDeveloperL...
Cmdlet          Update-FormatData                                  3.1.0.0    Microsoft.PowerSh...
Cmdlet          Update-Help                                        3.0.0.0    Microsoft.PowerSh...
Cmdlet          Update-List                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Update-TypeData                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Update-UevTemplate                                 2.1.639.0  UEV
Cmdlet          Update-VMVersion                                   2.0.0.0    Hyper-V
Cmdlet          Update-WIMBootEntry                                3.0        Dism
Cmdlet          Use-Transaction                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Use-WindowsUnattend                                3.0        Dism
Cmdlet          Wait-Debugger                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Wait-Event                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          Wait-Job                                           3.0.0.0    Microsoft.PowerSh...
Cmdlet          Wait-Process                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Wait-VM                                            2.0.0.0    Hyper-V
Cmdlet          Where-Object                                       3.0.0.0    Microsoft.PowerSh...
Cmdlet          Write-Debug                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Write-Error                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Write-EventLog                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          Write-Host                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          Write-Information                                  3.1.0.0    Microsoft.PowerSh...
Cmdlet          Write-Output                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Write-Progress                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          Write-Verbose                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Write-Warning                                      3.1.0.0    Microsoft.PowerSh...

```
### Get-Command -Type Cmdlet | Sort-Object -Property Noun  使用(按照字母排序)
```
PS C:\windows\system32> Get-Command -Type Cmdlet | Sort-Object -Property Noun                      
CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Get-Acl                                            3.0.0.0    Microsoft.PowerSh...
Cmdlet          Set-Acl                                            3.0.0.0    Microsoft.PowerSh...
Cmdlet          Import-Alias                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Alias                                          3.1.0.0    Microsoft.PowerSh...
Cmdlet          New-Alias                                          3.1.0.0    Microsoft.PowerSh...
Cmdlet          Export-Alias                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-Alias                                          3.1.0.0    Microsoft.PowerSh...
Cmdlet          Enable-AppBackgroundTaskDiagnosticLog              1.0.0.0    AppBackgroundTask
Cmdlet          Disable-AppBackgroundTaskDiagnosticLog             1.0.0.0    AppBackgroundTask
Cmdlet          Set-AppBackgroundTaskResourcePolicy                1.0.0.0    AppBackgroundTask
Cmdlet          Get-AppLockerFileInformation                       2.0.0.0    AppLocker
Cmdlet          Set-AppLockerPolicy                                2.0.0.0    AppLocker
Cmdlet          Test-AppLockerPolicy                               2.0.0.0    AppLocker
Cmdlet          Get-AppLockerPolicy                                2.0.0.0    AppLocker
Cmdlet          New-AppLockerPolicy                                2.0.0.0    AppLocker
Cmdlet          Enable-Appv                                        1.0.0.0    AppvClient
Cmdlet          Disable-Appv                                       1.0.0.0    AppvClient
Cmdlet          Get-AppvClientApplication                          1.0.0.0    AppvClient
Cmdlet          Set-AppvClientConfiguration                        1.0.0.0    AppvClient
Cmdlet          Get-AppvClientConfiguration                        1.0.0.0    AppvClient
Cmdlet          Add-AppvClientConnectionGroup                      1.0.0.0    AppvClient
Cmdlet          Mount-AppvClientConnectionGroup                    1.0.0.0    AppvClient
Cmdlet          Repair-AppvClientConnectionGroup                   1.0.0.0    AppvClient
Cmdlet          Remove-AppvClientConnectionGroup                   1.0.0.0    AppvClient
Cmdlet          Get-AppvClientConnectionGroup                      1.0.0.0    AppvClient
Cmdlet          Stop-AppvClientConnectionGroup                     1.0.0.0    AppvClient
Cmdlet          Disable-AppvClientConnectionGroup                  1.0.0.0    AppvClient
Cmdlet          Enable-AppvClientConnectionGroup                   1.0.0.0    AppvClient
Cmdlet          Set-AppvClientMode                                 1.0.0.0    AppvClient
Cmdlet          Get-AppvClientMode                                 1.0.0.0    AppvClient
Cmdlet          Stop-AppvClientPackage                             1.0.0.0    AppvClient
Cmdlet          Unpublish-AppvClientPackage                        1.0.0.0    AppvClient
Cmdlet          Repair-AppvClientPackage                           1.0.0.0    AppvClient
Cmdlet          Get-AppvClientPackage                              1.0.0.0    AppvClient
Cmdlet          Publish-AppvClientPackage                          1.0.0.0    AppvClient
Cmdlet          Mount-AppvClientPackage                            1.0.0.0    AppvClient
Cmdlet          Add-AppvClientPackage                              1.0.0.0    AppvClient
Cmdlet          Set-AppvClientPackage                              1.0.0.0    AppvClient
Cmdlet          Remove-AppvClientPackage                           1.0.0.0    AppvClient
Cmdlet          Send-AppvClientReport                              1.0.0.0    AppvClient
Cmdlet          Remove-AppvPublishingServer                        1.0.0.0    AppvClient
Cmdlet          Add-AppvPublishingServer                           1.0.0.0    AppvClient
Cmdlet          Sync-AppvPublishingServer                          1.0.0.0    AppvClient
Cmdlet          Set-AppvPublishingServer                           1.0.0.0    AppvClient
Cmdlet          Get-AppvPublishingServer                           1.0.0.0    AppvClient
Cmdlet          Get-AppvStatus                                     1.0.0.0    AppvClient
Cmdlet          Set-AppxDefaultVolume                              2.0.1.0    Appx
Cmdlet          Get-AppxDefaultVolume                              2.0.1.0    Appx
Cmdlet          Move-AppxPackage                                   2.0.1.0    Appx
Cmdlet          Add-AppxPackage                                    2.0.1.0    Appx
Cmdlet          Remove-AppxPackage                                 2.0.1.0    Appx
Cmdlet          Get-AppxPackage                                    2.0.1.0    Appx
Cmdlet          Get-AppxPackageManifest                            2.0.1.0    Appx
Cmdlet          Set-AppXProvisionedDataFile                        3.0        Dism
Cmdlet          Remove-AppxProvisionedPackage                      3.0        Dism
Cmdlet          Add-AppxProvisionedPackage                         3.0        Dism
Cmdlet          Get-AppxProvisionedPackage                         3.0        Dism
Cmdlet          Optimize-AppxProvisionedPackages                   3.0        Dism
Cmdlet          Mount-AppxVolume                                   2.0.1.0    Appx
Cmdlet          Get-AppxVolume                                     2.0.1.0    Appx
Cmdlet          Dismount-AppxVolume                                2.0.1.0    Appx
Cmdlet          Remove-AppxVolume                                  2.0.1.0    Appx
Cmdlet          Add-AppxVolume                                     2.0.1.0    Appx
Cmdlet          Register-ArgumentCompleter                         3.0.0.0    Microsoft.PowerSh...
Cmdlet          Set-AuthenticodeSignature                          3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-AuthenticodeSignature                          3.0.0.0    Microsoft.PowerSh...
Cmdlet          Export-BinaryMiLog                                 1.0.0.0    CimCmdlets
Cmdlet          Import-BinaryMiLog                                 1.0.0.0    CimCmdlets
Cmdlet          Add-BitsFile                                       2.0.0.0    BitsTransfer
Cmdlet          Get-BitsTransfer                                   2.0.0.0    BitsTransfer
Cmdlet          Suspend-BitsTransfer                               2.0.0.0    BitsTransfer
Cmdlet          Start-BitsTransfer                                 2.0.0.0    BitsTransfer
Cmdlet          Set-BitsTransfer                                   2.0.0.0    BitsTransfer
Cmdlet          Resume-BitsTransfer                                2.0.0.0    BitsTransfer
Cmdlet          Complete-BitsTransfer                              2.0.0.0    BitsTransfer
Cmdlet          Remove-BitsTransfer                                2.0.0.0    BitsTransfer
Cmdlet          Import-Certificate                                 1.0.0.0    PKI
Cmdlet          Get-Certificate                                    1.0.0.0    PKI
Cmdlet          Test-Certificate                                   1.0.0.0    PKI
Cmdlet          Export-Certificate                                 1.0.0.0    PKI
Cmdlet          Switch-Certificate                                 1.0.0.0    PKI
Cmdlet          Set-CertificateAutoEnrollmentPolicy                1.0.0.0    PKI
Cmdlet          Get-CertificateAutoEnrollmentPolicy                1.0.0.0    PKI
Cmdlet          Add-CertificateEnrollmentPolicyServer              1.0.0.0    PKI
Cmdlet          Get-CertificateEnrollmentPolicyServer              1.0.0.0    PKI
Cmdlet          Remove-CertificateEnrollmentPolicyServer           1.0.0.0    PKI
Cmdlet          New-CertificateNotificationTask                    1.0.0.0    PKI
Cmdlet          Get-CertificateNotificationTask                    1.0.0.0    PKI
Cmdlet          Remove-CertificateNotificationTask                 1.0.0.0    PKI
Cmdlet          Get-ChildItem                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-CimAssociatedInstance                          1.0.0.0    CimCmdlets
Cmdlet          Get-CimClass                                       1.0.0.0    CimCmdlets
Cmdlet          Register-CimIndicationEvent                        1.0.0.0    CimCmdlets
Cmdlet          New-CimInstance                                    1.0.0.0    CimCmdlets
Cmdlet          Set-CimInstance                                    1.0.0.0    CimCmdlets
Cmdlet          Get-CimInstance                                    1.0.0.0    CimCmdlets
Cmdlet          Remove-CimInstance                                 1.0.0.0    CimCmdlets
Cmdlet          Invoke-CimMethod                                   1.0.0.0    CimCmdlets
Cmdlet          New-CimSession                                     1.0.0.0    CimCmdlets
Cmdlet          Remove-CimSession                                  1.0.0.0    CimCmdlets
Cmdlet          Get-CimSession                                     1.0.0.0    CimCmdlets
Cmdlet          New-CimSessionOption                               1.0.0.0    CimCmdlets
Cmdlet          ConvertFrom-CIPolicy                               1.0        ConfigCI
Cmdlet          Merge-CIPolicy                                     1.0        ConfigCI
Cmdlet          Get-CIPolicy                                       1.0        ConfigCI
Cmdlet          New-CIPolicy                                       1.0        ConfigCI
Cmdlet          Set-CIPolicyIdInfo                                 1.0        ConfigCI
Cmdlet          Get-CIPolicyIdInfo                                 1.0        ConfigCI
Cmdlet          Get-CIPolicyInfo                                   1.0        ConfigCI
Cmdlet          Edit-CIPolicyRule                                  1.0        ConfigCI
Cmdlet          Remove-CIPolicyRule                                1.0        ConfigCI
Cmdlet          New-CIPolicyRule                                   1.0        ConfigCI
Cmdlet          Set-CIPolicySetting                                1.0        ConfigCI
Cmdlet          Set-CIPolicyVersion                                1.0        ConfigCI
Cmdlet          Set-Clipboard                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Clipboard                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Export-Clixml                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Import-Clixml                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Unprotect-CmsMessage                               3.0.0.0    Microsoft.PowerSh...
Cmdlet          Protect-CmsMessage                                 3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-CmsMessage                                     3.0.0.0    Microsoft.PowerSh...
Cmdlet          Trace-Command                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Measure-Command                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Show-Command                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Command                                        3.0.0.0    Microsoft.PowerSh...
Cmdlet          Invoke-Command                                     3.0.0.0    Microsoft.PowerSh...
Cmdlet          Invoke-CommandInDesktopPackage                     2.0.1.0    Appx
Cmdlet          Stop-Computer                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Restart-Computer                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Add-Computer                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Restore-Computer                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Rename-Computer                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Remove-Computer                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Checkpoint-Computer                                3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-ComputerInfo                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Reset-ComputerMachinePassword                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Disable-ComputerRestore                            3.1.0.0    Microsoft.PowerSh...
Cmdlet          Enable-ComputerRestore                             3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-ComputerRestorePoint                           3.1.0.0    Microsoft.PowerSh...
Cmdlet          Test-ComputerSecureChannel                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          Test-Connection                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Export-Console                                     3.0.0.0    Microsoft.PowerSh...
Cmdlet          Clear-Content                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Add-Content                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-Content                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Content                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Show-ControlPanelItem                              3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-ControlPanelItem                               3.1.0.0    Microsoft.PowerSh...
Cmdlet          Export-Counter                                     3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-Counter                                        3.0.0.0    Microsoft.PowerSh...
Cmdlet          Import-Counter                                     3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-Credential                                     3.0.0.0    Microsoft.PowerSh...
Cmdlet          ConvertFrom-Csv                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Export-Csv                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          ConvertTo-Csv                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Import-Csv                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-Culture                                        2.0.0.0    International
Cmdlet          Get-Culture                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Format-Custom                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-DAPolicyChange                                 2.0.0.0    NetSecurity
Cmdlet          Set-Date                                           3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Date                                           3.1.0.0    Microsoft.PowerSh...
Cmdlet          Write-Debug                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Wait-Debugger                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Out-Default                                        3.0.0.0    Microsoft.PowerSh...
Cmdlet          Delete-DeliveryOptimizationCache                   1.0.2.0    DeliveryOptimization
Cmdlet          Get-DeliveryOptimizationLog                        1.0.2.0    DeliveryOptimization
Cmdlet          Get-DeliveryOptimizationPerfSnap                   1.0.2.0    DeliveryOptimization
Cmdlet          Get-DeliveryOptimizationPerfSnapThisMonth          1.0.2.0    DeliveryOptimization
Cmdlet          Get-DeliveryOptimizationStatus                     1.0.2.0    DeliveryOptimization
Cmdlet          Set-DeliveryOptimizationStatus                     1.0.2.0    DeliveryOptimization
Cmdlet          Resolve-DnsName                                    1.0.0.0    DnsClient
Cmdlet          Get-DOConfig                                       1.0.2.0    DeliveryOptimization
Cmdlet          Get-DODownloadMode                                 1.0.2.0    DeliveryOptimization
Cmdlet          Set-DODownloadMode                                 1.0.2.0    DeliveryOptimization
Cmdlet          Set-DOPercentageMaxBackgroundBandwidth             1.0.2.0    DeliveryOptimization
Cmdlet          Get-DOPercentageMaxBackgroundBandwidth             1.0.2.0    DeliveryOptimization
Cmdlet          Get-DOPercentageMaxForegroundBandwidth             1.0.2.0    DeliveryOptimization
Cmdlet          Set-DOPercentageMaxForegroundBandwidth             1.0.2.0    DeliveryOptimization
Cmdlet          Start-DscConfiguration                             1.1        PSDesiredStateCon...
Cmdlet          Publish-DscConfiguration                           1.1        PSDesiredStateCon...
Cmdlet          Test-DscConfiguration                              1.1        PSDesiredStateCon...
Cmdlet          Set-DscLocalConfigurationManager                   1.1        PSDesiredStateCon...
Cmdlet          Invoke-DscResource                                 1.1        PSDesiredStateCon...
Cmdlet          Join-DtcDiagnosticResourceManager                  1.0.0.0    MsDtc
Cmdlet          Start-DtcDiagnosticResourceManager                 1.0.0.0    MsDtc
Cmdlet          Stop-DtcDiagnosticResourceManager                  1.0.0.0    MsDtc
Cmdlet          Complete-DtcDiagnosticTransaction                  1.0.0.0    MsDtc
Cmdlet          New-DtcDiagnosticTransaction                       1.0.0.0    MsDtc
Cmdlet          Send-DtcDiagnosticTransaction                      1.0.0.0    MsDtc
Cmdlet          Undo-DtcDiagnosticTransaction                      1.0.0.0    MsDtc
Cmdlet          Receive-DtcDiagnosticTransaction                   1.0.0.0    MsDtc
Cmdlet          Register-EngineEvent                               3.1.0.0    Microsoft.PowerSh...
Cmdlet          Write-Error                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Unregister-Event                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Event                                          3.1.0.0    Microsoft.PowerSh...
Cmdlet          New-Event                                          3.1.0.0    Microsoft.PowerSh...
Cmdlet          Wait-Event                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          Remove-Event                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Clear-EventLog                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          New-EventLog                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-EventLog                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Limit-EventLog                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          Remove-EventLog                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Show-EventLog                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Write-EventLog                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-EventSubscriber                                3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-ExecutionPolicy                                3.0.0.0    Microsoft.PowerSh...
Cmdlet          Set-ExecutionPolicy                                3.0.0.0    Microsoft.PowerSh...
Cmdlet          Invoke-Expression                                  3.1.0.0    Microsoft.PowerSh...
Cmdlet          Unblock-File                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Out-File                                           3.1.0.0    Microsoft.PowerSh...
Cmdlet          New-FileCatalog                                    3.0.0.0    Microsoft.PowerSh...
Cmdlet          Test-FileCatalog                                   3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-FormatData                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          Export-FormatData                                  3.1.0.0    Microsoft.PowerSh...
Cmdlet          Update-FormatData                                  3.1.0.0    Microsoft.PowerSh...
Cmdlet          Out-GridView                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Help                                           3.0.0.0    Microsoft.PowerSh...
Cmdlet          Save-Help                                          3.0.0.0    Microsoft.PowerSh...
Cmdlet          Update-Help                                        3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-HgsAttestationBaselinePolicy                   1.0.0.0    HgsClient
Cmdlet          Get-HgsTrace                                       1.0.0.0    HgsDiagnostics
Cmdlet          Get-HgsTraceFileData                               1.0.0.0    HgsDiagnostics
Cmdlet          New-HgsTraceTarget                                 1.0.0.0    HgsDiagnostics
Cmdlet          Test-HgsTraceTarget                                1.0.0.0    HgsDiagnostics
Cmdlet          Clear-History                                      3.0.0.0    Microsoft.PowerSh...
Cmdlet          Invoke-History                                     3.0.0.0    Microsoft.PowerSh...
Cmdlet          Add-History                                        3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-History                                        3.0.0.0    Microsoft.PowerSh...
Cmdlet          Read-Host                                          3.1.0.0    Microsoft.PowerSh...
Cmdlet          Write-Host                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          Out-Host                                           3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-Host                                           3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-HotFix                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          ConvertTo-Html                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-HVCIOptions                                    1.0        ConfigCI
Cmdlet          Write-Information                                  3.1.0.0    Microsoft.PowerSh...
Cmdlet          Remove-Item                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Move-Item                                          3.1.0.0    Microsoft.PowerSh...
Cmdlet          Invoke-Item                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Item                                           3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-Item                                           3.1.0.0    Microsoft.PowerSh...
Cmdlet          Clear-Item                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          New-Item                                           3.1.0.0    Microsoft.PowerSh...
Cmdlet          Copy-Item                                          3.1.0.0    Microsoft.PowerSh...
Cmdlet          Rename-Item                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-ItemProperty                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Move-ItemProperty                                  3.1.0.0    Microsoft.PowerSh...
Cmdlet          Clear-ItemProperty                                 3.1.0.0    Microsoft.PowerSh...
Cmdlet          New-ItemProperty                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Remove-ItemProperty                                3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-ItemProperty                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Copy-ItemProperty                                  3.1.0.0    Microsoft.PowerSh...
Cmdlet          Rename-ItemProperty                                3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-ItemPropertyValue                              3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Job                                            3.0.0.0    Microsoft.PowerSh...
Cmdlet          Receive-Job                                        3.0.0.0    Microsoft.PowerSh...
Cmdlet          Resume-Job                                         3.0.0.0    Microsoft.PowerSh...
Cmdlet          Suspend-Job                                        3.0.0.0    Microsoft.PowerSh...
Cmdlet          Start-Job                                          3.0.0.0    Microsoft.PowerSh...
Cmdlet          Remove-Job                                         3.0.0.0    Microsoft.PowerSh...
Cmdlet          Debug-Job                                          3.0.0.0    Microsoft.PowerSh...
Cmdlet          Wait-Job                                           3.0.0.0    Microsoft.PowerSh...
Cmdlet          Stop-Job                                           3.0.0.0    Microsoft.PowerSh...
Cmdlet          Set-JobTrigger                                     1.1.0.0    PSScheduledJob
Cmdlet          Disable-JobTrigger                                 1.1.0.0    PSScheduledJob
Cmdlet          Get-JobTrigger                                     1.1.0.0    PSScheduledJob
Cmdlet          Enable-JobTrigger                                  1.1.0.0    PSScheduledJob
Cmdlet          Remove-JobTrigger                                  1.1.0.0    PSScheduledJob
Cmdlet          New-JobTrigger                                     1.1.0.0    PSScheduledJob
Cmdlet          Add-JobTrigger                                     1.1.0.0    PSScheduledJob
Cmdlet          ConvertTo-Json                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          ConvertFrom-Json                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Clear-KdsCache                                     1.0.0.0    Kds
Cmdlet          Get-KdsConfiguration                               1.0.0.0    Kds
Cmdlet          Set-KdsConfiguration                               1.0.0.0    Kds
Cmdlet          Add-KdsRootKey                                     1.0.0.0    Kds
Cmdlet          Test-KdsRootKey                                    1.0.0.0    Kds
Cmdlet          Get-KdsRootKey                                     1.0.0.0    Kds
Cmdlet          Update-List                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Format-List                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-LocalGroup                                     1.0.0.0    Microsoft.PowerSh...
Cmdlet          Rename-LocalGroup                                  1.0.0.0    Microsoft.PowerSh...
Cmdlet          Remove-LocalGroup                                  1.0.0.0    Microsoft.PowerSh...
Cmdlet          New-LocalGroup                                     1.0.0.0    Microsoft.PowerSh...
Cmdlet          Set-LocalGroup                                     1.0.0.0    Microsoft.PowerSh...
Cmdlet          Add-LocalGroupMember                               1.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-LocalGroupMember                               1.0.0.0    Microsoft.PowerSh...
Cmdlet          Remove-LocalGroupMember                            1.0.0.0    Microsoft.PowerSh...
Cmdlet          Import-LocalizedData                               3.1.0.0    Microsoft.PowerSh...
Cmdlet          Disable-LocalUser                                  1.0.0.0    Microsoft.PowerSh...
Cmdlet          Enable-LocalUser                                   1.0.0.0    Microsoft.PowerSh...
Cmdlet          Rename-LocalUser                                   1.0.0.0    Microsoft.PowerSh...
Cmdlet          New-LocalUser                                      1.0.0.0    Microsoft.PowerSh...
Cmdlet          Set-LocalUser                                      1.0.0.0    Microsoft.PowerSh...
Cmdlet          Remove-LocalUser                                   1.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-LocalUser                                      1.0.0.0    Microsoft.PowerSh...
Cmdlet          Push-Location                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Location                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Pop-Location                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-Location                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Send-MailMessage                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Member                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          Add-Member                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Module                                         3.0.0.0    Microsoft.PowerSh...
Cmdlet          Remove-Module                                      3.0.0.0    Microsoft.PowerSh...
Cmdlet          New-Module                                         3.0.0.0    Microsoft.PowerSh...
Cmdlet          Import-Module                                      3.0.0.0    Microsoft.PowerSh...
Cmdlet          New-ModuleManifest                                 3.0.0.0    Microsoft.PowerSh...
Cmdlet          Test-ModuleManifest                                3.0.0.0    Microsoft.PowerSh...
Cmdlet          Export-ModuleMember                                3.0.0.0    Microsoft.PowerSh...
Cmdlet          New-NetIPsecAuthProposal                           2.0.0.0    NetSecurity
Cmdlet          New-NetIPsecMainModeCryptoProposal                 2.0.0.0    NetSecurity
Cmdlet          New-NetIPsecQuickModeCryptoProposal                2.0.0.0    NetSecurity
Cmdlet          Set-NonRemovableAppsPolicy                         3.0        Dism
Cmdlet          Get-NonRemovableAppsPolicy                         3.0        Dism
Cmdlet          Out-Null                                           3.0.0.0    Microsoft.PowerSh...
Cmdlet          Group-Object                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Select-Object                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Where-Object                                       3.0.0.0    Microsoft.PowerSh...
Cmdlet          New-Object                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          Measure-Object                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          Tee-Object                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          Compare-Object                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          ForEach-Object                                     3.0.0.0    Microsoft.PowerSh...
Cmdlet          Sort-Object                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Register-ObjectEvent                               3.1.0.0    Microsoft.PowerSh...
Cmdlet          Start-OSUninstall                                  3.0        Dism
Cmdlet          Write-Output                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Install-Package                                    1.0.0.1    PackageManagement
Cmdlet          Get-Package                                        1.0.0.1    PackageManagement
Cmdlet          Save-Package                                       1.0.0.1    PackageManagement
Cmdlet          Uninstall-Package                                  1.0.0.1    PackageManagement
Cmdlet          Find-Package                                       1.0.0.1    PackageManagement
Cmdlet          Install-PackageProvider                            1.0.0.1    PackageManagement
Cmdlet          Get-PackageProvider                                1.0.0.1    PackageManagement
Cmdlet          Find-PackageProvider                               1.0.0.1    PackageManagement
Cmdlet          Import-PackageProvider                             1.0.0.1    PackageManagement
Cmdlet          Get-PackageSource                                  1.0.0.1    PackageManagement
Cmdlet          Set-PackageSource                                  1.0.0.1    PackageManagement
Cmdlet          Unregister-PackageSource                           1.0.0.1    PackageManagement
Cmdlet          Register-PackageSource                             1.0.0.1    PackageManagement
Cmdlet          Resolve-Path                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Test-Path                                          3.1.0.0    Microsoft.PowerSh...
Cmdlet          Split-Path                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          Convert-Path                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Join-Path                                          3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-PfxCertificate                                 3.0.0.0    Microsoft.PowerSh...
Cmdlet          Import-PfxCertificate                              1.0.0.0    PKI
Cmdlet          Export-PfxCertificate                              1.0.0.0    PKI
Cmdlet          Get-PfxData                                        1.0.0.0    PKI
Cmdlet          New-PmemDisk                                       1.0.0.0    PersistentMemory
Cmdlet          Get-PmemDisk                                       1.0.0.0    PersistentMemory
Cmdlet          Remove-PmemDisk                                    1.0.0.0    PersistentMemory
Cmdlet          Get-PmemPhysicalDevice                             1.0.0.0    PersistentMemory
Cmdlet          Initialize-PmemPhysicalDevice                      1.0.0.0    PersistentMemory
Cmdlet          Get-PmemUnusedRegion                               1.0.0.0    PersistentMemory
Cmdlet          Out-Printer                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Process                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Wait-Process                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Debug-Process                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Start-Process                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Stop-Process                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-ProcessMitigation                              1.0.11     ProcessMitigations
Cmdlet          Set-ProcessMitigation                              1.0.11     ProcessMitigations
Cmdlet          ConvertTo-ProcessMitigationPolicy                  1.0.11     ProcessMitigations
Cmdlet          Write-Progress                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          Export-ProvisioningPackage                         3.0        Provisioning
Cmdlet          Uninstall-ProvisioningPackage                      3.0        Provisioning
Cmdlet          Get-ProvisioningPackage                            3.0        Provisioning
Cmdlet          Install-ProvisioningPackage                        3.0        Provisioning
Cmdlet          New-ProvisioningRepro                              3.0        Provisioning
Cmdlet          Resume-ProvisioningSession                         3.0        Provisioning
Cmdlet          Disable-PSBreakpoint                               3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-PSBreakpoint                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Remove-PSBreakpoint                                3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-PSBreakpoint                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Enable-PSBreakpoint                                3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-PSCallStack                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-PSDebug                                        3.0.0.0    Microsoft.PowerSh...
Cmdlet          New-PSDrive                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Remove-PSDrive                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-PSDrive                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Enter-PSHostProcess                                3.0.0.0    Microsoft.PowerSh...
Cmdlet          Exit-PSHostProcess                                 3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-PSHostProcessInfo                              3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-PSProvider                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-PSReadLineKeyHandler                           2.0.0      PSReadline
Cmdlet          Get-PSReadLineKeyHandler                           2.0.0      PSReadline
Cmdlet          Remove-PSReadLineKeyHandler                        2.0.0      PSReadline
Cmdlet          Set-PSReadLineOption                               2.0.0      PSReadline
Cmdlet          Get-PSReadLineOption                               2.0.0      PSReadline
Cmdlet          Enable-PSRemoting                                  3.0.0.0    Microsoft.PowerSh...
Cmdlet          Disable-PSRemoting                                 3.0.0.0    Microsoft.PowerSh...
Cmdlet          New-PSRoleCapabilityFile                           3.0.0.0    Microsoft.PowerSh...
Cmdlet          Import-PSSession                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Enter-PSSession                                    3.0.0.0    Microsoft.PowerSh...
Cmdlet          Exit-PSSession                                     3.0.0.0    Microsoft.PowerSh...
Cmdlet          Disconnect-PSSession                               3.0.0.0    Microsoft.PowerSh...
Cmdlet          New-PSSession                                      3.0.0.0    Microsoft.PowerSh...
Cmdlet          Remove-PSSession                                   3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-PSSession                                      3.0.0.0    Microsoft.PowerSh...
Cmdlet          Receive-PSSession                                  3.0.0.0    Microsoft.PowerSh...
Cmdlet          Connect-PSSession                                  3.0.0.0    Microsoft.PowerSh...
Cmdlet          Export-PSSession                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-PSSessionCapability                            3.0.0.0    Microsoft.PowerSh...
Cmdlet          Unregister-PSSessionConfiguration                  3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-PSSessionConfiguration                         3.0.0.0    Microsoft.PowerSh...
Cmdlet          Enable-PSSessionConfiguration                      3.0.0.0    Microsoft.PowerSh...
Cmdlet          Register-PSSessionConfiguration                    3.0.0.0    Microsoft.PowerSh...
Cmdlet          Set-PSSessionConfiguration                         3.0.0.0    Microsoft.PowerSh...
Cmdlet          Disable-PSSessionConfiguration                     3.0.0.0    Microsoft.PowerSh...
Cmdlet          New-PSSessionConfigurationFile                     3.0.0.0    Microsoft.PowerSh...
Cmdlet          Test-PSSessionConfigurationFile                    3.0.0.0    Microsoft.PowerSh...
Cmdlet          New-PSSessionOption                                3.0.0.0    Microsoft.PowerSh...
Cmdlet          Remove-PSSnapin                                    3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-PSSnapin                                       3.0.0.0    Microsoft.PowerSh...
Cmdlet          Add-PSSnapin                                       3.0.0.0    Microsoft.PowerSh...
Cmdlet          New-PSTransportOption                              3.0.0.0    Microsoft.PowerSh...
Cmdlet          New-PSWorkflowExecutionOption                      2.0.0.0    PSWorkflow
Cmdlet          Get-Random                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          Clear-RecycleBin                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Invoke-RestMethod                                  3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-RuleOption                                     1.0        ConfigCI
Cmdlet          Debug-Runspace                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Runspace                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-RunspaceDebug                                  3.1.0.0    Microsoft.PowerSh...
Cmdlet          Enable-RunspaceDebug                               3.1.0.0    Microsoft.PowerSh...
Cmdlet          Disable-RunspaceDebug                              3.1.0.0    Microsoft.PowerSh...
Cmdlet          Register-ScheduledJob                              1.1.0.0    PSScheduledJob
Cmdlet          Set-ScheduledJob                                   1.1.0.0    PSScheduledJob
Cmdlet          Unregister-ScheduledJob                            1.1.0.0    PSScheduledJob
Cmdlet          Enable-ScheduledJob                                1.1.0.0    PSScheduledJob
Cmdlet          Disable-ScheduledJob                               1.1.0.0    PSScheduledJob
Cmdlet          Get-ScheduledJob                                   1.1.0.0    PSScheduledJob
Cmdlet          Get-ScheduledJobOption                             1.1.0.0    PSScheduledJob
Cmdlet          New-ScheduledJobOption                             1.1.0.0    PSScheduledJob
Cmdlet          Set-ScheduledJobOption                             1.1.0.0    PSScheduledJob
Cmdlet          Get-SecureBootPolicy                               2.0.0.0    SecureBoot
Cmdlet          Confirm-SecureBootUEFI                             2.0.0.0    SecureBoot
Cmdlet          Get-SecureBootUEFI                                 2.0.0.0    SecureBoot
Cmdlet          Set-SecureBootUEFI                                 2.0.0.0    SecureBoot
Cmdlet          Format-SecureBootUEFI                              2.0.0.0    SecureBoot
Cmdlet          ConvertTo-SecureString                             3.0.0.0    Microsoft.PowerSh...
Cmdlet          ConvertFrom-SecureString                           3.0.0.0    Microsoft.PowerSh...
Cmdlet          New-SelfSignedCertificate                          1.0.0.0    PKI
Cmdlet          Get-Service                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Resume-Service                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          Restart-Service                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-Service                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Start-Service                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Stop-Service                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Suspend-Service                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          New-Service                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Add-SignerRule                                     1.0        ConfigCI
Cmdlet          Start-Sleep                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Import-StartLayout                                 1.0.0.0    StartLayout
Cmdlet          Export-StartLayout                                 1.0.0.0    StartLayout
Cmdlet          Export-StartLayoutEdgeAssets                       1.0.0.0    StartLayout
Cmdlet          Set-StrictMode                                     3.0.0.0    Microsoft.PowerSh...
Cmdlet          Convert-String                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          ConvertFrom-String                                 3.1.0.0    Microsoft.PowerSh...
Cmdlet          Out-String                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          Select-String                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          ConvertFrom-StringData                             3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-SystemDriver                                   1.0        ConfigCI
Cmdlet          Format-Table                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          New-TimeSpan                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-TimeZone                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-TimeZone                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-TlsCipherSuite                                 2.0.0.0    TLS
Cmdlet          Enable-TlsCipherSuite                              2.0.0.0    TLS
Cmdlet          Disable-TlsCipherSuite                             2.0.0.0    TLS
Cmdlet          Get-TlsEccCurve                                    2.0.0.0    TLS
Cmdlet          Disable-TlsEccCurve                                2.0.0.0    TLS
Cmdlet          Enable-TlsEccCurve                                 2.0.0.0    TLS
Cmdlet          Enable-TlsSessionTicketKey                         2.0.0.0    TLS
Cmdlet          Export-TlsSessionTicketKey                         2.0.0.0    TLS
Cmdlet          Disable-TlsSessionTicketKey                        2.0.0.0    TLS
Cmdlet          New-TlsSessionTicketKey                            2.0.0.0    TLS
Cmdlet          Initialize-Tpm                                     2.0.0.0    TrustedPlatformMo...
Cmdlet          Clear-Tpm                                          2.0.0.0    TrustedPlatformMo...
Cmdlet          Unblock-Tpm                                        2.0.0.0    TrustedPlatformMo...
Cmdlet          Get-Tpm                                            2.0.0.0    TrustedPlatformMo...
Cmdlet          Enable-TpmAutoProvisioning                         2.0.0.0    TrustedPlatformMo...
Cmdlet          Disable-TpmAutoProvisioning                        2.0.0.0    TrustedPlatformMo...
Cmdlet          Get-TpmEndorsementKeyInfo                          2.0.0.0    TrustedPlatformMo...
Cmdlet          Import-TpmOwnerAuth                                2.0.0.0    TrustedPlatformMo...
Cmdlet          ConvertTo-TpmOwnerAuth                             2.0.0.0    TrustedPlatformMo...
Cmdlet          Set-TpmOwnerAuth                                   2.0.0.0    TrustedPlatformMo...
Cmdlet          Get-TpmSupportedFeature                            2.0.0.0    TrustedPlatformMo...
Cmdlet          Export-Trace                                       3.0        Provisioning
Cmdlet          Get-TraceSource                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-TraceSource                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Undo-Transaction                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Use-Transaction                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Start-Transaction                                  3.1.0.0    Microsoft.PowerSh...
Cmdlet          Complete-Transaction                               3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Transaction                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Start-Transcript                                   3.0.0.0    Microsoft.PowerSh...
Cmdlet          Stop-Transcript                                    3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-TroubleshootingPack                            1.0.0.0    TroubleshootingPack
Cmdlet          Invoke-TroubleshootingPack                         1.0.0.0    TroubleshootingPack
Cmdlet          Uninstall-TrustedProvisioningCertificate           3.0        Provisioning
Cmdlet          Get-TrustedProvisioningCertificate                 3.0        Provisioning
Cmdlet          Install-TrustedProvisioningCertificate             3.0        Provisioning
Cmdlet          Add-Type                                           3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-TypeData                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Remove-TypeData                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Update-TypeData                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Disable-Uev                                        2.1.639.0  UEV
Cmdlet          Enable-Uev                                         2.1.639.0  UEV
Cmdlet          Clear-UevAppxPackage                               2.1.639.0  UEV
Cmdlet          Get-UevAppxPackage                                 2.1.639.0  UEV
Cmdlet          Enable-UevAppxPackage                              2.1.639.0  UEV
Cmdlet          Disable-UevAppxPackage                             2.1.639.0  UEV
Cmdlet          Restore-UevBackup                                  2.1.639.0  UEV
Cmdlet          Set-UevConfiguration                               2.1.639.0  UEV
Cmdlet          Get-UevConfiguration                               2.1.639.0  UEV
Cmdlet          Clear-UevConfiguration                             2.1.639.0  UEV
Cmdlet          Import-UevConfiguration                            2.1.639.0  UEV
Cmdlet          Export-UevConfiguration                            2.1.639.0  UEV
Cmdlet          Export-UevPackage                                  2.1.639.0  UEV
Cmdlet          Get-UevStatus                                      2.1.639.0  UEV
Cmdlet          Enable-UevTemplate                                 2.1.639.0  UEV
Cmdlet          Test-UevTemplate                                   2.1.639.0  UEV
Cmdlet          Disable-UevTemplate                                2.1.639.0  UEV
Cmdlet          Get-UevTemplate                                    2.1.639.0  UEV
Cmdlet          Update-UevTemplate                                 2.1.639.0  UEV
Cmdlet          Register-UevTemplate                               2.1.639.0  UEV
Cmdlet          Unregister-UevTemplate                             2.1.639.0  UEV
Cmdlet          Repair-UevTemplateIndex                            2.1.639.0  UEV
Cmdlet          Set-UevTemplateProfile                             2.1.639.0  UEV
Cmdlet          Get-UevTemplateProgram                             2.1.639.0  UEV
Cmdlet          Restore-UevUserSetting                             2.1.639.0  UEV
Cmdlet          Get-UICulture                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Unique                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          Clear-Variable                                     3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-Variable                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Remove-Variable                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-Variable                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          New-Variable                                       3.1.0.0    Microsoft.PowerSh...
Cmdlet          Write-Verbose                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          New-VFD                                            2.0.0.0    Hyper-V
Cmdlet          Convert-VHD                                        2.0.0.0    Hyper-V
Cmdlet          Get-VHD                                            2.0.0.0    Hyper-V
Cmdlet          Optimize-VHD                                       2.0.0.0    Hyper-V
Cmdlet          Set-VHD                                            2.0.0.0    Hyper-V
Cmdlet          Merge-VHD                                          2.0.0.0    Hyper-V
Cmdlet          Resize-VHD                                         2.0.0.0    Hyper-V
Cmdlet          Mount-VHD                                          2.0.0.0    Hyper-V
Cmdlet          Dismount-VHD                                       2.0.0.0    Hyper-V
Cmdlet          Test-VHD                                           2.0.0.0    Hyper-V
Cmdlet          New-VHD                                            2.0.0.0    Hyper-V
Cmdlet          Get-VHDSet                                         2.0.0.0    Hyper-V
Cmdlet          Optimize-VHDSet                                    2.0.0.0    Hyper-V
Cmdlet          Get-VHDSnapshot                                    2.0.0.0    Hyper-V
Cmdlet          Remove-VHDSnapshot                                 2.0.0.0    Hyper-V
Cmdlet          Wait-VM                                            2.0.0.0    Hyper-V
Cmdlet          Remove-VM                                          2.0.0.0    Hyper-V
Cmdlet          Debug-VM                                           2.0.0.0    Hyper-V
Cmdlet          Set-VM                                             2.0.0.0    Hyper-V
Cmdlet          Move-VM                                            2.0.0.0    Hyper-V
Cmdlet          Stop-VM                                            2.0.0.0    Hyper-V
Cmdlet          Suspend-VM                                         2.0.0.0    Hyper-V
Cmdlet          Resume-VM                                          2.0.0.0    Hyper-V
Cmdlet          New-VM                                             2.0.0.0    Hyper-V
Cmdlet          Save-VM                                            2.0.0.0    Hyper-V
Cmdlet          Export-VM                                          2.0.0.0    Hyper-V
Cmdlet          Measure-VM                                         2.0.0.0    Hyper-V
Cmdlet          Restart-VM                                         2.0.0.0    Hyper-V
Cmdlet          Import-VM                                          2.0.0.0    Hyper-V
Cmdlet          Repair-VM                                          2.0.0.0    Hyper-V
Cmdlet          Compare-VM                                         2.0.0.0    Hyper-V
Cmdlet          Start-VM                                           2.0.0.0    Hyper-V
Cmdlet          Rename-VM                                          2.0.0.0    Hyper-V
Cmdlet          Get-VM                                             2.0.0.0    Hyper-V
Cmdlet          Checkpoint-VM                                      2.0.0.0    Hyper-V
Cmdlet          Remove-VMAssignableDevice                          2.0.0.0    Hyper-V
Cmdlet          Add-VMAssignableDevice                             2.0.0.0    Hyper-V
Cmdlet          Get-VMAssignableDevice                             2.0.0.0    Hyper-V
Cmdlet          Set-VMBios                                         2.0.0.0    Hyper-V
Cmdlet          Get-VMBios                                         2.0.0.0    Hyper-V
Cmdlet          Get-VMComPort                                      2.0.0.0    Hyper-V
Cmdlet          Set-VMComPort                                      2.0.0.0    Hyper-V
Cmdlet          Get-VMConnectAccess                                2.0.0.0    Hyper-V
Cmdlet          Revoke-VMConnectAccess                             2.0.0.0    Hyper-V
Cmdlet          Grant-VMConnectAccess                              2.0.0.0    Hyper-V
Cmdlet          Disable-VMConsoleSupport                           2.0.0.0    Hyper-V
Cmdlet          Enable-VMConsoleSupport                            2.0.0.0    Hyper-V
Cmdlet          Remove-VMDvdDrive                                  2.0.0.0    Hyper-V
Cmdlet          Set-VMDvdDrive                                     2.0.0.0    Hyper-V
Cmdlet          Add-VMDvdDrive                                     2.0.0.0    Hyper-V
Cmdlet          Get-VMDvdDrive                                     2.0.0.0    Hyper-V
Cmdlet          Disable-VMEventing                                 2.0.0.0    Hyper-V
Cmdlet          Enable-VMEventing                                  2.0.0.0    Hyper-V
Cmdlet          Stop-VMFailover                                    2.0.0.0    Hyper-V
Cmdlet          Complete-VMFailover                                2.0.0.0    Hyper-V
Cmdlet          Start-VMFailover                                   2.0.0.0    Hyper-V
Cmdlet          Set-VMFibreChannelHba                              2.0.0.0    Hyper-V
Cmdlet          Get-VMFibreChannelHba                              2.0.0.0    Hyper-V
Cmdlet          Remove-VMFibreChannelHba                           2.0.0.0    Hyper-V
Cmdlet          Add-VMFibreChannelHba                              2.0.0.0    Hyper-V
Cmdlet          Copy-VMFile                                        2.0.0.0    Hyper-V
Cmdlet          Get-VMFirmware                                     2.0.0.0    Hyper-V
Cmdlet          Set-VMFirmware                                     2.0.0.0    Hyper-V
Cmdlet          Get-VMFloppyDiskDrive                              2.0.0.0    Hyper-V
Cmdlet          Set-VMFloppyDiskDrive                              2.0.0.0    Hyper-V
Cmdlet          Add-VMGpuPartitionAdapter                          2.0.0.0    Hyper-V
Cmdlet          Remove-VMGpuPartitionAdapter                       2.0.0.0    Hyper-V
Cmdlet          Get-VMGpuPartitionAdapter                          2.0.0.0    Hyper-V
Cmdlet          Set-VMGpuPartitionAdapter                          2.0.0.0    Hyper-V
Cmdlet          Rename-VMGroup                                     2.0.0.0    Hyper-V
Cmdlet          Get-VMGroup                                        2.0.0.0    Hyper-V
Cmdlet          Remove-VMGroup                                     2.0.0.0    Hyper-V
Cmdlet          New-VMGroup                                        2.0.0.0    Hyper-V
Cmdlet          Add-VMGroupMember                                  2.0.0.0    Hyper-V
Cmdlet          Remove-VMGroupMember                               2.0.0.0    Hyper-V
Cmdlet          Get-VMHardDiskDrive                                2.0.0.0    Hyper-V
Cmdlet          Add-VMHardDiskDrive                                2.0.0.0    Hyper-V
Cmdlet          Remove-VMHardDiskDrive                             2.0.0.0    Hyper-V
Cmdlet          Set-VMHardDiskDrive                                2.0.0.0    Hyper-V
Cmdlet          Get-VMHost                                         2.0.0.0    Hyper-V
Cmdlet          Set-VMHost                                         2.0.0.0    Hyper-V
Cmdlet          Add-VMHostAssignableDevice                         2.0.0.0    Hyper-V
Cmdlet          Remove-VMHostAssignableDevice                      2.0.0.0    Hyper-V
Cmdlet          Mount-VMHostAssignableDevice                       2.0.0.0    Hyper-V
Cmdlet          Dismount-VMHostAssignableDevice                    2.0.0.0    Hyper-V
Cmdlet          Get-VMHostAssignableDevice                         2.0.0.0    Hyper-V
Cmdlet          Set-VMHostCluster                                  2.0.0.0    Hyper-V
Cmdlet          Get-VMHostCluster                                  2.0.0.0    Hyper-V
Cmdlet          Get-VMHostNumaNode                                 2.0.0.0    Hyper-V
Cmdlet          Get-VMHostNumaNodeStatus                           2.0.0.0    Hyper-V
Cmdlet          Get-VMHostSupportedVersion                         2.0.0.0    Hyper-V
Cmdlet          Get-VMIdeController                                2.0.0.0    Hyper-V
Cmdlet          Import-VMInitialReplication                        2.0.0.0    Hyper-V
Cmdlet          Stop-VMInitialReplication                          2.0.0.0    Hyper-V
Cmdlet          Start-VMInitialReplication                         2.0.0.0    Hyper-V
Cmdlet          Disable-VMIntegrationService                       2.0.0.0    Hyper-V
Cmdlet          Enable-VMIntegrationService                        2.0.0.0    Hyper-V
Cmdlet          Get-VMIntegrationService                           2.0.0.0    Hyper-V
Cmdlet          Set-VMKeyProtector                                 2.0.0.0    Hyper-V
Cmdlet          Get-VMKeyProtector                                 2.0.0.0    Hyper-V
Cmdlet          Remove-VMKeyStorageDrive                           2.0.0.0    Hyper-V
Cmdlet          Add-VMKeyStorageDrive                              2.0.0.0    Hyper-V
Cmdlet          Get-VMKeyStorageDrive                              2.0.0.0    Hyper-V
Cmdlet          Set-VMKeyStorageDrive                              2.0.0.0    Hyper-V
Cmdlet          Get-VMMemory                                       2.0.0.0    Hyper-V
Cmdlet          Set-VMMemory                                       2.0.0.0    Hyper-V
Cmdlet          Disable-VMMigration                                2.0.0.0    Hyper-V
Cmdlet          Enable-VMMigration                                 2.0.0.0    Hyper-V
Cmdlet          Get-VMMigrationNetwork                             2.0.0.0    Hyper-V
Cmdlet          Remove-VMMigrationNetwork                          2.0.0.0    Hyper-V
Cmdlet          Add-VMMigrationNetwork                             2.0.0.0    Hyper-V
Cmdlet          Set-VMMigrationNetwork                             2.0.0.0    Hyper-V
Cmdlet          Add-VMNetworkAdapter                               2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapter                               2.0.0.0    Hyper-V
Cmdlet          Remove-VMNetworkAdapter                            2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapter                               2.0.0.0    Hyper-V
Cmdlet          Test-VMNetworkAdapter                              2.0.0.0    Hyper-V
Cmdlet          Disconnect-VMNetworkAdapter                        2.0.0.0    Hyper-V
Cmdlet          Connect-VMNetworkAdapter                           2.0.0.0    Hyper-V
Cmdlet          Rename-VMNetworkAdapter                            2.0.0.0    Hyper-V
Cmdlet          Add-VMNetworkAdapterAcl                            2.0.0.0    Hyper-V
Cmdlet          Remove-VMNetworkAdapterAcl                         2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterAcl                            2.0.0.0    Hyper-V
Cmdlet          Add-VMNetworkAdapterExtendedAcl                    2.0.0.0    Hyper-V
Cmdlet          Remove-VMNetworkAdapterExtendedAcl                 2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterExtendedAcl                    2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapterFailoverConfiguration          2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterFailoverConfiguration          2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapterIsolation                      2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterIsolation                      2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterRdma                           2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapterRdma                           2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapterRoutingDomainMapping           2.0.0.0    Hyper-V
Cmdlet          Remove-VMNetworkAdapterRoutingDomainMapping        2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterRoutingDomainMapping           2.0.0.0    Hyper-V
Cmdlet          Add-VMNetworkAdapterRoutingDomainMapping           2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterTeamMapping                    2.0.0.0    Hyper-V
Cmdlet          Remove-VMNetworkAdapterTeamMapping                 2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapterTeamMapping                    2.0.0.0    Hyper-V
Cmdlet          Get-VMNetworkAdapterVlan                           2.0.0.0    Hyper-V
Cmdlet          Set-VMNetworkAdapterVlan                           2.0.0.0    Hyper-V
Cmdlet          Get-VMPartitionableGpu                             2.0.0.0    Hyper-V
Cmdlet          Set-VMPartitionableGpu                             2.0.0.0    Hyper-V
Cmdlet          Add-VMPmemController                               2.0.0.0    Hyper-V
Cmdlet          Get-VMPmemController                               2.0.0.0    Hyper-V
Cmdlet          Remove-VMPmemController                            2.0.0.0    Hyper-V
Cmdlet          Set-VMProcessor                                    2.0.0.0    Hyper-V
Cmdlet          Get-VMProcessor                                    2.0.0.0    Hyper-V
Cmdlet          Add-VMRemoteFx3dVideoAdapter                       2.0.0.0    Hyper-V
Cmdlet          Set-VMRemoteFx3dVideoAdapter                       2.0.0.0    Hyper-V
Cmdlet          Get-VMRemoteFx3dVideoAdapter                       2.0.0.0    Hyper-V
Cmdlet          Remove-VMRemoteFx3dVideoAdapter                    2.0.0.0    Hyper-V
Cmdlet          Disable-VMRemoteFXPhysicalVideoAdapter             2.0.0.0    Hyper-V
Cmdlet          Enable-VMRemoteFXPhysicalVideoAdapter              2.0.0.0    Hyper-V
Cmdlet          Get-VMRemoteFXPhysicalVideoAdapter                 2.0.0.0    Hyper-V
Cmdlet          Measure-VMReplication                              2.0.0.0    Hyper-V
Cmdlet          Remove-VMReplication                               2.0.0.0    Hyper-V
Cmdlet          Suspend-VMReplication                              2.0.0.0    Hyper-V
Cmdlet          Set-VMReplication                                  2.0.0.0    Hyper-V
Cmdlet          Resume-VMReplication                               2.0.0.0    Hyper-V
Cmdlet          Get-VMReplication                                  2.0.0.0    Hyper-V
Cmdlet          Enable-VMReplication                               2.0.0.0    Hyper-V
Cmdlet          Stop-VMReplication                                 2.0.0.0    Hyper-V
Cmdlet          New-VMReplicationAuthorizationEntry                2.0.0.0    Hyper-V
Cmdlet          Set-VMReplicationAuthorizationEntry                2.0.0.0    Hyper-V
Cmdlet          Get-VMReplicationAuthorizationEntry                2.0.0.0    Hyper-V
Cmdlet          Remove-VMReplicationAuthorizationEntry             2.0.0.0    Hyper-V
Cmdlet          Test-VMReplicationConnection                       2.0.0.0    Hyper-V
Cmdlet          Set-VMReplicationServer                            2.0.0.0    Hyper-V
Cmdlet          Get-VMReplicationServer                            2.0.0.0    Hyper-V
Cmdlet          Reset-VMReplicationStatistics                      2.0.0.0    Hyper-V
Cmdlet          Reset-VMResourceMetering                           2.0.0.0    Hyper-V
Cmdlet          Disable-VMResourceMetering                         2.0.0.0    Hyper-V
Cmdlet          Enable-VMResourceMetering                          2.0.0.0    Hyper-V
Cmdlet          Remove-VMResourcePool                              2.0.0.0    Hyper-V
Cmdlet          New-VMResourcePool                                 2.0.0.0    Hyper-V
Cmdlet          Get-VMResourcePool                                 2.0.0.0    Hyper-V
Cmdlet          Measure-VMResourcePool                             2.0.0.0    Hyper-V
Cmdlet          Rename-VMResourcePool                              2.0.0.0    Hyper-V
Cmdlet          Set-VMResourcePool                                 2.0.0.0    Hyper-V
Cmdlet          Set-VMSan                                          2.0.0.0    Hyper-V
Cmdlet          Disconnect-VMSan                                   2.0.0.0    Hyper-V
Cmdlet          Rename-VMSan                                       2.0.0.0    Hyper-V
Cmdlet          Get-VMSan                                          2.0.0.0    Hyper-V
Cmdlet          New-VMSan                                          2.0.0.0    Hyper-V
Cmdlet          Remove-VMSan                                       2.0.0.0    Hyper-V
Cmdlet          Connect-VMSan                                      2.0.0.0    Hyper-V
Cmdlet          Remove-VMSavedState                                2.0.0.0    Hyper-V
Cmdlet          Get-VMScsiController                               2.0.0.0    Hyper-V
Cmdlet          Add-VMScsiController                               2.0.0.0    Hyper-V
Cmdlet          Remove-VMScsiController                            2.0.0.0    Hyper-V
Cmdlet          Get-VMSecurity                                     2.0.0.0    Hyper-V
Cmdlet          Set-VMSecurity                                     2.0.0.0    Hyper-V
Cmdlet          Set-VMSecurityPolicy                               2.0.0.0    Hyper-V
Cmdlet          Get-VMSnapshot                                     2.0.0.0    Hyper-V
Cmdlet          Restore-VMSnapshot                                 2.0.0.0    Hyper-V
Cmdlet          Remove-VMSnapshot                                  2.0.0.0    Hyper-V
Cmdlet          Rename-VMSnapshot                                  2.0.0.0    Hyper-V
Cmdlet          Export-VMSnapshot                                  2.0.0.0    Hyper-V
Cmdlet          Move-VMStorage                                     2.0.0.0    Hyper-V
Cmdlet          Remove-VMStoragePath                               2.0.0.0    Hyper-V
Cmdlet          Add-VMStoragePath                                  2.0.0.0    Hyper-V
Cmdlet          Get-VMStoragePath                                  2.0.0.0    Hyper-V
Cmdlet          Set-VMStorageSettings                              2.0.0.0    Hyper-V
Cmdlet          Get-VMStorageSettings                              2.0.0.0    Hyper-V
Cmdlet          Rename-VMSwitch                                    2.0.0.0    Hyper-V
Cmdlet          Add-VMSwitch                                       2.0.0.0    Hyper-V
Cmdlet          New-VMSwitch                                       2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitch                                       2.0.0.0    Hyper-V
Cmdlet          Set-VMSwitch                                       2.0.0.0    Hyper-V
Cmdlet          Remove-VMSwitch                                    2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitchExtension                              2.0.0.0    Hyper-V
Cmdlet          Enable-VMSwitchExtension                           2.0.0.0    Hyper-V
Cmdlet          Disable-VMSwitchExtension                          2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitchExtensionPortData                      2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitchExtensionPortFeature                   2.0.0.0    Hyper-V
Cmdlet          Add-VMSwitchExtensionPortFeature                   2.0.0.0    Hyper-V
Cmdlet          Set-VMSwitchExtensionPortFeature                   2.0.0.0    Hyper-V
Cmdlet          Remove-VMSwitchExtensionPortFeature                2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitchExtensionSwitchData                    2.0.0.0    Hyper-V
Cmdlet          Remove-VMSwitchExtensionSwitchFeature              2.0.0.0    Hyper-V
Cmdlet          Add-VMSwitchExtensionSwitchFeature                 2.0.0.0    Hyper-V
Cmdlet          Set-VMSwitchExtensionSwitchFeature                 2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitchExtensionSwitchFeature                 2.0.0.0    Hyper-V
Cmdlet          Set-VMSwitchTeam                                   2.0.0.0    Hyper-V
Cmdlet          Get-VMSwitchTeam                                   2.0.0.0    Hyper-V
Cmdlet          Remove-VMSwitchTeamMember                          2.0.0.0    Hyper-V
Cmdlet          Add-VMSwitchTeamMember                             2.0.0.0    Hyper-V
Cmdlet          Get-VMSystemSwitchExtension                        2.0.0.0    Hyper-V
Cmdlet          Get-VMSystemSwitchExtensionPortFeature             2.0.0.0    Hyper-V
Cmdlet          Get-VMSystemSwitchExtensionSwitchFeature           2.0.0.0    Hyper-V
Cmdlet          Enable-VMTPM                                       2.0.0.0    Hyper-V
Cmdlet          Disable-VMTPM                                      2.0.0.0    Hyper-V
Cmdlet          Start-VMTrace                                      2.0.0.0    Hyper-V
Cmdlet          Stop-VMTrace                                       2.0.0.0    Hyper-V
Cmdlet          Update-VMVersion                                   2.0.0.0    Hyper-V
Cmdlet          Set-VMVideo                                        2.0.0.0    Hyper-V
Cmdlet          Get-VMVideo                                        2.0.0.0    Hyper-V
Cmdlet          Write-Warning                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Invoke-WebRequest                                  3.1.0.0    Microsoft.PowerSh...
Cmdlet          New-WebServiceProxy                                3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-WheaMemoryPolicy                               2.0.0.0    Whea
Cmdlet          Get-WheaMemoryPolicy                               2.0.0.0    Whea
Cmdlet          Format-Wide                                        3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-WIMBootEntry                                   3.0        Dism
Cmdlet          Update-WIMBootEntry                                3.0        Dism
Cmdlet          Set-WinAcceptLanguageFromLanguageListOptOut        2.0.0.0    International
Cmdlet          Get-WinAcceptLanguageFromLanguageListOptOut        2.0.0.0    International
Cmdlet          Set-WinCultureFromLanguageListOptOut               2.0.0.0    International
Cmdlet          Get-WinCultureFromLanguageListOptOut               2.0.0.0    International
Cmdlet          Get-WinDefaultInputMethodOverride                  2.0.0.0    International
Cmdlet          Set-WinDefaultInputMethodOverride                  2.0.0.0    International
Cmdlet          Add-WindowsCapability                              3.0        Dism
Cmdlet          Get-WindowsCapability                              3.0        Dism
Cmdlet          Remove-WindowsCapability                           3.0        Dism
Cmdlet          Export-WindowsCapabilitySource                     3.0        Dism
Cmdlet          Clear-WindowsCorruptMountPoint                     3.0        Dism
Cmdlet          Expand-WindowsCustomDataImage                      3.0        Dism
Cmdlet          New-WindowsCustomImage                             3.0        Dism
Cmdlet          Unregister-WindowsDeveloperLicense                 1.0.0.0    WindowsDeveloperL...
Cmdlet          Get-WindowsDeveloperLicense                        1.0.0.0    WindowsDeveloperL...
Cmdlet          Show-WindowsDeveloperLicenseRegistration           1.0.0.0    WindowsDeveloperL...
Cmdlet          Remove-WindowsDriver                               3.0        Dism
Cmdlet          Add-WindowsDriver                                  3.0        Dism
Cmdlet          Get-WindowsDriver                                  3.0        Dism
Cmdlet          Export-WindowsDriver                               3.0        Dism
Cmdlet          Set-WindowsEdition                                 3.0        Dism
Cmdlet          Get-WindowsEdition                                 3.0        Dism
Cmdlet          Enable-WindowsErrorReporting                       1.0        WindowsErrorRepor...
Cmdlet          Get-WindowsErrorReporting                          1.0        WindowsErrorRepor...
Cmdlet          Disable-WindowsErrorReporting                      1.0        WindowsErrorRepor...
Cmdlet          Add-WindowsImage                                   3.0        Dism
Cmdlet          Get-WindowsImage                                   3.0        Dism
Cmdlet          Save-WindowsImage                                  3.0        Dism
Cmdlet          Remove-WindowsImage                                3.0        Dism
Cmdlet          Optimize-WindowsImage                              3.0        Dism
Cmdlet          Split-WindowsImage                                 3.0        Dism
Cmdlet          Export-WindowsImage                                3.0        Dism
Cmdlet          Repair-WindowsImage                                3.0        Dism
Cmdlet          New-WindowsImage                                   3.0        Dism
Cmdlet          Dismount-WindowsImage                              3.0        Dism
Cmdlet          Mount-WindowsImage                                 3.0        Dism
Cmdlet          Expand-WindowsImage                                3.0        Dism
Cmdlet          Get-WindowsImageContent                            3.0        Dism
Cmdlet          Disable-WindowsOptionalFeature                     3.0        Dism
Cmdlet          Get-WindowsOptionalFeature                         3.0        Dism
Cmdlet          Enable-WindowsOptionalFeature                      3.0        Dism
Cmdlet          Add-WindowsPackage                                 3.0        Dism
Cmdlet          Remove-WindowsPackage                              3.0        Dism
Cmdlet          Get-WindowsPackage                                 3.0        Dism
Cmdlet          Set-WindowsProductKey                              3.0        Dism
Cmdlet          Get-WindowsSearchSetting                           1.0.0.0    WindowsSearch
Cmdlet          Set-WindowsSearchSetting                           1.0.0.0    WindowsSearch
Cmdlet          Use-WindowsUnattend                                3.0        Dism
Cmdlet          Get-WinEvent                                       3.0.0.0    Microsoft.PowerSh...
Cmdlet          New-WinEvent                                       3.0.0.0    Microsoft.PowerSh...
Cmdlet          Get-WinHomeLocation                                2.0.0.0    International
Cmdlet          Set-WinHomeLocation                                2.0.0.0    International
Cmdlet          Set-WinLanguageBarOption                           2.0.0.0    International
Cmdlet          Get-WinLanguageBarOption                           2.0.0.0    International
Cmdlet          Set-WinSystemLocale                                2.0.0.0    International
Cmdlet          Get-WinSystemLocale                                2.0.0.0    International
Cmdlet          Get-WinUILanguageOverride                          2.0.0.0    International
Cmdlet          Set-WinUILanguageOverride                          2.0.0.0    International
Cmdlet          Set-WinUserLanguageList                            2.0.0.0    International
Cmdlet          New-WinUserLanguageList                            2.0.0.0    International
Cmdlet          Get-WinUserLanguageList                            2.0.0.0    International
Cmdlet          Register-WmiEvent                                  3.1.0.0    Microsoft.PowerSh...
Cmdlet          Set-WmiInstance                                    3.1.0.0    Microsoft.PowerSh...
Cmdlet          Invoke-WmiMethod                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Remove-WmiObject                                   3.1.0.0    Microsoft.PowerSh...
Cmdlet          Get-WmiObject                                      3.1.0.0    Microsoft.PowerSh...
Cmdlet          Disconnect-WSMan                                   3.0.0.0    Microsoft.WSMan.M...
Cmdlet          Connect-WSMan                                      3.0.0.0    Microsoft.WSMan.M...
Cmdlet          Test-WSMan                                         3.0.0.0    Microsoft.WSMan.M...
Cmdlet          Invoke-WSManAction                                 3.0.0.0    Microsoft.WSMan.M...
Cmdlet          Get-WSManCredSSP                                   3.0.0.0    Microsoft.WSMan.M...
Cmdlet          Disable-WSManCredSSP                               3.0.0.0    Microsoft.WSMan.M...
Cmdlet          Enable-WSManCredSSP                                3.0.0.0    Microsoft.WSMan.M...
Cmdlet          New-WSManInstance                                  3.0.0.0    Microsoft.WSMan.M...
Cmdlet          Set-WSManInstance                                  3.0.0.0    Microsoft.WSMan.M...
Cmdlet          Remove-WSManInstance                               3.0.0.0    Microsoft.WSMan.M...
Cmdlet          Get-WSManInstance                                  3.0.0.0    Microsoft.WSMan.M...
Cmdlet          Set-WSManQuickConfig                               3.0.0.0    Microsoft.WSMan.M...
Cmdlet          New-WSManSessionOption                             3.0.0.0    Microsoft.WSMan.M...
Cmdlet          Select-Xml                                         3.1.0.0    Microsoft.PowerSh...
Cmdlet          ConvertTo-Xml                                      3.1.0.0    Microsoft.PowerSh...

```
### Get-Command -Type Cmdlet | Format-Table -GroupBy Noun 使用
```
Cmdlet          Invoke-WebRequest                                  3.1.0.0    Microsoft.PowerSh...


   Noun: WmiMethod

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Invoke-WmiMethod                                   3.1.0.0    Microsoft.PowerSh...


   Noun: WSManAction

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Invoke-WSManAction                                 3.0.0.0    Microsoft.WSMan.M...


   Noun: DtcDiagnosticResourceManager

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Join-DtcDiagnosticResourceManager                  1.0.0.0    MsDtc


   Noun: Path

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Join-Path                                          3.1.0.0    Microsoft.PowerSh...


   Noun: EventLog

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Limit-EventLog                                     3.1.0.0    Microsoft.PowerSh...


   Noun: Command

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Measure-Command                                    3.1.0.0    Microsoft.PowerSh...


   Noun: Object

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Measure-Object                                     3.1.0.0    Microsoft.PowerSh...


   Noun: VM

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Measure-VM                                         2.0.0.0    Hyper-V


   Noun: VMReplication

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Measure-VMReplication                              2.0.0.0    Hyper-V


   Noun: VMResourcePool

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Measure-VMResourcePool                             2.0.0.0    Hyper-V


   Noun: CIPolicy

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Merge-CIPolicy                                     1.0        ConfigCI


   Noun: VHD

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Merge-VHD                                          2.0.0.0    Hyper-V


   Noun: AppvClientConnectionGroup

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Mount-AppvClientConnectionGroup                    1.0.0.0    AppvClient


   Noun: AppvClientPackage

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Mount-AppvClientPackage                            1.0.0.0    AppvClient


   Noun: AppxVolume

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Mount-AppxVolume                                   2.0.1.0    Appx


   Noun: VHD

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Mount-VHD                                          2.0.0.0    Hyper-V


   Noun: VMHostAssignableDevice

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Mount-VMHostAssignableDevice                       2.0.0.0    Hyper-V


   Noun: WindowsImage

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Mount-WindowsImage                                 3.0        Dism


   Noun: AppxPackage

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Move-AppxPackage                                   2.0.1.0    Appx


   Noun: Item

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Move-Item                                          3.1.0.0    Microsoft.PowerSh...


   Noun: ItemProperty

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Move-ItemProperty                                  3.1.0.0    Microsoft.PowerSh...


   Noun: VM

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Move-VM                                            2.0.0.0    Hyper-V


   Noun: VMStorage

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Move-VMStorage                                     2.0.0.0    Hyper-V


   Noun: Alias

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-Alias                                          3.1.0.0    Microsoft.PowerSh...


   Noun: AppLockerPolicy

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-AppLockerPolicy                                2.0.0.0    AppLocker


   Noun: CertificateNotificationTask

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-CertificateNotificationTask                    1.0.0.0    PKI


   Noun: CimInstance

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-CimInstance                                    1.0.0.0    CimCmdlets


   Noun: CimSession

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-CimSession                                     1.0.0.0    CimCmdlets


   Noun: CimSessionOption

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-CimSessionOption                               1.0.0.0    CimCmdlets


   Noun: CIPolicy

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-CIPolicy                                       1.0        ConfigCI


   Noun: CIPolicyRule

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-CIPolicyRule                                   1.0        ConfigCI


   Noun: DtcDiagnosticTransaction

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-DtcDiagnosticTransaction                       1.0.0.0    MsDtc


   Noun: Event

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-Event                                          3.1.0.0    Microsoft.PowerSh...


   Noun: EventLog

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-EventLog                                       3.1.0.0    Microsoft.PowerSh...


   Noun: FileCatalog

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-FileCatalog                                    3.0.0.0    Microsoft.PowerSh...


   Noun: HgsTraceTarget

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-HgsTraceTarget                                 1.0.0.0    HgsDiagnostics


   Noun: Item

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-Item                                           3.1.0.0    Microsoft.PowerSh...


   Noun: ItemProperty

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-ItemProperty                                   3.1.0.0    Microsoft.PowerSh...


   Noun: JobTrigger

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-JobTrigger                                     1.1.0.0    PSScheduledJob


   Noun: LocalGroup

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-LocalGroup                                     1.0.0.0    Microsoft.PowerSh...


   Noun: LocalUser

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-LocalUser                                      1.0.0.0    Microsoft.PowerSh...


   Noun: Module

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-Module                                         3.0.0.0    Microsoft.PowerSh...


   Noun: ModuleManifest

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-ModuleManifest                                 3.0.0.0    Microsoft.PowerSh...


   Noun: NetIPsecAuthProposal

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-NetIPsecAuthProposal                           2.0.0.0    NetSecurity


   Noun: NetIPsecMainModeCryptoProposal

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-NetIPsecMainModeCryptoProposal                 2.0.0.0    NetSecurity


   Noun: NetIPsecQuickModeCryptoProposal

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-NetIPsecQuickModeCryptoProposal                2.0.0.0    NetSecurity


   Noun: Object

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-Object                                         3.1.0.0    Microsoft.PowerSh...


   Noun: PmemDisk

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-PmemDisk                                       1.0.0.0    PersistentMemory


   Noun: ProvisioningRepro

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-ProvisioningRepro                              3.0        Provisioning


   Noun: PSDrive

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-PSDrive                                        3.1.0.0    Microsoft.PowerSh...


   Noun: PSRoleCapabilityFile

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-PSRoleCapabilityFile                           3.0.0.0    Microsoft.PowerSh...


   Noun: PSSession

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-PSSession                                      3.0.0.0    Microsoft.PowerSh...


   Noun: PSSessionConfigurationFile

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-PSSessionConfigurationFile                     3.0.0.0    Microsoft.PowerSh...


   Noun: PSSessionOption

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-PSSessionOption                                3.0.0.0    Microsoft.PowerSh...


   Noun: PSTransportOption

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-PSTransportOption                              3.0.0.0    Microsoft.PowerSh...


   Noun: PSWorkflowExecutionOption

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-PSWorkflowExecutionOption                      2.0.0.0    PSWorkflow


   Noun: ScheduledJobOption

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-ScheduledJobOption                             1.1.0.0    PSScheduledJob


   Noun: SelfSignedCertificate

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-SelfSignedCertificate                          1.0.0.0    PKI


   Noun: Service

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-Service                                        3.1.0.0    Microsoft.PowerSh...


   Noun: TimeSpan

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-TimeSpan                                       3.1.0.0    Microsoft.PowerSh...


   Noun: TlsSessionTicketKey

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-TlsSessionTicketKey                            2.0.0.0    TLS


   Noun: Variable

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-Variable                                       3.1.0.0    Microsoft.PowerSh...


   Noun: VFD

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-VFD                                            2.0.0.0    Hyper-V


   Noun: VHD

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-VHD                                            2.0.0.0    Hyper-V


   Noun: VM

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-VM                                             2.0.0.0    Hyper-V


   Noun: VMGroup

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-VMGroup                                        2.0.0.0    Hyper-V


   Noun: VMReplicationAuthorizationEntry

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-VMReplicationAuthorizationEntry                2.0.0.0    Hyper-V


   Noun: VMResourcePool

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-VMResourcePool                                 2.0.0.0    Hyper-V


   Noun: VMSan

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-VMSan                                          2.0.0.0    Hyper-V


   Noun: VMSwitch

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-VMSwitch                                       2.0.0.0    Hyper-V


   Noun: WebServiceProxy

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-WebServiceProxy                                3.1.0.0    Microsoft.PowerSh...


   Noun: WindowsCustomImage

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-WindowsCustomImage                             3.0        Dism


   Noun: WindowsImage

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-WindowsImage                                   3.0        Dism


   Noun: WinEvent

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-WinEvent                                       3.0.0.0    Microsoft.PowerSh...


   Noun: WinUserLanguageList

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-WinUserLanguageList                            2.0.0.0    International


   Noun: WSManInstance

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-WSManInstance                                  3.0.0.0    Microsoft.WSMan.M...


   Noun: WSManSessionOption

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          New-WSManSessionOption                             3.0.0.0    Microsoft.WSMan.M...


   Noun: AppxProvisionedPackages

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Optimize-AppxProvisionedPackages                   3.0        Dism


   Noun: VHD

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Optimize-VHD                                       2.0.0.0    Hyper-V


   Noun: VHDSet

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Optimize-VHDSet                                    2.0.0.0    Hyper-V


   Noun: WindowsImage

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Optimize-WindowsImage                              3.0        Dism


   Noun: Default

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Out-Default                                        3.0.0.0    Microsoft.PowerSh...


   Noun: File

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Out-File                                           3.1.0.0    Microsoft.PowerSh...


   Noun: GridView

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Out-GridView                                       3.1.0.0    Microsoft.PowerSh...


   Noun: Host

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Out-Host                                           3.0.0.0    Microsoft.PowerSh...


   Noun: Null

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Out-Null                                           3.0.0.0    Microsoft.PowerSh...


   Noun: Printer

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Out-Printer                                        3.1.0.0    Microsoft.PowerSh...


   Noun: String

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Out-String                                         3.1.0.0    Microsoft.PowerSh...


   Noun: Location

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Pop-Location                                       3.1.0.0    Microsoft.PowerSh...


   Noun: CmsMessage

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Protect-CmsMessage                                 3.0.0.0    Microsoft.PowerSh...


   Noun: AppvClientPackage

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Publish-AppvClientPackage                          1.0.0.0    AppvClient


   Noun: DscConfiguration

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Publish-DscConfiguration                           1.1        PSDesiredStateCon...


   Noun: Location

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Push-Location                                      3.1.0.0    Microsoft.PowerSh...


   Noun: Host

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Read-Host                                          3.1.0.0    Microsoft.PowerSh...


   Noun: DtcDiagnosticTransaction

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Receive-DtcDiagnosticTransaction                   1.0.0.0    MsDtc


   Noun: Job

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Receive-Job                                        3.0.0.0    Microsoft.PowerSh...


   Noun: PSSession

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Receive-PSSession                                  3.0.0.0    Microsoft.PowerSh...


   Noun: ArgumentCompleter

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Register-ArgumentCompleter                         3.0.0.0    Microsoft.PowerSh...


   Noun: CimIndicationEvent

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Register-CimIndicationEvent                        1.0.0.0    CimCmdlets


   Noun: EngineEvent

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Register-EngineEvent                               3.1.0.0    Microsoft.PowerSh...


   Noun: ObjectEvent

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Register-ObjectEvent                               3.1.0.0    Microsoft.PowerSh...


   Noun: PackageSource

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Register-PackageSource                             1.0.0.1    PackageManagement


   Noun: PSSessionConfiguration

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Register-PSSessionConfiguration                    3.0.0.0    Microsoft.PowerSh...


   Noun: ScheduledJob

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Register-ScheduledJob                              1.1.0.0    PSScheduledJob


   Noun: UevTemplate

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Register-UevTemplate                               2.1.639.0  UEV


   Noun: WmiEvent

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Register-WmiEvent                                  3.1.0.0    Microsoft.PowerSh...


   Noun: AppvClientConnectionGroup

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-AppvClientConnectionGroup                   1.0.0.0    AppvClient


   Noun: AppvClientPackage

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-AppvClientPackage                           1.0.0.0    AppvClient


   Noun: AppvPublishingServer

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-AppvPublishingServer                        1.0.0.0    AppvClient


   Noun: AppxPackage

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-AppxPackage                                 2.0.1.0    Appx


   Noun: AppxProvisionedPackage

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-AppxProvisionedPackage                      3.0        Dism


   Noun: AppxVolume

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-AppxVolume                                  2.0.1.0    Appx


   Noun: BitsTransfer

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-BitsTransfer                                2.0.0.0    BitsTransfer


   Noun: CertificateEnrollmentPolicyServer

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-CertificateEnrollmentPolicyServer           1.0.0.0    PKI


   Noun: CertificateNotificationTask

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-CertificateNotificationTask                 1.0.0.0    PKI


   Noun: CimInstance

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-CimInstance                                 1.0.0.0    CimCmdlets


   Noun: CimSession

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-CimSession                                  1.0.0.0    CimCmdlets


   Noun: CIPolicyRule

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-CIPolicyRule                                1.0        ConfigCI


   Noun: Computer

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-Computer                                    3.1.0.0    Microsoft.PowerSh...


   Noun: Event

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-Event                                       3.1.0.0    Microsoft.PowerSh...


   Noun: EventLog

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-EventLog                                    3.1.0.0    Microsoft.PowerSh...


   Noun: Item

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-Item                                        3.1.0.0    Microsoft.PowerSh...


   Noun: ItemProperty

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-ItemProperty                                3.1.0.0    Microsoft.PowerSh...


   Noun: Job

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-Job                                         3.0.0.0    Microsoft.PowerSh...


   Noun: JobTrigger

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-JobTrigger                                  1.1.0.0    PSScheduledJob


   Noun: LocalGroup

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-LocalGroup                                  1.0.0.0    Microsoft.PowerSh...


   Noun: LocalGroupMember

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-LocalGroupMember                            1.0.0.0    Microsoft.PowerSh...


   Noun: LocalUser

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-LocalUser                                   1.0.0.0    Microsoft.PowerSh...


   Noun: Module

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-Module                                      3.0.0.0    Microsoft.PowerSh...


   Noun: PmemDisk

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-PmemDisk                                    1.0.0.0    PersistentMemory


   Noun: PSBreakpoint

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-PSBreakpoint                                3.1.0.0    Microsoft.PowerSh...


   Noun: PSDrive

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-PSDrive                                     3.1.0.0    Microsoft.PowerSh...


   Noun: PSReadLineKeyHandler

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-PSReadLineKeyHandler                        2.0.0      PSReadline


   Noun: PSSession

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-PSSession                                   3.0.0.0    Microsoft.PowerSh...


   Noun: PSSnapin

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-PSSnapin                                    3.0.0.0    Microsoft.PowerSh...


   Noun: TypeData

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-TypeData                                    3.1.0.0    Microsoft.PowerSh...


   Noun: Variable

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-Variable                                    3.1.0.0    Microsoft.PowerSh...


   Noun: VHDSnapshot

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VHDSnapshot                                 2.0.0.0    Hyper-V


   Noun: VM

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VM                                          2.0.0.0    Hyper-V


   Noun: VMAssignableDevice

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMAssignableDevice                          2.0.0.0    Hyper-V


   Noun: VMDvdDrive

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMDvdDrive                                  2.0.0.0    Hyper-V


   Noun: VMFibreChannelHba

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMFibreChannelHba                           2.0.0.0    Hyper-V


   Noun: VMGpuPartitionAdapter

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMGpuPartitionAdapter                       2.0.0.0    Hyper-V


   Noun: VMGroup

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMGroup                                     2.0.0.0    Hyper-V


   Noun: VMGroupMember

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMGroupMember                               2.0.0.0    Hyper-V


   Noun: VMHardDiskDrive

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMHardDiskDrive                             2.0.0.0    Hyper-V


   Noun: VMHostAssignableDevice

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMHostAssignableDevice                      2.0.0.0    Hyper-V


   Noun: VMKeyStorageDrive

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMKeyStorageDrive                           2.0.0.0    Hyper-V


   Noun: VMMigrationNetwork

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMMigrationNetwork                          2.0.0.0    Hyper-V


   Noun: VMNetworkAdapter

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMNetworkAdapter                            2.0.0.0    Hyper-V


   Noun: VMNetworkAdapterAcl

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMNetworkAdapterAcl                         2.0.0.0    Hyper-V


   Noun: VMNetworkAdapterExtendedAcl

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMNetworkAdapterExtendedAcl                 2.0.0.0    Hyper-V


   Noun: VMNetworkAdapterRoutingDomainMapping

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMNetworkAdapterRoutingDomainMapping        2.0.0.0    Hyper-V


   Noun: VMNetworkAdapterTeamMapping

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMNetworkAdapterTeamMapping                 2.0.0.0    Hyper-V


   Noun: VMPmemController

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMPmemController                            2.0.0.0    Hyper-V


   Noun: VMRemoteFx3dVideoAdapter

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMRemoteFx3dVideoAdapter                    2.0.0.0    Hyper-V


   Noun: VMReplication

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMReplication                               2.0.0.0    Hyper-V


   Noun: VMReplicationAuthorizationEntry

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMReplicationAuthorizationEntry             2.0.0.0    Hyper-V


   Noun: VMResourcePool

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMResourcePool                              2.0.0.0    Hyper-V


   Noun: VMSan

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMSan                                       2.0.0.0    Hyper-V


   Noun: VMSavedState

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMSavedState                                2.0.0.0    Hyper-V


   Noun: VMScsiController

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMScsiController                            2.0.0.0    Hyper-V


   Noun: VMSnapshot

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMSnapshot                                  2.0.0.0    Hyper-V


   Noun: VMStoragePath

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMStoragePath                               2.0.0.0    Hyper-V


   Noun: VMSwitch

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMSwitch                                    2.0.0.0    Hyper-V


   Noun: VMSwitchExtensionPortFeature

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMSwitchExtensionPortFeature                2.0.0.0    Hyper-V


   Noun: VMSwitchExtensionSwitchFeature

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMSwitchExtensionSwitchFeature              2.0.0.0    Hyper-V


   Noun: VMSwitchTeamMember

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-VMSwitchTeamMember                          2.0.0.0    Hyper-V


   Noun: WindowsCapability

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-WindowsCapability                           3.0        Dism


   Noun: WindowsDriver

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-WindowsDriver                               3.0        Dism


   Noun: WindowsImage

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-WindowsImage                                3.0        Dism


   Noun: WindowsPackage

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-WindowsPackage                              3.0        Dism


   Noun: WmiObject

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-WmiObject                                   3.1.0.0    Microsoft.PowerSh...


   Noun: WSManInstance

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Remove-WSManInstance                               3.0.0.0    Microsoft.WSMan.M...


   Noun: Computer

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Rename-Computer                                    3.1.0.0    Microsoft.PowerSh...


   Noun: Item

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Rename-Item                                        3.1.0.0    Microsoft.PowerSh...


   Noun: ItemProperty

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Rename-ItemProperty                                3.1.0.0    Microsoft.PowerSh...


   Noun: LocalGroup

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Rename-LocalGroup                                  1.0.0.0    Microsoft.PowerSh...


   Noun: LocalUser

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Rename-LocalUser                                   1.0.0.0    Microsoft.PowerSh...


   Noun: VM

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Rename-VM                                          2.0.0.0    Hyper-V


   Noun: VMGroup

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Rename-VMGroup                                     2.0.0.0    Hyper-V


   Noun: VMNetworkAdapter

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Rename-VMNetworkAdapter                            2.0.0.0    Hyper-V


   Noun: VMResourcePool

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Rename-VMResourcePool                              2.0.0.0    Hyper-V


   Noun: VMSan

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Rename-VMSan                                       2.0.0.0    Hyper-V


   Noun: VMSnapshot

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Rename-VMSnapshot                                  2.0.0.0    Hyper-V


   Noun: VMSwitch

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Rename-VMSwitch                                    2.0.0.0    Hyper-V


   Noun: AppvClientConnectionGroup

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Repair-AppvClientConnectionGroup                   1.0.0.0    AppvClient


   Noun: AppvClientPackage

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Repair-AppvClientPackage                           1.0.0.0    AppvClient


   Noun: UevTemplateIndex

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Repair-UevTemplateIndex                            2.1.639.0  UEV


   Noun: VM

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Repair-VM                                          2.0.0.0    Hyper-V


   Noun: WindowsImage

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Repair-WindowsImage                                3.0        Dism


   Noun: ComputerMachinePassword

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Reset-ComputerMachinePassword                      3.1.0.0    Microsoft.PowerSh...


   Noun: VMReplicationStatistics

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Reset-VMReplicationStatistics                      2.0.0.0    Hyper-V


   Noun: VMResourceMetering

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Reset-VMResourceMetering                           2.0.0.0    Hyper-V


   Noun: VHD

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Resize-VHD                                         2.0.0.0    Hyper-V


   Noun: DnsName

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Resolve-DnsName                                    1.0.0.0    DnsClient


   Noun: Path

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Resolve-Path                                       3.1.0.0    Microsoft.PowerSh...


   Noun: Computer

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Restart-Computer                                   3.1.0.0    Microsoft.PowerSh...


   Noun: Service

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Restart-Service                                    3.1.0.0    Microsoft.PowerSh...


   Noun: VM

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Restart-VM                                         2.0.0.0    Hyper-V


   Noun: Computer

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Restore-Computer                                   3.1.0.0    Microsoft.PowerSh...


   Noun: UevBackup

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Restore-UevBackup                                  2.1.639.0  UEV


   Noun: UevUserSetting

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Restore-UevUserSetting                             2.1.639.0  UEV


   Noun: VMSnapshot

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Restore-VMSnapshot                                 2.0.0.0    Hyper-V


   Noun: BitsTransfer

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Resume-BitsTransfer                                2.0.0.0    BitsTransfer


   Noun: Job

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Resume-Job                                         3.0.0.0    Microsoft.PowerSh...


   Noun: ProvisioningSession

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Resume-ProvisioningSession                         3.0        Provisioning


   Noun: Service

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Resume-Service                                     3.1.0.0    Microsoft.PowerSh...


   Noun: VM

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Resume-VM                                          2.0.0.0    Hyper-V


   Noun: VMReplication

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Resume-VMReplication                               2.0.0.0    Hyper-V


   Noun: VMConnectAccess

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Revoke-VMConnectAccess                             2.0.0.0    Hyper-V


   Noun: Help

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Save-Help                                          3.0.0.0    Microsoft.PowerSh...


   Noun: Package

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Save-Package                                       1.0.0.1    PackageManagement


   Noun: VM

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Save-VM                                            2.0.0.0    Hyper-V


   Noun: WindowsImage

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Save-WindowsImage                                  3.0        Dism


   Noun: Object

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Select-Object                                      3.1.0.0    Microsoft.PowerSh...


   Noun: String

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Select-String                                      3.1.0.0    Microsoft.PowerSh...


   Noun: Xml

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Select-Xml                                         3.1.0.0    Microsoft.PowerSh...


   Noun: AppvClientReport

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Send-AppvClientReport                              1.0.0.0    AppvClient


   Noun: DtcDiagnosticTransaction

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Send-DtcDiagnosticTransaction                      1.0.0.0    MsDtc


   Noun: MailMessage

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Send-MailMessage                                   3.1.0.0    Microsoft.PowerSh...


   Noun: Acl

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-Acl                                            3.0.0.0    Microsoft.PowerSh...


   Noun: Alias

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-Alias                                          3.1.0.0    Microsoft.PowerSh...


   Noun: AppBackgroundTaskResourcePolicy

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-AppBackgroundTaskResourcePolicy                1.0.0.0    AppBackgroundTask


   Noun: AppLockerPolicy

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-AppLockerPolicy                                2.0.0.0    AppLocker


   Noun: AppvClientConfiguration

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-AppvClientConfiguration                        1.0.0.0    AppvClient


   Noun: AppvClientMode

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-AppvClientMode                                 1.0.0.0    AppvClient


   Noun: AppvClientPackage

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-AppvClientPackage                              1.0.0.0    AppvClient


   Noun: AppvPublishingServer

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-AppvPublishingServer                           1.0.0.0    AppvClient


   Noun: AppxDefaultVolume

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-AppxDefaultVolume                              2.0.1.0    Appx


   Noun: AppXProvisionedDataFile

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-AppXProvisionedDataFile                        3.0        Dism


   Noun: AuthenticodeSignature

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-AuthenticodeSignature                          3.0.0.0    Microsoft.PowerSh...


   Noun: BitsTransfer

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-BitsTransfer                                   2.0.0.0    BitsTransfer


   Noun: CertificateAutoEnrollmentPolicy

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-CertificateAutoEnrollmentPolicy                1.0.0.0    PKI


   Noun: CimInstance

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-CimInstance                                    1.0.0.0    CimCmdlets


   Noun: CIPolicyIdInfo

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-CIPolicyIdInfo                                 1.0        ConfigCI


   Noun: CIPolicySetting

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-CIPolicySetting                                1.0        ConfigCI


   Noun: CIPolicyVersion

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-CIPolicyVersion                                1.0        ConfigCI


   Noun: Clipboard

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-Clipboard                                      3.1.0.0    Microsoft.PowerSh...


   Noun: Content

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-Content                                        3.1.0.0    Microsoft.PowerSh...


   Noun: Culture

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-Culture                                        2.0.0.0    International


   Noun: Date

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-Date                                           3.1.0.0    Microsoft.PowerSh...


   Noun: DeliveryOptimizationStatus

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-DeliveryOptimizationStatus                     1.0.2.0    DeliveryOptimization


   Noun: DODownloadMode

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-DODownloadMode                                 1.0.2.0    DeliveryOptimization


   Noun: DOPercentageMaxBackgroundBandwidth

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-DOPercentageMaxBackgroundBandwidth             1.0.2.0    DeliveryOptimization


   Noun: DOPercentageMaxForegroundBandwidth

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-DOPercentageMaxForegroundBandwidth             1.0.2.0    DeliveryOptimization


   Noun: DscLocalConfigurationManager

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-DscLocalConfigurationManager                   1.1        PSDesiredStateCon...


   Noun: ExecutionPolicy

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-ExecutionPolicy                                3.0.0.0    Microsoft.PowerSh...


   Noun: HVCIOptions

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-HVCIOptions                                    1.0        ConfigCI


   Noun: Item

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-Item                                           3.1.0.0    Microsoft.PowerSh...


   Noun: ItemProperty

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-ItemProperty                                   3.1.0.0    Microsoft.PowerSh...


   Noun: JobTrigger

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-JobTrigger                                     1.1.0.0    PSScheduledJob


   Noun: KdsConfiguration

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-KdsConfiguration                               1.0.0.0    Kds


   Noun: LocalGroup

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-LocalGroup                                     1.0.0.0    Microsoft.PowerSh...


   Noun: LocalUser

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-LocalUser                                      1.0.0.0    Microsoft.PowerSh...


   Noun: Location

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-Location                                       3.1.0.0    Microsoft.PowerSh...


   Noun: NonRemovableAppsPolicy

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-NonRemovableAppsPolicy                         3.0        Dism


   Noun: PackageSource

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-PackageSource                                  1.0.0.1    PackageManagement


   Noun: ProcessMitigation

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-ProcessMitigation                              1.0.11     ProcessMitigations


   Noun: PSBreakpoint

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-PSBreakpoint                                   3.1.0.0    Microsoft.PowerSh...


   Noun: PSDebug

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-PSDebug                                        3.0.0.0    Microsoft.PowerSh...


   Noun: PSReadLineKeyHandler

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-PSReadLineKeyHandler                           2.0.0      PSReadline


   Noun: PSReadLineOption

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-PSReadLineOption                               2.0.0      PSReadline


   Noun: PSSessionConfiguration

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-PSSessionConfiguration                         3.0.0.0    Microsoft.PowerSh...


   Noun: RuleOption

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-RuleOption                                     1.0        ConfigCI


   Noun: ScheduledJob

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-ScheduledJob                                   1.1.0.0    PSScheduledJob


   Noun: ScheduledJobOption

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-ScheduledJobOption                             1.1.0.0    PSScheduledJob


   Noun: SecureBootUEFI

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-SecureBootUEFI                                 2.0.0.0    SecureBoot


   Noun: Service

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-Service                                        3.1.0.0    Microsoft.PowerSh...


   Noun: StrictMode

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-StrictMode                                     3.0.0.0    Microsoft.PowerSh...


   Noun: TimeZone

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-TimeZone                                       3.1.0.0    Microsoft.PowerSh...


   Noun: TpmOwnerAuth

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-TpmOwnerAuth                                   2.0.0.0    TrustedPlatformMo...


   Noun: TraceSource

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-TraceSource                                    3.1.0.0    Microsoft.PowerSh...


   Noun: UevConfiguration

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-UevConfiguration                               2.1.639.0  UEV


   Noun: UevTemplateProfile

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-UevTemplateProfile                             2.1.639.0  UEV


   Noun: Variable

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-Variable                                       3.1.0.0    Microsoft.PowerSh...


   Noun: VHD

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VHD                                            2.0.0.0    Hyper-V


   Noun: VM

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VM                                             2.0.0.0    Hyper-V


   Noun: VMBios

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMBios                                         2.0.0.0    Hyper-V


   Noun: VMComPort

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMComPort                                      2.0.0.0    Hyper-V


   Noun: VMDvdDrive

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMDvdDrive                                     2.0.0.0    Hyper-V


   Noun: VMFibreChannelHba

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMFibreChannelHba                              2.0.0.0    Hyper-V


   Noun: VMFirmware

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMFirmware                                     2.0.0.0    Hyper-V


   Noun: VMFloppyDiskDrive

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMFloppyDiskDrive                              2.0.0.0    Hyper-V


   Noun: VMGpuPartitionAdapter

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMGpuPartitionAdapter                          2.0.0.0    Hyper-V


   Noun: VMHardDiskDrive

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMHardDiskDrive                                2.0.0.0    Hyper-V


   Noun: VMHost

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMHost                                         2.0.0.0    Hyper-V


   Noun: VMHostCluster

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMHostCluster                                  2.0.0.0    Hyper-V


   Noun: VMKeyProtector

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMKeyProtector                                 2.0.0.0    Hyper-V


   Noun: VMKeyStorageDrive

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMKeyStorageDrive                              2.0.0.0    Hyper-V


   Noun: VMMemory

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMMemory                                       2.0.0.0    Hyper-V


   Noun: VMMigrationNetwork

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMMigrationNetwork                             2.0.0.0    Hyper-V


   Noun: VMNetworkAdapter

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMNetworkAdapter                               2.0.0.0    Hyper-V


   Noun: VMNetworkAdapterFailoverConfiguration

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMNetworkAdapterFailoverConfiguration          2.0.0.0    Hyper-V


   Noun: VMNetworkAdapterIsolation

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMNetworkAdapterIsolation                      2.0.0.0    Hyper-V


   Noun: VMNetworkAdapterRdma

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMNetworkAdapterRdma                           2.0.0.0    Hyper-V


   Noun: VMNetworkAdapterRoutingDomainMapping

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMNetworkAdapterRoutingDomainMapping           2.0.0.0    Hyper-V


   Noun: VMNetworkAdapterTeamMapping

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMNetworkAdapterTeamMapping                    2.0.0.0    Hyper-V


   Noun: VMNetworkAdapterVlan

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMNetworkAdapterVlan                           2.0.0.0    Hyper-V


   Noun: VMPartitionableGpu

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMPartitionableGpu                             2.0.0.0    Hyper-V


   Noun: VMProcessor

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMProcessor                                    2.0.0.0    Hyper-V


   Noun: VMRemoteFx3dVideoAdapter

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMRemoteFx3dVideoAdapter                       2.0.0.0    Hyper-V


   Noun: VMReplication

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMReplication                                  2.0.0.0    Hyper-V


   Noun: VMReplicationAuthorizationEntry

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMReplicationAuthorizationEntry                2.0.0.0    Hyper-V


   Noun: VMReplicationServer

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMReplicationServer                            2.0.0.0    Hyper-V


   Noun: VMResourcePool

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMResourcePool                                 2.0.0.0    Hyper-V


   Noun: VMSan

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMSan                                          2.0.0.0    Hyper-V


   Noun: VMSecurity

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMSecurity                                     2.0.0.0    Hyper-V


   Noun: VMSecurityPolicy

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMSecurityPolicy                               2.0.0.0    Hyper-V


   Noun: VMStorageSettings

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMStorageSettings                              2.0.0.0    Hyper-V


   Noun: VMSwitch

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMSwitch                                       2.0.0.0    Hyper-V


   Noun: VMSwitchExtensionPortFeature

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMSwitchExtensionPortFeature                   2.0.0.0    Hyper-V


   Noun: VMSwitchExtensionSwitchFeature

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMSwitchExtensionSwitchFeature                 2.0.0.0    Hyper-V


   Noun: VMSwitchTeam

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMSwitchTeam                                   2.0.0.0    Hyper-V


   Noun: VMVideo

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-VMVideo                                        2.0.0.0    Hyper-V


   Noun: WheaMemoryPolicy

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-WheaMemoryPolicy                               2.0.0.0    Whea


   Noun: WinAcceptLanguageFromLanguageListOptOut

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-WinAcceptLanguageFromLanguageListOptOut        2.0.0.0    International


   Noun: WinCultureFromLanguageListOptOut

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-WinCultureFromLanguageListOptOut               2.0.0.0    International


   Noun: WinDefaultInputMethodOverride

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-WinDefaultInputMethodOverride                  2.0.0.0    International


   Noun: WindowsEdition

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-WindowsEdition                                 3.0        Dism


   Noun: WindowsProductKey

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-WindowsProductKey                              3.0        Dism


   Noun: WindowsSearchSetting

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-WindowsSearchSetting                           1.0.0.0    WindowsSearch


   Noun: WinHomeLocation

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-WinHomeLocation                                2.0.0.0    International


   Noun: WinLanguageBarOption

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-WinLanguageBarOption                           2.0.0.0    International


   Noun: WinSystemLocale

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-WinSystemLocale                                2.0.0.0    International


   Noun: WinUILanguageOverride

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-WinUILanguageOverride                          2.0.0.0    International


   Noun: WinUserLanguageList

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-WinUserLanguageList                            2.0.0.0    International


   Noun: WmiInstance

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-WmiInstance                                    3.1.0.0    Microsoft.PowerSh...


   Noun: WSManInstance

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-WSManInstance                                  3.0.0.0    Microsoft.WSMan.M...


   Noun: WSManQuickConfig

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Set-WSManQuickConfig                               3.0.0.0    Microsoft.WSMan.M...


   Noun: Command

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Show-Command                                       3.1.0.0    Microsoft.PowerSh...


   Noun: ControlPanelItem

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Show-ControlPanelItem                              3.1.0.0    Microsoft.PowerSh...


   Noun: EventLog

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Show-EventLog                                      3.1.0.0    Microsoft.PowerSh...


   Noun: WindowsDeveloperLicenseRegistration

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Show-WindowsDeveloperLicenseRegistration           1.0.0.0    WindowsDeveloperL...


   Noun: Object

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Sort-Object                                        3.1.0.0    Microsoft.PowerSh...


   Noun: Path

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Split-Path                                         3.1.0.0    Microsoft.PowerSh...


   Noun: WindowsImage

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Split-WindowsImage                                 3.0        Dism


   Noun: BitsTransfer

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Start-BitsTransfer                                 2.0.0.0    BitsTransfer


   Noun: DscConfiguration

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Start-DscConfiguration                             1.1        PSDesiredStateCon...


   Noun: DtcDiagnosticResourceManager

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Start-DtcDiagnosticResourceManager                 1.0.0.0    MsDtc


   Noun: Job

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Start-Job                                          3.0.0.0    Microsoft.PowerSh...


   Noun: OSUninstall

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Start-OSUninstall                                  3.0        Dism


   Noun: Process

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Start-Process                                      3.1.0.0    Microsoft.PowerSh...


   Noun: Service

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Start-Service                                      3.1.0.0    Microsoft.PowerSh...


   Noun: Sleep

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Start-Sleep                                        3.1.0.0    Microsoft.PowerSh...


   Noun: Transaction

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Start-Transaction                                  3.1.0.0    Microsoft.PowerSh...


   Noun: Transcript

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Start-Transcript                                   3.0.0.0    Microsoft.PowerSh...


   Noun: VM

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Start-VM                                           2.0.0.0    Hyper-V


   Noun: VMFailover

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Start-VMFailover                                   2.0.0.0    Hyper-V


   Noun: VMInitialReplication

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Start-VMInitialReplication                         2.0.0.0    Hyper-V


   Noun: VMTrace

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Start-VMTrace                                      2.0.0.0    Hyper-V


   Noun: AppvClientConnectionGroup

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Stop-AppvClientConnectionGroup                     1.0.0.0    AppvClient


   Noun: AppvClientPackage

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Stop-AppvClientPackage                             1.0.0.0    AppvClient


   Noun: Computer

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Stop-Computer                                      3.1.0.0    Microsoft.PowerSh...


   Noun: DtcDiagnosticResourceManager

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Stop-DtcDiagnosticResourceManager                  1.0.0.0    MsDtc


   Noun: Job

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Stop-Job                                           3.0.0.0    Microsoft.PowerSh...


   Noun: Process

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Stop-Process                                       3.1.0.0    Microsoft.PowerSh...


   Noun: Service

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Stop-Service                                       3.1.0.0    Microsoft.PowerSh...


   Noun: Transcript

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Stop-Transcript                                    3.0.0.0    Microsoft.PowerSh...


   Noun: VM

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Stop-VM                                            2.0.0.0    Hyper-V


   Noun: VMFailover

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Stop-VMFailover                                    2.0.0.0    Hyper-V


   Noun: VMInitialReplication

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Stop-VMInitialReplication                          2.0.0.0    Hyper-V


   Noun: VMReplication

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Stop-VMReplication                                 2.0.0.0    Hyper-V


   Noun: VMTrace

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Stop-VMTrace                                       2.0.0.0    Hyper-V


   Noun: BitsTransfer

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Suspend-BitsTransfer                               2.0.0.0    BitsTransfer


   Noun: Job

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Suspend-Job                                        3.0.0.0    Microsoft.PowerSh...


   Noun: Service

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Suspend-Service                                    3.1.0.0    Microsoft.PowerSh...


   Noun: VM

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Suspend-VM                                         2.0.0.0    Hyper-V


   Noun: VMReplication

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Suspend-VMReplication                              2.0.0.0    Hyper-V


   Noun: Certificate

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Switch-Certificate                                 1.0.0.0    PKI


   Noun: AppvPublishingServer

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Sync-AppvPublishingServer                          1.0.0.0    AppvClient


   Noun: Object

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Tee-Object                                         3.1.0.0    Microsoft.PowerSh...


   Noun: AppLockerPolicy

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Test-AppLockerPolicy                               2.0.0.0    AppLocker


   Noun: Certificate

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Test-Certificate                                   1.0.0.0    PKI


   Noun: ComputerSecureChannel

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Test-ComputerSecureChannel                         3.1.0.0    Microsoft.PowerSh...


   Noun: Connection

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Test-Connection                                    3.1.0.0    Microsoft.PowerSh...


   Noun: DscConfiguration

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Test-DscConfiguration                              1.1        PSDesiredStateCon...


   Noun: FileCatalog

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Test-FileCatalog                                   3.0.0.0    Microsoft.PowerSh...


   Noun: HgsTraceTarget

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Test-HgsTraceTarget                                1.0.0.0    HgsDiagnostics


   Noun: KdsRootKey

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Test-KdsRootKey                                    1.0.0.0    Kds


   Noun: ModuleManifest

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Test-ModuleManifest                                3.0.0.0    Microsoft.PowerSh...


   Noun: Path

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Test-Path                                          3.1.0.0    Microsoft.PowerSh...


   Noun: PSSessionConfigurationFile

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Test-PSSessionConfigurationFile                    3.0.0.0    Microsoft.PowerSh...


   Noun: UevTemplate

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Test-UevTemplate                                   2.1.639.0  UEV


   Noun: VHD

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Test-VHD                                           2.0.0.0    Hyper-V


   Noun: VMNetworkAdapter

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Test-VMNetworkAdapter                              2.0.0.0    Hyper-V


   Noun: VMReplicationConnection

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Test-VMReplicationConnection                       2.0.0.0    Hyper-V


   Noun: WSMan

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Test-WSMan                                         3.0.0.0    Microsoft.WSMan.M...


   Noun: Command

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Trace-Command                                      3.1.0.0    Microsoft.PowerSh...


   Noun: File

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Unblock-File                                       3.1.0.0    Microsoft.PowerSh...


   Noun: Tpm

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Unblock-Tpm                                        2.0.0.0    TrustedPlatformMo...


   Noun: DtcDiagnosticTransaction

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Undo-DtcDiagnosticTransaction                      1.0.0.0    MsDtc


   Noun: Transaction

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Undo-Transaction                                   3.1.0.0    Microsoft.PowerSh...


   Noun: Package

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Uninstall-Package                                  1.0.0.1    PackageManagement


   Noun: ProvisioningPackage

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Uninstall-ProvisioningPackage                      3.0        Provisioning


   Noun: TrustedProvisioningCertificate

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Uninstall-TrustedProvisioningCertificate           3.0        Provisioning


   Noun: CmsMessage

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Unprotect-CmsMessage                               3.0.0.0    Microsoft.PowerSh...


   Noun: AppvClientPackage

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Unpublish-AppvClientPackage                        1.0.0.0    AppvClient


   Noun: Event

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Unregister-Event                                   3.1.0.0    Microsoft.PowerSh...


   Noun: PackageSource

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Unregister-PackageSource                           1.0.0.1    PackageManagement


   Noun: PSSessionConfiguration

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Unregister-PSSessionConfiguration                  3.0.0.0    Microsoft.PowerSh...


   Noun: ScheduledJob

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Unregister-ScheduledJob                            1.1.0.0    PSScheduledJob


   Noun: UevTemplate

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Unregister-UevTemplate                             2.1.639.0  UEV


   Noun: WindowsDeveloperLicense

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Unregister-WindowsDeveloperLicense                 1.0.0.0    WindowsDeveloperL...


   Noun: FormatData

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Update-FormatData                                  3.1.0.0    Microsoft.PowerSh...


   Noun: Help

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Update-Help                                        3.0.0.0    Microsoft.PowerSh...


   Noun: List

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Update-List                                        3.1.0.0    Microsoft.PowerSh...


   Noun: TypeData

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Update-TypeData                                    3.1.0.0    Microsoft.PowerSh...


   Noun: UevTemplate

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Update-UevTemplate                                 2.1.639.0  UEV


   Noun: VMVersion

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Update-VMVersion                                   2.0.0.0    Hyper-V


   Noun: WIMBootEntry

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Update-WIMBootEntry                                3.0        Dism


   Noun: Transaction

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Use-Transaction                                    3.1.0.0    Microsoft.PowerSh...


   Noun: WindowsUnattend

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Use-WindowsUnattend                                3.0        Dism


   Noun: Debugger

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Wait-Debugger                                      3.1.0.0    Microsoft.PowerSh...


   Noun: Event

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Wait-Event                                         3.1.0.0    Microsoft.PowerSh...


   Noun: Job

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Wait-Job                                           3.0.0.0    Microsoft.PowerSh...


   Noun: Process

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Wait-Process                                       3.1.0.0    Microsoft.PowerSh...


   Noun: VM

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Wait-VM                                            2.0.0.0    Hyper-V


   Noun: Object

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Where-Object                                       3.0.0.0    Microsoft.PowerSh...


   Noun: Debug

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Write-Debug                                        3.1.0.0    Microsoft.PowerSh...


   Noun: Error

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Write-Error                                        3.1.0.0    Microsoft.PowerSh...


   Noun: EventLog

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Write-EventLog                                     3.1.0.0    Microsoft.PowerSh...


   Noun: Host

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Write-Host                                         3.1.0.0    Microsoft.PowerSh...


   Noun: Information

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Write-Information                                  3.1.0.0    Microsoft.PowerSh...


   Noun: Output

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Write-Output                                       3.1.0.0    Microsoft.PowerSh...


   Noun: Progress

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Write-Progress                                     3.1.0.0    Microsoft.PowerSh...


   Noun: Verbose

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Write-Verbose                                      3.1.0.0    Microsoft.PowerSh...


   Noun: Warning

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Write-Warning                                      3.1.0.0    Microsoft.PowerSh...

```
###
```

```
