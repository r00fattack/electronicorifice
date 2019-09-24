Function Install-LTService{
    <#
    .SYNOPSIS
        This function will install the LabTech agent on the machine.
    
    .DESCRIPTION
        This function will install the LabTech agent on the machine with the specified server/password/location. If .NET 3.5  is not installed, it will be installed 
        prior to agent installation, unless the parameter -SkipDotNet is specified.
    
    .PARAMETER Server
        This is the URL to your LabTech server.

    .PARAMETER Password
        This is the server password that agents use to authenticate with the LabTech server.
    
    .PARAMETER LocationID
        This is the LocationID of the location that the agent will be put into.
    
    .PARAMETER TrayPort
        This is the port LTSvc.exe listens on for communication with LTTray processes.
    
    .PARAMETER Rename
        This will call Rename-LTAddRemove after the install.
    
    .PARAMETER Hide
        This will call Hide-LTAddRemove after the install.
    
    .PARAMETER SkipDotNet
        This will disable the error checking for the .NET 3.5 and .NET 2.0 frameworks during the install process.
    
    .PARAMETER Force
        This will disable some of the error checking on the install process.
    
    .PARAMETER NoWait
        This will skip the ending health check for the install process.
        The function will exit once the installer has completed.
    
    .EXAMPLE
        Install-LTService -Server https://lt.domain.com -Password sQWZzEDYKFFnTT0yP56vgA== -LocationID 42
        This will install the LabTech agent using the provided Server URL, Password, and LocationID.
    
    .NOTES
        Author: Andrew Adams
        Date: 09/23/2019
    
    #>
        [CmdletBinding(SupportsShouldProcess=$True)]
        Param(
            [Parameter(ValueFromPipelineByPropertyName = $true, Mandatory=$True)]
            [string[]]$Server,
            [Parameter(ValueFromPipelineByPropertyName = $True)]
            [Alias("Password")]
            [AllowNull()]
            [string]$ServerPassword,
            [Parameter(ValueFromPipelineByPropertyName = $True)]
            [AllowNull()]
            [int]$LocationID,
            [Parameter(ValueFromPipelineByPropertyName = $True)]
            [AllowNull()]
            [int]$TrayPort,
            [Parameter()]
            [AllowNull()]
            [string]$Rename,
            [switch]$Hide,
            [switch]$SkipDotNet,
            [switch]$Force,
            [switch]$NoWait
        )
    
        Begin{
            Clear-Variable DotNET,OSVersion,PasswordArg,Result,logpath,logfile,curlog,installer,installerTest,installerResult,GoodServer,GoodTrayPort,TestTrayPort,Svr,SVer,SvrVer,SvrVerCheck,iarg,timeout,sw,tmpLTSI -EA 0 -WhatIf:$False -Confirm:$False #Clearing Variables for use
            Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)"
    
            If (!($Force)) {
                If (Get-Service 'LTService','LTSvcMon' -ErrorAction SilentlyContinue) {
                    If ($WhatIfPreference -ne $True) {
                        Write-Error "ERROR: Line $(LINENUM): Services are already installed." -ErrorAction Stop
                    } Else {
                        Write-Error "ERROR: Line $(LINENUM): What if: Stopping: Services are already installed." -ErrorAction Stop
                    }#End If
                }#End If
            }#End If
    
            If (-not ([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()|Select-Object -Expand groups -EA 0) -match 'S-1-5-32-544'))) {
                Throw "Needs to be ran as Administrator"
            }
    
            If (!$SkipDotNet){
                $DotNET = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse -EA 0 | Get-ItemProperty -name Version,Release -EA 0 | Where-Object { $_.PSChildName -match '^(?!S)\p{L}'} | Select-Object -ExpandProperty Version -EA 0
                If (-not ($DotNet -like '3.5.*')){
                    Write-Output ".NET 3.5 installation needed."
                    #Install-WindowsFeature Net-Framework-Core
                    $OSVersion = [System.Environment]::OSVersion.Version
    
                    If ([version]$OSVersion -gt [version]'6.2'){
                        Try{
                            If ( $PSCmdlet.ShouldProcess("NetFx3", "Enable-WindowsOptionalFeature") ) {
                                $Install = Enable-WindowsOptionalFeature -Online -FeatureName "NetFx3" -All
                                If ($Install.RestartNeeded) {
                                    Write-Output ".NET 3.5 installed but a reboot is needed."
                                }
                            }
                        }
                        Catch{
                            Write-Error "ERROR: Line $(LINENUM): .NET 3.5 install failed." -ErrorAction Continue
                            If (!($Force)) { Write-Error ("Line $(LINENUM):",$Install) -ErrorAction Stop }
                        }
                    }
                    Else{
                        If ( $PSCmdlet.ShouldProcess("NetFx3", "Add Windows Feature") ) {
                            Try {$Result=& "$env:windir\system32\Dism.exe" /online /get-featureinfo /featurename:NetFx3 2>''}
                            Catch {Write-Output "Error calling Dism.exe."; $Result=$Null}
                            If ($Result -contains "State : Enabled"){
                                # also check reboot status, unsure of possible outputs
                                # Restart Required : Possible
                                Write-Warning "WARNING: Line $(LINENUM): .Net Framework 3.5 has been installed and enabled."
                            }
                            Else {
                                Write-Error "ERROR: Line $(LINENUM): .NET 3.5 install failed." -ErrorAction Continue
                                If (!($Force)) { Write-Error ("ERROR: Line $(LINENUM):",$Result) -ErrorAction Stop }
                            }#End If
                        }#End If
                    }#End If
    
                    $DotNET = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse | Get-ItemProperty -name Version -EA 0 | Where-Object{ $_.PSChildName -match '^(?!S)\p{L}'} | Select-Object -ExpandProperty Version
                }#End If
    
                If (-not ($DotNet -like '3.5.*')){
                    If (($Force)) {
                        If ($DotNet -like '2.0.*'){
                            Write-Error "ERROR: Line $(LINENUM): .NET 3.5 is not detected and could not be installed." -ErrorAction Continue
                        } Else {
                            Write-Error "ERROR: Line $(LINENUM): .NET 2.0 is not detected and could not be installed." -ErrorAction Stop
                        }#End If
                    } Else {
                        Write-Error "ERROR: Line $(LINENUM): .NET 3.5 is not detected and could not be installed." -ErrorAction Stop
                    }#End If
                }#End If
            }#End If
    
            $logpath = [System.Environment]::ExpandEnvironmentVariables("%windir%\temp\LabTech")
            $logfile = "LTAgentInstall"
            $curlog = "$($logpath)\$($logfile).log"
            If (-not (Test-Path -PathType Container -Path "$logpath\Installer" )){
                New-Item "$logpath\Installer" -type directory -ErrorAction SilentlyContinue | Out-Null
            }#End if
            If ((Test-Path -PathType Leaf -Path $($curlog))){
                If ($PSCmdlet.ShouldProcess("$($curlog)","Rotate existing log file")){
                    $curlog = Get-Item -Path $curlog -EA 0
                    Rename-Item -Path $($curlog|Select-Object -Expand FullName -EA 0) -NewName "$($logfile)-$(Get-Date $($curlog|Select-Object -Expand LastWriteTime -EA 0) -Format 'yyyyMMddHHmmss').log" -Force -Confirm:$False -WhatIf:$False
                    Remove-Item -Path $($curlog|Select-Object -Expand FullName -EA 0) -Force -EA 0 -Confirm:$False -WhatIf:$False
                }#End If
            }#End If
        }#End Begin
    
        Process{
            If (-not ($LocationID)){
                $LocationID = "1"
            }
            If (-not ($TrayPort) -or -not ($TrayPort -ge 1 -and $TrayPort -le 65535)){
                $TrayPort = "42000"
            }
            $Server=ForEach ($Svr in $Server) {$Svr; If ($Svr -notmatch 'https?://.+') {"https://$($Svr)"}}
            ForEach ($Svr in $Server) {
                If (-not ($GoodServer)) {
                    If ($Svr -match '^(https?://)?(([12]?[0-9]{1,2}\.){3}[12]?[0-9]{1,2}|[a-z0-9][a-z0-9_-]+(\.[a-z0-9][a-z0-9_-]*)*)$') {
                        If ($Svr -notmatch 'https?://.+') {$Svr = "http://$($Svr)"}
                        Try {
                            $SvrVerCheck = "$($Svr)/Labtech/Agent.aspx"
                            Write-Debug "Line $(LINENUM): Testing Server Response and Version: $SvrVerCheck"
                            $SvrVer = $Script:LTServiceNetWebClient.DownloadString($SvrVerCheck)
                            Write-Debug "Line $(LINENUM): Raw Response: $SvrVer"
                            $SVer = $SvrVer|select-string -pattern '(?<=[|]{6})[0-9]{1,3}\.[0-9]{1,3}'|ForEach-Object {$_.matches}|Select-Object -Expand value -EA 0
                            If ($Null -eq $SVer) {
                                Write-Verbose "Unable to test version response from $($Svr)."
                                Continue
                            }
                            If ([System.Version]$SVer -ge [System.Version]'110.374') {
                                #New Style Download Link starting with LT11 Patch 13 - Direct Location Targeting is no longer available
                                $installer = "$($Svr)/Labtech/Deployment.aspx?Probe=1&installType=msi&MSILocations=1"
                            } Else {
                                #Original URL
                                $installer = "$($Svr)/Labtech/Deployment.aspx?Probe=1&installType=msi&MSILocations=$LocationID"
                            }
                            $installerTest = [System.Net.WebRequest]::Create($installer)
                            If (($Script:LTProxy.Enabled) -eq $True) {
                                Write-Debug "Line $(LINENUM): Proxy Configuration Needed. Applying Proxy Settings to request."
                                $installerTest.Proxy=$Script:LTWebProxy
                            }#End If
                            $installerTest.KeepAlive=$False
                            $installerTest.ProtocolVersion = '1.0'
                            $installerResult = $installerTest.GetResponse()
                            $installerTest.Abort()
                            If ($installerResult.StatusCode -ne 200) {
                                Write-Warning "WARNING: Line $(LINENUM): Unable to download Agent_Install from server $($Svr)."
                                Continue
                            } Else {
                                If ( $PSCmdlet.ShouldProcess($installer, "DownloadFile") ) {
                                    Write-Debug "Line $(LINENUM): Downloading Agent_Install.msi from $installer"
                                    $Script:LTServiceNetWebClient.DownloadFile($installer,"$env:windir\temp\LabTech\Installer\Agent_Install.msi")
                                    If((Test-Path "$env:windir\temp\LabTech\Installer\Agent_Install.msi") -and  !((Get-Item "$env:windir\temp\LabTech\Installer\Agent_Install.msi" -EA 0).length/1KB -gt 1234)) {
                                        Write-Warning "WARNING: Line $(LINENUM): Agent_Install.msi size is below normal. Removing suspected corrupt file."
                                        Remove-Item "$env:windir\temp\LabTech\Installer\Agent_Install.msi" -ErrorAction SilentlyContinue -Force -Confirm:$False
                                        Continue
                                    }#End If
                                }#End If
    
                                If ($WhatIfPreference -eq $True) {
                                    $GoodServer = $Svr
                                } ElseIf (Test-Path "$env:windir\temp\LabTech\Installer\Agent_Install.msi") {
                                    $GoodServer = $Svr
                                    Write-Verbose "Agent_Install.msi downloaded successfully from server $($Svr)."
                                } Else {
                                    Write-Warning "WARNING: Line $(LINENUM): Error encountered downloading from $($Svr). No installation file was received."
                                    Continue
                                }#End If
                            }#End If
                        }#End Try
                        Catch {
                            Write-Warning "WARNING: Line $(LINENUM): Error encountered downloading from $($Svr)."
                            Continue
                        }
                    } Else {
                        Write-Warning "WARNING: Line $(LINENUM): Server address $($Svr) is not formatted correctly. Example: https://lt.domain.com"
                    }
                } Else {
                    Write-Debug "Line $(LINENUM): Server $($GoodServer) has been selected."
                    Write-Verbose "Server has already been selected - Skipping $($Svr)."
                }
            }#End Foreach
        }#End Process
    
        End{
            If (($ServerPassword)){
                $PasswordArg = "SERVERPASS=$ServerPassword"
            }
            If ($GoodServer) {
    
                If ( $WhatIfPreference -eq $True -and (Get-PSCallStack)[1].Command -eq 'Redo-LTService' ) {
                    Write-Debug "Line $(LINENUM): Skipping Preinstall Check: Called by Redo-LTService and ""-WhatIf=`$True"""
                } Else {
                    If ((Test-Path "$($env:windir)\ltsvc" -EA 0) -or (Test-Path "$($env:windir)\temp\_ltudpate" -EA 0) -or (Test-Path registry::HKLM\Software\LabTech\Service -EA 0) -or (Test-Path registry::HKLM\Software\WOW6432Node\Labtech\Service -EA 0)){
                        Write-Warning "WARNING: Line $(LINENUM): Previous installation detected. Calling Uninstall-LTService"
                        Uninstall-LTService -Server $GoodServer -Force
                        Start-Sleep 10
                    }#End If
                }#End If
    
                If ($WhatIfPreference -ne $True) {
                    $GoodTrayPort=$Null;
                    $TestTrayPort=$TrayPort;
                    For ($i=0; $i -le 10; $i++) {
                        If (-not ($GoodTrayPort)) {
                            If (-not (Test-LTPorts -TrayPort $TestTrayPort -Quiet)){
                                $TestTrayPort++;
                                If ($TestTrayPort -gt 42009) {$TestTrayPort=42000}
                            } Else {
                                $GoodTrayPort=$TestTrayPort
                            }#End If
                        }#End If
                    }#End For
                    If ($GoodTrayPort -and $GoodTrayPort -ne $TrayPort -and $GoodTrayPort -ge 1 -and $GoodTrayPort -le 65535) {
                        Write-Verbose "TrayPort $($TrayPort) is in use. Changing TrayPort to $($GoodTrayPort)"
                        $TrayPort=$GoodTrayPort
                    }#End If
                    Write-Output "Starting Install."
                }#End If
    
                $iarg = "/i ""$env:windir\temp\LabTech\Installer\Agent_Install.msi"" SERVERADDRESS=$GoodServer $PasswordArg LOCATION=$LocationID SERVICEPORT=$TrayPort /qn /l ""$logpath\$logfile.log"""
    
                Try{
                    If ( $PSCmdlet.ShouldProcess("msiexec.exe $($iarg)", "Execute Install") ) {
                        $InstallAttempt=0
                        Do {
                            If ($InstallAttempt -gt 0 ) {
                                Write-Warning "WARNING: Line $(LINENUM): Service Failed to Install. Retrying in 30 seconds." -WarningAction 'Continue'
                                $timeout = new-timespan -Seconds 30
                                $sw = [diagnostics.stopwatch]::StartNew()
                                Do {
                                    Start-Sleep 5
                                    $svcRun = ('LTService') | Get-Service -EA 0 | Measure-Object | Select-Object -Expand Count
                                } Until ($sw.elapsed -gt $timeout -or $svcRun -eq 1)
                                $sw.Stop()
                            }#End If
                            $InstallAttempt++
                            $svcRun = ('LTService') | Get-Service -EA 0 | Measure-Object | Select-Object -Expand Count
                            If ($svcRun -eq 0) {
                                Write-Verbose "Launching Installation Process: msiexec.exe $(($iarg))"
                                Start-Process -Wait -FilePath "$env:windir\system32\msiexec.exe" -ArgumentList $iarg -WorkingDirectory $env:TEMP
                                Start-Sleep 5
                            }
                            $svcRun = ('LTService') | Get-Service -EA 0 | Measure-Object | Select-Object -Expand Count
                        } Until ($InstallAttempt -ge 3 -or $svcRun -eq 1)
                        If ($svcRun -eq 0) {
                            Write-Error "ERROR: Line $(LINENUM): LTService was not installed. Installation failed."
                            Return
                        }
                    }#End If
                    If (($Script:LTProxy.Enabled) -eq $True) {
                        Write-Verbose "Proxy Configuration Needed. Applying Proxy Settings to Agent Installation."
                        If ( $PSCmdlet.ShouldProcess($Script:LTProxy.ProxyServerURL, "Configure Agent Proxy") ) {
                            $svcRun = ('LTService') | Get-Service -EA 0 | Where-Object {$_.Status -eq 'Running'} | Measure-Object | Select-Object -Expand Count
                            If ($svcRun -ne 0) {
                                $timeout = new-timespan -Minutes 2
                                $sw = [diagnostics.stopwatch]::StartNew()
                                Write-Host -NoNewline "Waiting for Service to Start."
                                Do {
                                    Write-Host -NoNewline '.'
                                    Start-Sleep 2
                                    $svcRun = ('LTService') | Get-Service -EA 0 | Where-Object {$_.Status -eq 'Running'} | Measure-Object | Select-Object -Expand Count
                                } Until ($sw.elapsed -gt $timeout -or $svcRun -eq 1)
                                Write-Host ""
                                $sw.Stop()
                                If ($svcRun -eq 1) {
                                    Write-Debug "Line $(LINENUM): LTService Initial Startup Successful."
                                } Else {
                                    Write-Debug "Line $(LINENUM): LTService Initial Startup failed to complete within expected period."
                                }#End If
                            }#End If
                            Set-LTProxy -ProxyServerURL $Script:LTProxy.ProxyServerURL -ProxyUsername $Script:LTProxy.ProxyUsername -ProxyPassword $Script:LTProxy.ProxyPassword -Confirm:$False -WhatIf:$False
                        }#End If
                    } Else {
                        Write-Verbose "No Proxy Configuration has been specified - Continuing."
                    }#End If
                    If (!($NoWait) -and $PSCmdlet.ShouldProcess("LTService","Monitor For Successful Agent Registration") ) {
                        $timeout = new-timespan -Minutes 3
                        $sw = [diagnostics.stopwatch]::StartNew()
                        Write-Host -NoNewline "Waiting for agent to register."
                        Do {
                            Write-Host -NoNewline '.'
                            Start-Sleep 5
                            $tmpLTSI = (Get-LTServiceInfo -EA 0 -Verbose:$False -WhatIf:$False -Confirm:$False -Debug:$False|Select-Object -Expand 'ID' -EA 0)
                        } Until ($sw.elapsed -gt $timeout -or $tmpLTSI -ge 1)
                        Write-Host ""
                        $sw.Stop()
                        Write-Verbose "Completed wait for LabTech Installation after $(([int32]$sw.Elapsed.TotalSeconds).ToString()) seconds."
                        $Null=Get-LTProxy -ErrorAction Continue
                    }#End If
                    If ($Hide) {Hide-LTAddRemove}
                }#End Try
    
                Catch{
                    Write-Error "ERROR: Line $(LINENUM): There was an error during the install process. $($Error[0])"
                    Return
                }#End Catch
    
                If ( $WhatIfPreference -ne $True ) {
                    $tmpLTSI = Get-LTServiceInfo -EA 0 -Verbose:$False -WhatIf:$False -Confirm:$False -Debug:$False
                    If (($tmpLTSI)) {
                        If (($tmpLTSI|Select-Object -Expand 'ID' -EA 0) -ge 1) {
                            Write-Output "LabTech has been installed successfully. Agent ID: $($tmpLTSI|Select-Object -Expand 'ID' -EA 0) LocationID: $($tmpLTSI|Select-Object -Expand 'LocationID' -EA 0)"
                        } ElseIf (!($NoWait)) {
                            Write-Error "ERROR: Line $(LINENUM): LabTech installation completed but Agent failed to register within expected period." -ErrorAction Continue
                        } Else {
                            Write-Warning "WARNING: Line $(LINENUM): LabTech installation completed but Agent did not yet register." -WarningAction Continue
                        }#End If
                    } Else {
                        If (($Error)) {
                            Write-Error "ERROR: Line $(LINENUM): There was an error installing LabTech. Check the log, $($env:windir)\temp\LabTech\LTAgentInstall.log $($Error[0])"
                            Return
                        } ElseIf (!($NoWait)) {
                            Write-Error "ERROR: Line $(LINENUM): There was an error installing LabTech. Check the log, $($env:windir)\temp\LabTech\LTAgentInstall.log"
                            Return
                        } Else {
                            Write-Warning "WARNING: Line $(LINENUM): LabTech installation may not have succeeded." -WarningAction Continue
                        }#End If
                    }#End If
                }#End If
                If (($Rename) -and $Rename -notmatch 'False'){ Rename-LTAddRemove -Name $Rename }
            } ElseIf ( $WhatIfPreference -ne $True ) {
                Write-Error "ERROR: Line $(LINENUM): No valid server was reached to use for the install."
            }#End If
            Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)"
        }#End End
    }#End Function Install-LTService


Function Uninstall-LTService {
    <#
    .SYNOPSIS
        Uninstall existing LTService
    .DESCRIPTION
        Uses the universal agent uninstaller to silently remove Automate remote agent
    .NOTES
        Author: Andrew Adams
        Date: 09/24/2019
    .EXAMPLE
        N/A
    #>

    # If LTService exists, attempt uninstall
    If (Get-Service LTService -ErrorAction SilentlyContinue) {
        Try {
            $uninstallURL   = "https://lt.electronicoffice.net/labtech/transfer/Uninstall.zip"
            $uninstallFile  = "C:\Uninstall.zip"
            (New-Object System.Net.WebClient).DownloadFile($uninstallURL, $uninstallFile)
            Start-Sleep -Seconds 10
            Expand-Archive -Path C:\Uninstall.zip -DestinationPath C:\uninstall
            Start-Sleep -Seconds 10
            Invoke-Item -Path C:\uninstall\Uninstall.exe
        } Catch {
            Write-Error "Error occurred while attempting to remove Automate agent: `n`n$_"
            Exit
        }
    }
}