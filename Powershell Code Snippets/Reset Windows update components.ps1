function Reset-WindowsUpdateComponents {

    ## This is needed if not custom "Write-Log" function exists. It will alias is to "Write-Host".
    if (-not (Get-Command 'Write-Log' -EA 0)) {
        Set-Alias 'Write-Log' 'Write-Host'
    }

    ## Change the global Error action to stop, so that any error will stop the script.
    $Global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

    ## Trigger unused drivers cleanup.
    Write-Log "Calling the unused drivers cleanup function."
    rundll32.exe pnpclean.dll, RunDLL_PnpClean /DRIVERS /MAXCLEAN

    #Region    === Stop Windows update related services =======================

    Write-Log "Stopping Windows Update related services."
    [string[]]$WuRelatedServices = @(
        'wuauserv'
        'bits'
        'appidsvc'
        'cryptsvc'
        'msiserver'
    )
    foreach ($Item in $WuRelatedServices) {
        [string]$CmdOutput = (
            Get-Service -Name $Item -ErrorAction 'Ignore' |
            Stop-Service -Force -Verbose -ErrorAction 'Ignore'
        ) *>&1
        if ($CmdOutput.Length -gt 0) { Write-Log "$CmdOutput" }
    }
    Start-Sleep -Seconds 5

    #EndRegion === Stop Windows update related services =======================

    #Region    === Clear the download manager queue ===========================

    Write-Log "Clearing the download manager queue."
    [string]$CmdOutput = (
        Get-ChildItem -Path "$env:ALLUSERSPROFILE\Microsoft\Network\Downloader" -Filter "qmgr*.dat" |
        Remove-Item -Force
    ) *>&1
    if ($CmdOutput.Length -gt 0) { Write-Log "$CmdOutput" }
    [string]$CmdOutput = (
        Get-ChildItem -Path "$env:ALLUSERSPROFILE\Application Data\Microsoft\Network\Downloader" -Filter "qmgr*.dat" |
        Remove-Item -Force
    ) *>&1

    #EndRegion === Clear the download manager queue ===========================

    #Region    === Remove software distribution related files and folders =====

    Write-Log "Removing the software distribution related files and folders."
    Remove-Item -Path "$env:SystemRoot\winsxs\pending.xml" -ErrorAction 'SilentlyContinue'
    try {
        [System.IO.Directory]::Delete("$env:SystemRoot\SoftwareDistribution", $true) | Out-Null
    }
    catch {
        Write-Log "An error has occurred while removing '$env:SystemRoot\SoftwareDistribution'."
        Write-Log "$($_.Exception.Message)"
    }
    try {
        [System.IO.Directory]::Delete("$env:SystemRoot\System32\catroot2", $true) | Out-Null
    }
    catch {
        Write-Log "An error has occurred while removing '$env:SystemRoot\System32\catroot2'."
        Write-Log "$($_.Exception.Message)"
    }
    Remove-Item -Path "$env:SystemRoot\WindowsUpdate.log" -ErrorAction 'SilentlyContinue'

    #EndRegion === Remove software distribution related files and folders =====

    #Region    === Re-register all relevant DLLs ==============================

    Write-Log "Re-registering Windows update related DLLs."
    [string[]]$DLLs = @(
        'atl.dll'
        'urlmon.dll'
        'mshtml.dll'
        'shdocvw.dll'
        'browseui.dll'
        'jscript.dll'
        'vbscript.dll'
        'scrrun.dll'
        'msxml.dll'
        'msxml3.dll'
        'msxml6.dll'
        'actxprxy.dll'
        'softpub.dll'
        'wintrust.dll'
        'dssenh.dll'
        'rsaenh.dll'
        'gpkcsp.dll'
        'sccbase.dll'
        'slbcsp.dll'
        'cryptdlg.dll'
        'oleaut32.dll'
        'ole32.dll'
        'shell32.dll'
        'initpki.dll'
        'wuapi.dll'
        'wuaueng.dll'
        'wuaueng1.dll'
        'wucltui.dll'
        'wups.dll'
        'wups2.dll'
        'wuweb.dll'
        'qmgr.dll'
        'qmgrprxy.dll'
        'wucltux.dll'
        'muweb.dll'
        'wuwebv.dll'
    )
    [string]$PathRegsvr = (Join-Path -Path $env:SystemRoot -ChildPath '\System32\Regsvr32.exe')
    $null = Set-Location -Path $(Join-Path -Path $env:SystemRoot -ChildPath 'System32')
    ForEach ($Dll in $DLLs) {
        Start-Process -FilePath $PathRegsvr -ArgumentList "/s $Dll" -Wait -ErrorAction 'SilentlyContinue'
    }

    #EndRegion === Re-register all relevant DLLs ==============================

    #Region    === Clear the BITS queue =======================================

    Write-Log "Clearing the BITS queue."
    $null = Get-BitsTransfer -AllUsers | Remove-BitsTransfer

    #EndRegion === Clear the BITS queue =======================================

    #Region    === Reset WinSock ==============================================

    Write-Log "Resetting WinSock proxy."
    netsh.exe winsock reset
    netsh.exe winsock reset proxy

    #EndRegion === Reset WinSock ==============================================

    #Region    === Start the services =========================================

    Write-Log "Starting the services."
    foreach ($Item in $WuRelatedServices) {
        [string]$CmdOutput = (
            Get-Service -Name $Item -ErrorAction 'Ignore' |
            Start-Service -ErrorAction 'Ignore'
        ) *>&1
        if ($CmdOutput.Length -gt 0) { Write-Log "$CmdOutput" }
    }

    #EndRegion === Start the services =========================================

    ## Run the component cleanup.
    Write-Log "Starting component cleanup."
    Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
}

Reset-WindowsUpdateComponents

