#Requires -Version 5
#Requires -RunAsAdministrator

#Region ===============================[Metadata]==============================

<#PSScriptInfo

.VERSION 1.0.0.1

.GUID c6094d13-5ef9-47d3-9c8b-96fd5df6902a

.AUTHOR andreiv3103@gmail.com

.COPYRIGHT Andrei Vida-Rațiu

#>

<#

.DESCRIPTION
  Uninstall the AIP Client, no matter what version is installed.

.INPUTS
  None

.OUTPUTS
  None

.NOTES
  Author:         Andrei Vida-Rațiu
  Creation Date:  2023-03-15
  Purpose/Change: Initial script development

#>

#EndRegion ============================[Metadata]==============================

#Region ===============================[Parameters]============================

[CmdletBinding()]
Param (
    #Script parameters go here.
)

#EndRegion ============================[Parameters]============================

#Region ===============================[Variables]=============================

# Script version.
[string]$ScriptVersion = '1.0.0.1'
# Script name.
[string]$ScriptName = (Get-Item $MyInvocation.MyCommand.Definition).BaseName
# Define the log file name.
[string]$LogFileName = $ScriptName -replace ('\s+', '')
# Log file full path.
[string]$LogFile = "$env:Temp\$LogFileName.log"
# Global script exit code variable.
$Global:ScriptExitCode = 0

#EndRegion ============================[Variables]=============================

#Region ===============================[Functions]=============================

function Write-Log {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]
        $Message,
        [Parameter(Mandatory = $False, Position = 1)]
        [int32]
        $Severity = 1,
        [Parameter(Mandatory = $False, Position = 2)]
        [boolean]
        $WriteHost = $true
    )
    switch ($Severity) {
        1 { $Level = 'Info:' }
        2 { $Level = 'Warning:' }
        3 { $Level = 'Error:' }
        Default { $Level = '-----' }
    }
    $TS = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss K")
    if ($null -eq $LogFile) {
        [string]$ScriptName = "TemporaryLogFile"
        $LogFilePath = "$PsScriptRoot\$ScriptName.log"
    }
    else {
        $LogFilePath = $LogFile
    }
    $Entry = "[$TS] $Level $Message"
    if ($LogFilePath) {
        try {
            Add-Content $LogFilePath -Value $Entry -EA 'Stop'
        }
        catch {
            Write-Warning "Unable to access log file [$LogFilePath]"
        }
    }
    else {
        Write-Warning "Log file is missing."
    }
    # If the "$WriteHost" variable is set, output the log data to console also.
    if ($WriteHost) {
        # Only output using color options if running in a host which supports colors.
        if ($Host.UI.RawUI.ForegroundColor) {
            Switch ($Severity) {
                3 { Write-Host -Object $Entry -ForegroundColor 'Red' -BackgroundColor 'Black' }
                2 { Write-Host -Object $Entry -ForegroundColor 'Yellow' -BackgroundColor 'Black' }
                Default { Write-Host -Object $Entry }
            }
        }
        # If executing "powershell.exe -File <filename>.ps1 > log.txt",
        # then all the Write-Host calls are converted to Write-Output calls so that they are included in the text log.
        Else {
            Write-Output -InputObject $Entry
        }
    }
}
function Get-InstalledApplication {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Name
    )
    # MSI Product Code RegEx Pattern.
    [string]$MSIProductCodeRegExPattern = '(\{{0,1}([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}\}{0,1})'
    #  Registry keys for native and WOW64 applications.
    [string[]]$RegKeyApplications = @(
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    #  Get the OS Architecture.
    [boolean]$Is64Bit = [boolean]((Get-WmiObject -Class 'Win32_Processor' -EA 'SilentlyContinue' |
            ForEach-Object { if ($_.DeviceID -eq 'CPU0') { $_.AddressWidth } }) -eq 64)

    Write-Log "Get information for installed Application Name(s) [$($name -join ', ')]."

    ## Enumerate the installed applications from the registry for applications that have the "DisplayName" property.
    [PsObject[]]$RegKeyApplication = @()
    foreach ($regKey in $RegKeyApplications) {
        if (Test-Path -LiteralPath $regKey -EA 'SilentlyContinue') {
            [PsObject[]]$UninstallKeyApps = Get-ChildItem -LiteralPath $regKey -EA 'SilentlyContinue'
            foreach ($UninstallKeyApp in $UninstallKeyApps) {
                try {
                    [PsObject]$RegKeyApplicationProps = Get-ItemProperty -LiteralPath $UninstallKeyApp.PSPath -EA 'Stop'
                    if ($RegKeyApplicationProps.DisplayName) { [PsObject[]]$RegKeyApplication += $RegKeyApplicationProps }
                }
                catch {
                    Write-Log "Unable to enumerate properties from registry key path [$($UninstallKeyApp.PSPath)]. Error: $($_.Exception.Message)"
                    continue
                }
            }
        }
    }
    if ($ErrorUninstallKeyPath) {
        Write-Log "The following error(s) took place while enumerating installed applications from the registry:`n$ErrorUninstallKeyPath"
    }

    ## Create a custom object with the desired properties for the installed applications and sanitize property details.
    [PsObject[]]$installedApplication = @()
    foreach ($RegKeyApp in $RegKeyApplication) {
        try {
            [string]$appDisplayName = ''
            [string]$appDisplayVersion = ''
            [string]$appPublisher = ''

            ## Bypass any updates or hotfixes.
            if (
                    ($RegKeyApp.DisplayName -match '(?i)kb\d+') -or
                    ($RegKeyApp.DisplayName -match 'Cumulative Update') -or
                    ($RegKeyApp.DisplayName -match 'Security Update') -or
                    ($RegKeyApp.DisplayName -match 'Hotfix')
            ) {
                continue
            }

            ## Remove any control characters which may interfere with logging and creating file path names from these variables.
            $appDisplayName = $RegKeyApp.DisplayName -replace "[^\p{L}\p{Nd}\p{Z}\p{P}]", ''
            $appDisplayVersion = $RegKeyApp.DisplayVersion -replace "[^\p{L}\p{Nd}\p{Z}\p{P}]", ''
            $appPublisher = $RegKeyApp.Publisher -replace "[^\p{L}\p{Nd}\p{Z}\p{P}]", ''

            ## Determine if application is a 64-bit application.
            [boolean]$Is64BitApp = if (($Is64Bit) -and ($RegKeyApp.PSPath -NotMatch '^Microsoft\.PowerShell\.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node')) { $true } Else { $false }
            ## Verify if there is a match with the application name(s) passed to the script.
            foreach ($Application in $Name) {
                $ApplicationMatched = $false
                #  Check for a regex application name match.
                if ($RegKeyApp.DisplayName -match $Application) {
                    $ApplicationMatched = $true
                    Write-Log "Found installed application [$appDisplayName] version [$appDisplayVersion] using regex matching for search term [$Application]."
                }
                if ($ApplicationMatched) {
                    try {
                        $CurrentGUID = ([regex]::Matches($RegKeyApp.UninstallString, $MSIProductCodeRegExPattern)).Groups[0].Value
                    }
                    catch {
                        $CurrentGUID = [string]::Empty
                    }
                    $installedApplication += [PsCustomObject]@{
                        UninstallSubKey    = $RegKeyApp.PSChildName
                        ProductCode        = $CurrentGUID
                        DisplayName        = $appDisplayName
                        DisplayVersion     = $appDisplayVersion
                        UninstallString    = $RegKeyApp.UninstallString
                        InstallSource      = $RegKeyApp.InstallSource
                        InstallLocation    = $RegKeyApp.InstallLocation
                        InstallDate        = $RegKeyApp.InstallDate
                        Publisher          = $appPublisher
                        Is64BitApplication = $Is64BitApp
                    }
                }
            }
        }
        catch {
            Write-Log "Failed to resolve application details from registry for [$appDisplayName]. Error: $($_.Exception.Message)"
            continue
        }
    }

    if (-not $installedApplication) {
        Write-Log "Found no application based on the supplied parameters."
    }

    Write-Output -InputObject $installedApplication
}

#EndRegion ============================[Functions]=============================

#Region ===============================[Execution]=============================
try {
    # Change the global Error action to stop, so that any error will stop the script.
    $Global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
    # Write the log header.
    Write-Log "================================================================================"
    Write-Log "Starting Script '$ScriptName'"
    Write-Log "Script version: '$ScriptVersion'"
    Write-Log "Hostname: '$env:COMPUTERNAME'"
    Write-Log "Powershell version: '$($PSVersionTable.PSVersion -join ('.'))'"
    Write-Log "Running as user: '$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)'"
    Write-Log "================================================================================"

    #! === [Main Code Start] === #

    # Name of the application.
    $AppName = 'Azure Information Protection'
    # Get all existing app instances.
    $AppInstances = Get-InstalledApplication $AppName
    # Uninstall each app instance.
    foreach ($App in $AppInstances) {
        Write-Log "Removing application '$($App.DisplayName)'."
        if ($App.UninstallString -like "*MsiExec.exe*") {
            $CmdletParams = @{
                FilePath     = "$env:SystemRoot\system32\msiexec.exe"
                ArgumentList = @(
                    "/x `"$($App.UninstallSubKey)`""
                    "/qn"
                    "/l*v `"$env:Temp\$($App.DisplayName -replace '\s+','-')_Uninstall.log`""
                )
                Wait         = $true
            }
            Write-Log "Start-Process parameters:`n$(($CmdletParams | Out-String).Trim())"
            $ExecStatus = Start-Process @CmdletParams
            if ($ExecStatus.ExitCode -notin (3010, 0, 1641)) {
                Write-Log "Application successfully removed."
            }
            else {
                Write-Log "Uninstall error. MsiExec exit code: $($ExecStatus.ExitCode)" -Severity 2
                $Global:ScriptExitCode = 65001
            }
        }
        else {
            $UninstallStringParts = ($App.UninstallString -split ('.exe')).Trim('"')
            $UninstallerPath = $UninstallStringParts[0] + '.exe'
            if ([string]::IsNullOrWhiteSpace($UninstallStringParts[1])) {
                $ArgumentList = '/S'
            }
            else {
                $ArgumentList = ($UninstallStringParts[1] + ' /S').Trim(' ')
            }
            $CmdletParams = @{
                FilePath     = $UninstallerPath
                ArgumentList = $ArgumentList
                Wait         = $true
            }
            Write-Log "Start-Process parameters:`n$(($CmdletParams | Out-String).Trim())"
            $ExecStatus = Start-Process @CmdletParams
            if ($ExecStatus.ExitCode -notin (3010, 0, 1641)) {
                Write-Log "Application successfully removed."
            }
            else {
                Write-Log "Uninstall error. Uninstaller exit code: $($ExecStatus.ExitCode)" -Severity 2
                $Global:ScriptExitCode = 65002
            }
        }
    }

    #! === [Main Code End]   === #

    Write-Log "================================================================================"
}
catch {
    $Global:ScriptExitCode = 65000
    $ErrorMessage = [string]$_.Exception.Message
    $ErrorPosition = [string]$_.InvocationInfo.PositionMessage
    $ErrorString = "$ErrorMessage | $ErrorPosition"
    Write-Log $ErrorString
    Write-Error -Message $ErrorString
}
finally {
    Exit $Global:ScriptExitCode
}

#EndRegion ============================[Execution]=============================
