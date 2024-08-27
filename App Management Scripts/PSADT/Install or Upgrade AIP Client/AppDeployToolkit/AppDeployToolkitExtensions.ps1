<#
.SYNOPSIS

PSAppDeployToolkit - Provides the ability to extend and customise the toolkit by adding your own functions that can be re-used.

.DESCRIPTION

This script is a template that allows you to extend the toolkit with your own custom functions.

This script is dot-sourced by the AppDeployToolkitMain.ps1 script which contains the logic and functions required to install or uninstall an application.

PSApppDeployToolkit is licensed under the GNU LGPLv3 License - (C) 2023 PSAppDeployToolkit Team (Sean Lillis, Dan Cunningham and Muhammad Mashwani).

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the
Free Software Foundation, either version 3 of the License, or any later version. This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
for more details. You should have received a copy of the GNU Lesser General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.

.EXAMPLE

powershell.exe -File .\AppDeployToolkitHelp.ps1

.INPUTS

None

You cannot pipe objects to this script.

.OUTPUTS

None

This script does not generate any output.

.NOTES

.LINK

https://psappdeploytoolkit.com
#>

[CmdletBinding()]
Param (
)

##*===============================================
##* VARIABLE DECLARATION
##*===============================================

# Variables: Script
[string]$appDeployToolkitExtName = 'PSAppDeployToolkitExt'
[string]$appDeployExtScriptFriendlyName = 'App Deploy Toolkit Extensions'
[version]$appDeployExtScriptVersion = [version]'3.9.2'
[string]$appDeployExtScriptDate = '02/02/2023'
[hashtable]$appDeployExtScriptParameters = $PSBoundParameters

##*===============================================
##* FUNCTION LISTINGS
##*===============================================

function Uninstall-AllAipInstances {
    # Get all existing app instances.
    $AppInstances = Get-InstalledApplication -Name $appName
    # Uninstall each app instance.
    foreach ($App in $AppInstances) {
        Write-Log "Removing application '$($App.DisplayName)'."
        if ($App.UninstallString -like "*MsiExec.exe*") {
            $CmdletParams = @{
                Action          = 'Uninstall'
                Path            = $App.UninstallSubKey
                ContinueOnError = $true
                Verbose         = $true
            }
            Execute-MSI @CmdletParams
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
                Path            = $UninstallerPath
                Parameters      = $ArgumentList
                WindowStyle     = 'Hidden'
                ContinueOnError = $true
                Verbose         = $true
            }
            Execute-Process @CmdletParams
        }
    }
    # Remove the app installer registry key. This causes issues sometimes with the client reinstall.
    $null = Push-Location
    $null = New-PSDrive -PSProvider 'registry' -Root 'HKEY_CLASSES_ROOT' -Name 'HKCR'
    $null = Set-Location 'HKCR:'
    [array]$TargetRegKeys = (Get-ItemProperty 'Installer\Products\*' |
        Where-Object { $_.ProductName -match $appName })
    if ($TargetRegKeys.Count -gt 0) {
        Write-Log "Registry keys related to the app found. Proceeding to remove."
    }
    else {
        Write-Log "No registry keys found. Nothing to delete" -Severity 2
    }
    foreach ($Item in $TargetRegKeys) {
        $CurrentKeyPath = $Item.PsPath -replace ('^.*::', '')
        Write-Log "Removing the client installer registry key '$CurrentKeyPath' for product '$($Item.ProductName)'."
        [array]$CommandOutput = reg.exe delete "$CurrentKeyPath" /f
        if ($CommandOutput.Count -gt 0) { Write-Log $(($CommandOutput | Out-String).Trim()) }
    }
    $null = Pop-Location
}

##*===============================================
##* END FUNCTION LISTINGS
##*===============================================

##*===============================================
##* SCRIPT BODY
##*===============================================

If ($scriptParentPath) {
    Write-Log -Message "Script [$($MyInvocation.MyCommand.Definition)] dot-source invoked by [$(((Get-Variable -Name MyInvocation).Value).ScriptName)]" -Source $appDeployToolkitExtName
}
Else {
    Write-Log -Message "Script [$($MyInvocation.MyCommand.Definition)] invoked directly" -Source $appDeployToolkitExtName
}

##*===============================================
##* END SCRIPT BODY
##*===============================================
