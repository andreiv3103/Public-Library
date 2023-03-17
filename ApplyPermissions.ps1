Param (
    [switch]$ApplyPermissions
)
Clear-Host
## Template ID.
$TemplateID = "7ac123e2-c257-4095-b586-fcf5d655bf0a"
## GUID Regex.
[string]$GuidRegex = "[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?"
## Define the template file path.
$TemplateFilePath = "$PSScriptRoot\*.xml"
## Load the template file and cast to XML.
$TemplateXml = [XML](Get-Content -Path $TemplateFilePath -Raw -Encoding 'utf8')
$RightsList = $TemplateXml.SelectNodes(".//RIGHTSLIST")
[array]$Targets = @()
foreach ($Item in $RightsList.ChildNodes) {
    $CurrentAccounts = $Item.SelectNodes(".//NAME").'#text'
    foreach ($Account in $CurrentAccounts) {
        if (($Account -notmatch $GuidRegex) -and ($Account -like "*@*")) {
            $Targets += [PSCustomObject]@{
                Right   = $Item.Name
                Account = $Account
            }
        }
    }
}
## $Targets | Sort-Object -Property 'Account'
$RightsDefParameters = @{}
foreach ($Item in $Targets) {
    try {
        $RightsDefParameters.Add($Item.Account, @($Item.Right))
    }
    catch {
        $RightsDefParameters[$Item.Account] += $Item.Right
    }
}
## Display the data for reference.
foreach ($Item in $RightsDefParameters.GetEnumerator()) {
    $Item.Key
    $Item.Value -join ','
}
if ($ApplyPermissions) {
    Connect-AipService
    ## Build the rights definition array.
    [array]$RightsToAdd = @()
    foreach ($Item in $RightsDefParameters.GetEnumerator()) {
        $CmdletParams = @{
            EmailAddress = $Item.Key
            Rights       = $Item.Value
        }
        $RightsToAdd += New-AipServiceRightsDefinition @CmdletParams
    }
    $CurrentRightsDefinitions = [array]((Get-AipServiceTemplate -TemplateID $TemplateID).RightsDefinitions)
    $ResultingRightsDefinitions = $CurrentRightsDefinitions + $RightsToAdd
    Set-AipServiceTemplateProperty -TemplateID $TemplateID -RightsDefinition $ResultingRightsDefinitions
}
