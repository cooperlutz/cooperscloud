<# 
.SYNOPSIS  
    This runbook is provided to serve as an Azure Automation Watcher Task Action
 
.AUTHOR CooperLutz
 
#> 

param( 
    $EVENTDATA
) 

$Cred = Get-AzureRmAutomationCredential -ResourceGroupName "ResourceGroup01" -Name "MyCredential"

Write-Output("Passed in data is " + ($EVENTDATA.EventProperties.Data | ConvertFrom-Json)) 

$ServiceName = ($EVENTDATA.EventProperties.Data | ConvertFrom-Json).ServiceName
$ComputerName = ($EVENTDATA.EventProperties.Data | ConvertFrom-Json).ComputerName

Write-Output "Restarting $ServiceName on $ComputerName..."


Invoke-Command -ComputerName $ComputerName -ScriptBlock {Restart-Service $ServiceName} -Credential $Cred