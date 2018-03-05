<# 
.SYNOPSIS  
    This runbook is provided to monitor the status of a windows service
 
.AUTHOR CooperLutz

.EXAMPLE 
    .\Watch-Service -ServiceName Spooler 
 
#> 

Param 
( 
    [Parameter(Mandatory = $true)] 
    $ServiceName,

    [Parameter(Mandatory = $true)] 
    $ComputerName
 
) 

$Cred = Get-AzureRmAutomationCredential -ResourceGroupName "ResourceGroup01" -Name "MyCredential"

$Status = (Invoke-Command -ComputerName $ComputerName -ScriptBlock {Get-Service $ServiceName} -Credential $Cred).Status

# Add Logic to check the status of the service is "Running"
if ($Status -ne "Running") { 
    #Setup data to send to the Watcher Action
    $Properties = @{} 
    $Properties.ServiceName = $ServiceName
    $Properties.Status = $Status
    $Properties.ComputerName = $ComputerName
        
    $Data = $Properties | ConvertTo-Json 
        
    # Invoke the watcher action, passing the data
    Invoke-AutomationWatcherAction -Message "Process Service..." -Data $Data
     
} 