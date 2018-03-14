param(
    [object]$WEBHOOKDATA
)

$connectionName = "AzureRunAsConnection"
try
{
    # Get the connection "AzureRunAsConnection "
    $servicePrincipalConnection=Get-AutomationConnection -Name $connectionName         

    "Logging in to Azure..."
    Add-AzureRmAccount `
        -ServicePrincipal `
        -TenantId $servicePrincipalConnection.TenantId `
        -ApplicationId $servicePrincipalConnection.ApplicationId `
        -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint 
}
catch {
    if (!$servicePrincipalConnection)
    {
        $ErrorMessage = "Connection $connectionName not found."
        throw $ErrorMessage
    } else{
        Write-Error -Message $_.Exception
        throw $_.Exception
    }
}

$body = $WebhookData.RequestBody | convertfrom-json
$vm =  $body.data.vm_name

Write-Output "Searching for VM..." 
$vms = Get-AzureRMVM
$vm = $vms | ? {$_.Name -eq $vm}

Write-Output "Restarting $($body.data.vm_name)"
$vm | restart-azurermvm