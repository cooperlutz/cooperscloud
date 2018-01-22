Param(
    [Parameter(Mandatory=$true)] $SourceVault,
    [Parameter(Mandatory=$true)] $DestinationVault
)

$SourceSecrets = Get-AzureKeyVaultSecret -VaultName $SourceVault

foreach($Secret in $SourceSecrets) {

Set-AzureKeyVaultSecret -VaultName coopervault-east -Name $Secret.Name  -SecretValue (ConvertTo-SecureString (Get-AzureKeyVaultSecret -VaultName $SourceVault -name $Secret.Name).SecretValueText -AsPlainText -Force)

}