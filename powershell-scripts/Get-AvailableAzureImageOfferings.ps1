## Want a quick and easy way to see available images from the Azure marketplace?

Param (
    [Parameter(Mandatory=$true)] $Region
)

$Publishers =  Get-AzureRmVMImagePublisher -Location $Region | Out-GridView -PassThru
$Offers = Get-AzureRmVMImageOffer -Location $Region -PublisherName $Publishers.PublisherName | Out-GridView -PassThru
$Sku = Get-AzureRmVMImageSku -Location $Region -PublisherName $Publishers.PublisherName -Offer $Offers.Offer | Out-GridView -PassThru
$Publishers.PublisherName
$Offers.Offer
$Sku.Skus