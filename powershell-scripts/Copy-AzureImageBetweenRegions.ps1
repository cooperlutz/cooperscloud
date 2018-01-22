<##################################################

BEFORE RUNNING THIS SCRIPT

Step 1: Deploy a dummy VM using existing image
Step 2: Sysprep the dummy VM
Step 3: Run this script

###################################################>

Param (
    [Parameter(Mandatory=$true)] $SourceImageVmRgName,
    [Parameter(Mandatory=$true)] $SourceImageVmOsDiskName,
    [Parameter(Mandatory=$true)] $StorageAccountName,
    [Parameter(Mandatory=$true)] $StorageAccountKey,
    [Parameter(Mandatory=$true)] $SourceImageRGName,
    [Parameter(Mandatory=$true)] $DestinationContainerName,
    [Parameter(Mandatory=$true)] $DestinationRegion,
    [Parameter(Mandatory=$true)] $DestinationImageName,
    [Parameter(Mandatory=$true)] $DestinationRgName
)

$Sas = Grant-AzureRmDiskAccess -ResourceGroupName $SourceImageVmRgName -DiskName $SourceImageVmOsDiskName -DurationInSecond 3600 -Access Read  
$DestinationStorageContext = New-AzureStorageContext –StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKey
$BlobCopy = Start-AzureStorageBlobCopy -AbsoluteUri $Sas.AccessSAS -DestContainer $DestContainerName -DestContext $DestinationStorageContext -DestBlob "$DestinationImageName.vhd"


## Create an image from the vhd in the preferred region

$ImageConfig = New-AzureRmImageConfig -Location $DestinationRegion;
$OsDiskVhdUri = "https://$StorageAccountName.blob.core.windows.net/$DestinationContainerName/$DestinationBlobName"

Set-AzureRmImageOsDisk -Image $ImageConfig -OsType 'Windows' -OsState 'Generalized' -BlobUri $OsDiskVhdUri
New-AzureRmImage -Image $ImageConfig -ImageName $DestinationImageName -ResourceGroupName $DestinationRgName