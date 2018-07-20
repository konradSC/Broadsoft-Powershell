# This script will reset a enterprise's phones one at a time every 10 seconds

##Admin and Session Variables
$global:localIpAddress=((ipconfig | findstr [0-9].\.)[0]).Split()[-1]
$global:uri = "http://myservice.com/webservice/services/ProvisioningService?wsdl"
$global:adminuser = 'bobby'
$global:adminpassword = "P@ssword1"
$enterpriseID = "enterprise1"
$Global:userInfo = @()
$Global:userList = @()
$Global:deviceList = @()


######################Authenticate, Create XML OCI Reqest and Send Command for GroupGetListInServiceProviderRequest
Get-Login $global:uri $global:adminuser $global:adminpassword $global:localIpAddress
Get-GroupGetListInServiceProviderRequest $global:sessionID $enterpriseID
#get the groups
[xml] $webrequest2 = Invoke-WebRequest -Uri $global:uri -Headers @{SOAPAction=''} -Method POST -Body $Global:xmlGroupGetListInServiceProviderRequest -ContentType "text/xml; charset=utf-8" -WebSession $Global:websession

# Put the groups into an array
    [xml] $groupdoc = $webrequest2.Envelope.Body.processOCIMessageResponse.processOCIMessageReturn 
    $Global:groupId = $groupdoc.BroadsoftDocument.command.groupTable | % {
    foreach ($v in $_.row) {
        $g = New-Object Object
            Add-Member -InputObject $g -MemberType NoteProperty -Name Group -Value $v.col[0]
            Add-Member -InputObject $g -MemberType NoteProperty -Name Enterprise -Value $enterpriseID
        $g
    }
    }
    
    foreach ($grouparray in $Global:groupId) {
        # Get the DeviceID
        Get-Login $global:uri $global:adminuser $global:adminpassword $global:localIpAddress
        Get-GroupAccessDeviceGetListRequest $global:sessionID $grouparray.Enterprise $grouparray.Group
        [xml] $webrequest5 = Invoke-WebRequest -Uri $global:uri -Headers @{SOAPAction=''} -Method POST -Body $Global:xmlGroupAccessDeviceGetListRequest -ContentType "text/xml; charset=utf-8" -WebSession $Global:websession
        [xml] $devicedoc = $webrequest5.Envelope.Body.processOCIMessageResponse.processOCIMessageReturn

        # Add DeviceId into an array
        $devicedoc.BroadsoftDocument.command.accessDeviceTable | % {
        foreach ($s in $_.row) {
                $f = New-Object Object
                Add-Member -InputObject $f -MemberType NoteProperty -Name DeviceName -Value $s.col[0]
                Add-Member -InputObject $f -MemberType NoteProperty -Name Group -Value $grouparray.Group
                Add-Member -InputObject $f -MemberType NoteProperty -Name Enterprise -Value $enterpriseID
        $Global:deviceList += $f   
        }
}
}

# Reboot the flipping phones already
$n = 0

foreach ($deviceID in $Global:deviceList) {
$n = $n + 1
Write-Host "$n. $($deviceID.Group) $($deviceID.DeviceName)"
######################Authenticate, Create XML OCI Reqest and Send Command for GroupCPEConfigRebuildDeviceConfigFileRequest
Get-Login $global:uri $global:adminuser $global:adminpassword $global:localIpAddress
Get-GroupCPEConfigRebuildDeviceConfigFileRequest $global:sessionID $deviceID.Enterprise $deviceID.Group $deviceID.DeviceName 
[xml] $webrequest = Invoke-WebRequest -Uri $global:uri -Headers @{SOAPAction=''} -Method POST -Body $Global:xmlGroupCPEConfigRebuildDeviceConfigFileRequest -ContentType "text/xml; charset=utf-8" -WebSession $Global:websession

Get-Login $global:uri $global:adminuser $global:adminpassword $global:localIpAddress
Get-GroupCPEConfigResetDeviceRequest $global:sessionID $deviceID.Enterprise $deviceID.Group $deviceID.DeviceName 
[xml] $webrequest2 = Invoke-WebRequest -Uri $global:uri -Headers @{SOAPAction=''} -Method POST -Body $Global:xmlGroupCPEConfigResetDeviceRequest -ContentType "text/xml; charset=utf-8" -WebSession $Global:websession
Start-Sleep -s 10
}

