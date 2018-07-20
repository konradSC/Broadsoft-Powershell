﻿#Get Group Service Packs
#


$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($adminPassword)
$global:adminPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

##Admin and Session Variables
$global:localIpAddress=((ipconfig | findstr [0-9].\.)[0]).Split()[-1]
$global:uri = "http://myservice.com/webservice/services/ProvisioningService?wsdl"
$global:adminuser = 'bobby'
$global:adminpassword = "P@ssword1"
$Logfile = "C:\Temp\Logs\ScriptLogs_$(get-date -format `"yyyyMMdd_hhmmsstt`").txt"
$manifest = "C:\Temp\Logs\GroupLicenses_$(get-date -format `"yyyyMMdd`").csv"

######################Authenticate, Create XML OCI Reqest and Send Command for ServiceProviderGetListRequest
Get-Login $global:uri $global:adminuser $global:adminpassword $global:localIpAddress
Get-ServiceProviderGetListRequest $global:sessionID
[xml] $webrequest = Invoke-WebRequest -Uri $global:uri -Headers @{SOAPAction=''} -Method POST -Body $Global:xmlServiceProviderGetListRequest -ContentType "text/xml; charset=utf-8" -WebSession $Global:websession

######################Create List of Enterprises
[xml] $doc = $webrequest.Envelope.Body.processOCIMessageResponse.processOCIMessageReturn 
$Global:serviceProviderId = $doc.BroadsoftDocument.command.serviceProviderTable | % {
    foreach ($i in $_.row) {
        $o = New-Object Object
            Add-Member -InputObject $o -MemberType NoteProperty -Name Enterprise -Value $i.col[0]
        $o
    }
}

foreach ($enterprise in $Global:serviceProviderId) {
######################Authenticate, Create XML OCI Reqest and Send Command for GroupGetListInServiceProviderRequest
Get-Login $global:uri $global:adminuser $global:adminpassword $global:localIpAddress
Get-GroupGetListInServiceProviderRequest $global:sessionID $enterprise.Enterprise
#get the groups
[xml] $webrequest2 = Invoke-WebRequest -Uri $global:uri -Headers @{SOAPAction=''} -Method POST -Body $Global:xmlGroupGetListInServiceProviderRequest -ContentType "text/xml; charset=utf-8" -WebSession $Global:websession

# Put the groups into an array
    [xml] $groupdoc = $webrequest2.Envelope.Body.processOCIMessageResponse.processOCIMessageReturn 
    $Global:groupId = $groupdoc.BroadsoftDocument.command.groupTable | % {
    foreach ($s in $_.row) {
        $g = New-Object Object
            Add-Member -InputObject $g -MemberType NoteProperty -Name Group -Value $s.col[0]
            Add-Member -InputObject $g -MemberType NoteProperty -Name Enterprise -Value $enterprise.Enterprise
        $g
    }

    foreach ($grouparray in $Global:groupId) {
    # Get the service packs
    Get-Login $global:uri $global:adminuser $global:adminpassword $global:localIpAddress
    Get-GroupServiceGetAuthorizationListRequest $global:sessionID $grouparray.Enterprise $grouparray.Group
    [xml] $webrequest3 = Invoke-WebRequest -Uri $global:uri -Headers @{SOAPAction=''} -Method POST -Body $Global:xmlGroupServiceGetAuthorizationListRequest -ContentType "text/xml; charset=utf-8" -WebSession $Global:websession
    
    #Process the service packs and put them in a csv
    [xml] $servicepackdoc = $webrequest3.Envelope.Body.processOCIMessageResponse.processOCIMessageReturn
    $Global:servicePack = $servicepackdoc.BroadsoftDocument.command.servicePacksAuthorizationTable | % {
        foreach ($u in $_.row) {
                        $n = New-Object Object
                        Add-Member -InputObject $n -MemberType NoteProperty -Name Enterprise -Value $grouparray.Enterprise
                        Add-Member -InputObject $n -MemberType NoteProperty -Name Group -Value $grouparray.Group
                        Add-Member -InputObject $n -MemberType NoteProperty -Name Package -Value $u.col[0]
                        Add-Member -InputObject $n -MemberType NoteProperty -Name Count -Value $u.col[6]
                        $n
                    } 
    $Global:servicePack | Export-Csv -Path $manifest  -Append
     }
}
}
}

