<#
Param(
    [Parameter(Mandatory=$true)][string]$global:adminuser,
    [Parameter(Mandatory=$true)][Security.SecureString]$secureadminPassword
)

$global:adminPassword = ""
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureadminPassword)
$global:adminPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
#>
##Admin and Session Variables
$global:localIpAddress=((ipconfig | findstr [0-9].\.)[0]).Split()[-1]
$global:uri = "http://myservice.com/webservice/services/ProvisioningService?wsdl"
$global:adminuser = 'username'
$global:adminpassword = "pass"
$Logfile = "C:\Temp\Logs\ScriptLogs_$(get-date -format `"yyyyMMdd_hhmmsstt`").txt"
$manifest = "C:\Temp\Logs\SystemUserReport$(get-date -format `"yyyyMMdd`").csv"
$Global:userInfo = @()
$Global:userList = @()
$n = 0 
######################Authenticate, Create XML OCI Reqest and Send Command for ServiceProviderGetListRequest
Get-Login $global:uri $global:adminuser $global:adminpassword $global:localIpAddress
Get-ServiceProviderGetListRequest $global:sessionID
[xml] $webrequest6 = Invoke-WebRequest -Uri $global:uri -Headers @{SOAPAction=''} -Method POST -Body $Global:xmlServiceProviderGetListRequest -ContentType "text/xml; charset=utf-8" -WebSession $Global:websession

######################Create List of Enterprises
[xml] $doc = $webrequest6.Envelope.Body.processOCIMessageResponse.processOCIMessageReturn 
$Global:serviceProviderId = $doc.BroadsoftDocument.command.serviceProviderTable | % {
    foreach ($i in $_.row) {
        $o = New-Object Object
            Add-Member -InputObject $o -MemberType NoteProperty -Name Enterprise -Value $i.col[0]
        $o
    }
}

foreach ($enterpriseID in $Global:serviceProviderId) {
$n = $n + 1
write-host "$n. $($enterpriseID.Enterprise)"
######################Authenticate, Create XML OCI Reqest and Send Command for UserGetListInServiceProviderRequest
Get-Login $global:uri $global:adminuser $global:adminpassword $global:localIpAddress
Get-UserGetListInServiceProviderRequest $global:sessionID $enterpriseID.Enterprise
#get the Users
[xml] $webrequest = Invoke-WebRequest -Uri $global:uri -Headers @{SOAPAction=''} -Method POST -Body $Global:xmlUserGetListInServiceProviderRequest -ContentType "text/xml; charset=utf-8" -WebSession $Global:websession

# Put the Users into an array
    [xml] $userlistdoc = $webrequest.Envelope.Body.processOCIMessageResponse.processOCIMessageReturn 
    $Global:userList = $userlistdoc.BroadsoftDocument.command.userTable | % {
    foreach ($s in $_.row) {
        $g = New-Object Object
            Add-Member -InputObject $g -MemberType NoteProperty -Name USERID -Value $s.col[0]
            Add-Member -InputObject $g -MemberType NoteProperty -Name Enterprise -Value $enterpriseID
            Add-Member -InputObject $g -MemberType NoteProperty -Name Group -Value $s.col[1]
        $g
    }
    }


    foreach ($userarray in $Global:userList) {
        # Get the User's name, number, extension, line, device
        Get-Login $global:uri $global:adminuser $global:adminpassword $global:localIpAddress
        Get-UserGetRequest20 $global:sessionID $userarray.USERID
        [xml] $webrequest2 = Invoke-WebRequest -Uri $global:uri -Headers @{SOAPAction=''} -Method POST -Body $Global:xmlUserGetRequest20 -ContentType "text/xml; charset=utf-8" -WebSession $Global:websession
        [xml] $userinfodoc = $webrequest2.Envelope.Body.processOCIMessageResponse.processOCIMessageReturn 
        
        # Get the User's Email CC
        Get-Login $global:uri $global:adminuser $global:adminpassword $global:localIpAddress
        Get-UserVoiceMessagingUserGetVoiceManagementRequest17 $global:sessionID $userarray.USERID
        [xml] $webrequest3 = Invoke-WebRequest -Uri $global:uri -Headers @{SOAPAction=''} -Method POST -Body $Global:xmlUserVoiceMessagingUserGetVoiceManagementRequest17 -ContentType "text/xml; charset=utf-8" -WebSession $Global:websession
        [xml] $useremailccdoc = $webrequest3.Envelope.Body.processOCIMessageResponse.processOCIMessageReturn

        # Get the User's Service Pack
        Get-Login $global:uri $global:adminuser $global:adminpassword $global:localIpAddress
        Get-UserServiceGetAssignmentListRequest $global:sessionID $userarray.USERID
        [xml] $webrequest4 = Invoke-WebRequest -Uri $global:uri -Headers @{SOAPAction=''} -Method POST -Body $Global:xmlUserServiceGetAssignmentListRequest -ContentType "text/xml; charset=utf-8" -WebSession $Global:websession
        [xml] $userservicepackdoc = $webrequest4.Envelope.Body.processOCIMessageResponse.processOCIMessageReturn

        # Get the User's Registration
        Get-Login $global:uri $global:adminuser $global:adminpassword $global:localIpAddress
        Get-UserGetRegistrationListRequest $global:sessionID $userarray.USERID
        [xml] $webrequest6 = Invoke-WebRequest -Uri $global:uri -Headers @{SOAPAction=''} -Method POST -Body $Global:xmlUserGetRegistrationListRequest -ContentType "text/xml; charset=utf-8" -WebSession $Global:websession
        [xml] $userregistrationdoc = $webrequest6.Envelope.Body.processOCIMessageResponse.processOCIMessageReturn
                
        # Add User Information to array
        $userinfodoc.BroadsoftDocument.command | % {
        foreach ($s in $_) {
            $f = New-Object Object
                Add-Member -InputObject $f -MemberType NoteProperty -Name USERID -Value $userarray.USERID
                Add-Member -InputObject $f -MemberType NoteProperty -Name Enterprise -Value $s.serviceProviderId
                Add-Member -InputObject $f -MemberType NoteProperty -Name Group -Value $s.groupId
                Add-Member -InputObject $f -MemberType NoteProperty -Name FirstName -Value $s.firstName
                Add-Member -InputObject $f -MemberType NoteProperty -Name LastName -Value $s.lastName
                Add-Member -InputObject $f -MemberType NoteProperty -Name PhoneNumber -Value $s.phoneNumber
                Add-Member -InputObject $f -MemberType NoteProperty -Name Extension -Value $s.extension
                Add-Member -InputObject $f -MemberType NoteProperty -Name CallingLineIdPhoneNumber -Value $s.callingLineIdPhoneNumber
                Add-Member -InputObject $f -MemberType NoteProperty -Name DeviceName -Value $s.accessDeviceEndpoint.accessDevice.deviceName
            }
        
        # Add Email CC Information to array
        $useremailccdoc.BroadsoftDocument.command | % {
        foreach ($s in $_) {
                Add-Member -InputObject $f -MemberType NoteProperty -Name EmailCC -Value $s.voiceMessageCarbonCopyEmailAddress
        }
        
        # Get the Device's MAC
        Get-Login $global:uri $global:adminuser $global:adminpassword $global:localIpAddress
        Get-GroupAccessDeviceGetRequest18sp1 $global:sessionID $f.Enterprise $f.Group $f.DeviceName
        [xml] $webrequest5 = Invoke-WebRequest -Uri $global:uri -Headers @{SOAPAction=''} -Method POST -Body $Global:xmlGroupAccessDeviceGetRequest18sp1 -ContentType "text/xml; charset=utf-8" -WebSession $Global:websession
        [xml] $devicedoc = $webrequest5.Envelope.Body.processOCIMessageResponse.processOCIMessageReturn

        # Add MAC and Device Type Information to array
        $devicedoc.BroadsoftDocument.command | % {
        foreach ($s in $_) {
                Add-Member -InputObject $f -MemberType NoteProperty -Name DeviceType -Value $s.deviceType
                Add-Member -InputObject $f -MemberType NoteProperty -Name MAC -Value $s.macAddress
                Add-Member -InputObject $f -MemberType NoteProperty -Name Version -Value $s.version
        }
        
        #Add Device Registration status to array
        Add-Member -InputObject $f -MemberType NoteProperty -Name Registration -Value "Not Registered"
        $userregistrationdoc.BroadsoftDocument.command| % {
        foreach ($s in $_.registrationTable.row) {
                if ($s.col[6] -eq "Primary") {Add-Member -InputObject $f -MemberType NoteProperty -Name Registration -Value "Registered" -Force}
                 
        }
        } 
        
        # Add Service Pack Information to array
        $t = @()
        $userservicepackdoc.BroadsoftDocument.command | % {
        foreach ($s in $_.servicePacksAssignmentTable.row) {
                if ($s.col[1] -eq "true") {$t+=$s.col[0]}
                
        }
        $v = $t -join ", "
        Add-Member -InputObject $f -MemberType NoteProperty -Name ServicePack -Value $v -force 
        }
   
}
}

$Global:userInfo += $f
}
}
$Global:userInfo | Export-Csv -Path $manifest  -Append
}