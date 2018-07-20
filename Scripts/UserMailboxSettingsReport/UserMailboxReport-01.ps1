$global:localIpAddress=((ipconfig | findstr [0-9].\.)[0]).Split()[-1]
$global:uri = "http://myservice.com/webservice/services/ProvisioningService?wsdl"
$global:adminuser = 'bobby'
$global:adminpassword = "P@ssword1"
$inputFile = "C:\temp\Logs\UserMailboxReportInput.csv"
$mailDomainId = "voice.local"
$manifest = "C:\Temp\Logs\UserMailboxReport$(get-date -format `"yyyyMMdd`").csv"
$users = Import-Csv $inputFile
$n = 0

foreach ($ID in $users) {
$n = $n + 1
Write-Host "$n. $ID.userID"
######################Authenticate, Create XML OCI Reqest and Send Command for UserVoiceMessagingUserGetAdvancedVoiceManagementRequest14sp3
######################Get current VM Authentication ID ##
Get-Login $global:uri $global:adminuser $global:adminpassword $global:localIpAddress
Get-UserVoiceMessagingUserGetAdvancedVoiceManagementRequest14sp3 $global:sessionID $ID.userID 
[xml] $webrequest = Invoke-WebRequest -Uri $global:uri -Headers @{SOAPAction=''} -Method POST -Body $Global:xmlUserVoiceMessagingUserGetAdvancedVoiceManagementRequest14sp3 -ContentType "text/xml; charset=utf-8" -WebSession $Global:websession


# Put the User information into an array
    [xml] $userlistdoc = $webrequest.Envelope.Body.processOCIMessageResponse.processOCIMessageReturn 
    $Global:userList = $userlistdoc.BroadsoftDocument.command | % {
    foreach ($s in $_) {
        $g = New-Object Object
            Add-Member -InputObject $g -MemberType NoteProperty -Name USERID -Value $ID.userID
            Add-Member -InputObject $g -MemberType NoteProperty -Name Enterprise -Value $ID.Enterprise
            Add-Member -InputObject $g -MemberType NoteProperty -Name Group -Value $ID.Group
            Add-Member -InputObject $g -MemberType NoteProperty -Name Extension -Value $ID.Extension
            Add-Member -InputObject $g -MemberType NoteProperty -Name mailServerSelection -Value $s.mailServerSelection
            Add-Member -InputObject $g -MemberType NoteProperty -Name groupMailServerUserId -Value $s.groupMailServerUserId
            Add-Member -InputObject $g -MemberType NoteProperty -Name useGroupDefaultMailServerFullMailboxLimit -Value $s.useGroupDefaultMailServerFullMailboxLimit
            Add-Member -InputObject $g -MemberType NoteProperty -Name personalMailServerNetAddress -Value $s.personalMailServerNetAddress
            Add-Member -InputObject $g -MemberType NoteProperty -Name personalMailServerProtocol -Value $s.personalMailServerProtocol
            Add-Member -InputObject $g -MemberType NoteProperty -Name personalMailServerEmailAddress -Value $s.personalMailServerEmailAddress
            Add-Member -InputObject $g -MemberType NoteProperty -Name personalMailServerUserId -Value $s.personalMailServerUserId
        $g
    }
    }
    $Global:userList | Export-Csv -Path $manifest  -Append
}
