#This script is used for bulk resetting user's voicemail and web portal passwords
#Create a CSV file with the list of accounts.
#


## Function for opening a Windows Dialog Box
Function Get-FileName($initialDirectory)
{
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = $initialDirectory
    $OpenFileDialog.filter = "CSV (*.csv)| *.csv"
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.filename
}


## Open a Windows Dialog Box and get the Input file
$inputfile = Get-FileName "C:\temp"
$inputdata = get-content $inputfile


##Admin and Session Variables
$global:localIpAddress=((ipconfig | findstr [0-9].\.)[0]).Split()[-1]
#Put your url here
$global:uri = "http://myservice.com/webservice/services/ProvisioningService?wsdl"
$global:adminuser = 'bobby'
$global:adminpassword = "P@ssword1"
$Logfile = "C:\Temp\Logs\ScriptLogs_$(get-date -format `"yyyyMMdd_hhmmsstt`").txt"

#User based variables
$global:newPassword = "changeme"
$global:newPasscode = "123456"


Foreach($global:userID in $inputdata)
{

######################Authenticate, Create XML OCI Reqest and Send Command for PasswordModifyRequest
Get-Login $global:uri $global:adminuser $global:adminpassword $global:localIpAddress
Get-PasswordModifyRequest $global:sessionID $global:userID $global:newPassword
$webrequest = Invoke-WebRequest -Uri $global:uri -Headers @{SOAPAction=''} -Method POST -Body $Global:xmlPasswordModifyRequest -ContentType "text/xml; charset=utf-8" -WebSession $Global:websession
Add-Content $Logfile -value "Password Modify"; Add-Content $Logfile -value $webrequest.Content

######################Authenticate, Create XML OCI Reqest and Send Command for UserPortalPasscodeModifyRequest
Get-Login $global:uri $global:adminuser $global:adminpassword $global:localIpAddress
Get-UserPortalPasscodeModifyRequest $global:sessionID $global:userID $global:newPasscode
$webrequest = Invoke-WebRequest -Uri $global:uri -Headers @{SOAPAction=''} -Method POST -Body $Global:xmlUserPortalPasscodeModifyRequest -ContentType "text/xml; charset=utf-8" -WebSession $Global:websession
Add-Content $Logfile -value "Passcode Modify" ; Add-Content $Logfile -value $webrequest.Content

######################Authenticate, Create XML OCI Reqest and Send Command for UserVoiceMessagingUserModifyVoiceManagementRequest
Get-Login $global:uri $global:adminuser $global:adminpassword $global:localIpAddress
Get-UserVoiceMessagingUserModifyVoiceManagementRequest $global:sessionID $global:userID
$webrequest = Invoke-WebRequest -Uri $global:uri -Headers @{SOAPAction=''} -Method POST -Body $Global:xmlUserVoiceMessagingUserModifyVoiceManagementRequest -ContentType "text/xml; charset=utf-8" -WebSession $Global:websession
Add-Content $Logfile -value "Message Modify" ; Add-Content $Logfile -value $webrequest.Content

######################Authenticate, Create XML OCI Reqest and Send Command for UserVoiceMessagingUserModifyGreetingRequest20
Get-Login $global:uri $global:adminuser $global:adminpassword $global:localIpAddress
Get-UserVoiceMessagingUserModifyGreetingRequest20 $global:sessionID $global:userID
$webrequest = Invoke-WebRequest -Uri $global:uri -Headers @{SOAPAction=''} -Method POST -Body $Global:xmlUserVoiceMessagingUserModifyGreetingRequest20 -ContentType "text/xml; charset=utf-8" -WebSession $Global:websession
Add-Content $Logfile -value "Reset Greetings" ; Add-Content $Logfile -value $webrequest.Content

######################Authenticate, Create XML OCI Reqest and Send Command for UserVoiceMessagingUserModifyVoicePortalRequest20
Get-Login $global:uri $global:adminuser $global:adminpassword $global:localIpAddress
Get-UserVoiceMessagingUserModifyVoicePortalRequest20 $global:sessionID $global:userID
$webrequest = Invoke-WebRequest -Uri $global:uri -Headers @{SOAPAction=''} -Method POST -Body $Global:xmlUserVoiceMessagingUserModifyVoicePortalRequest20 -ContentType "text/xml; charset=utf-8" -WebSession $Global:websession
Add-Content $Logfile -value "VoicePortal Modify" ; Add-Content $Logfile -value $webrequest.Content

######################Authenticate, Create XML OCI Reqest and Send Command for UserAnnouncementFileGetListRequest
Get-Login $global:uri $global:adminuser $global:adminpassword $global:localIpAddress
Get-UserAnnouncementFileGetListRequest $global:sessionID $global:userID
[xml] $webrequest = Invoke-WebRequest -Uri $global:uri -Headers @{SOAPAction=''} -Method POST -Body $Global:xmlUserAnnouncementFileGetListRequest -ContentType "text/xml; charset=utf-8" -WebSession $Global:websession

######################Create List of Recordings in the User's Announcement Repository and delete them
[xml] $doc = $webrequest.Envelope.Body.processOCIMessageResponse.processOCIMessageReturn 
$annoucements = $doc.BroadsoftDocument.command.announcementTable | % {
    foreach ($i in $_.row) {
        $o = New-Object Object
        #Add-Member -InputObject $o -MemberType NoteProperty -Name file -Value $i.announcementFileKey[0]
        Add-Member -InputObject $o -MemberType NoteProperty -Name Count -Value $i.col[0]
        $o
    }
}
foreach ($i in $annoucements) {
Get-Login $global:uri $global:adminuser $global:adminpassword $global:localIpAddress
Get-UserAnnouncementFileDeleteListRequest $global:sessionID $global:userID $i.Count
$webrequest = Invoke-WebRequest -Uri $global:uri -Headers @{SOAPAction=''} -Method POST -Body $Global:xmlUserAnnouncementFileDeleteListRequest -ContentType "text/xml; charset=utf-8" -WebSession $Global:websession
Add-Content $Logfile -value "Announcement Delete" ; Add-Content $Logfile -value $webrequest.Content
}

########################### Delete All Voicemails ########################################################################################
$beginURL = "http://myservice.com/com.broadsoft.xsi-actions/v2.0/user/"
$pair = "$($global:userID):$($global:newPassword)"
$encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
$basicAuthValue = "Basic $encodedCreds"
$Headers = @{
    Authorization = $basicAuthValue
}
$Headers = @{
    Authorization = $basicAuthValue
}

[xml]$xml = Invoke-WebRequest -Uri "https://myservice.com/com.broadsoft.xsi-actions/v2.0/user/$global:userID/voicemessagingmessages/" -Headers $Headers

$d = $xml.VoiceMessagingMessages.messageInfoList | % {
    foreach ($i in $_.messageInfo) {
        $o = New-Object Object
        Add-Member -InputObject $o -MemberType NoteProperty -Name ID -Value ($beginURL + $global:userID + "/voicemessagingmessages/" + ([regex]::matches($i.messageId, '(?m)(?<=\bvoicemessagingmessages\/).*$') | % {$_.value}))
        $o
    }
}
foreach ($i in $d) {
Invoke-WebRequest -Uri $i.ID -Headers $Headers -Method Delete
}
}