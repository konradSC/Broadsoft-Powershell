######################################################################################################################################
#### Function to generating encryption and hash ######################################################################################
Function Get-StringHash([String] $String,$HashName) 
{ 
$StringBuilder = New-Object System.Text.StringBuilder 
[System.Security.Cryptography.HashAlgorithm]::Create($HashName).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String))|%{ 
[Void]$StringBuilder.Append($_.ToString("x2")) 
} 
$StringBuilder.ToString() 
}
######################################################################################################################################

######################################################################################################################################
#### Function for SOAP Authentication ################################################################################################
Function Get-Login ([String] $uri, $adminuser, $adminpassword,[String] $localIpAddress)
{
$sessionRandom = Get-Random -Minimum 100000000 -Maximum 999999999
$sessionID = $localIpAddress + "," + $sessionRandom
$xml = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="AuthenticationRequest" xmlns="">
                <userId>$adminuser</userId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

#$header = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+$password))}
$webrequest = Invoke-WebRequest -Uri $uri -Headers @{SOAPAction=''} -Method Post -Body $xml -ContentType "text/xml; charset=utf-8" -SessionVariable websession
$cookie = $websession.Cookies.GetCookies($uri)
#Write-Host $cookie.value
[xml]$xmlresponse = $webrequest
$nonce = ([regex]::matches($xmlresponse.Envelope.Body.processOCIMessageResponse.processOCIMessageReturn, '(?m)(?<=\bnonce\>)\d+') | % {$_.value})
$passwordSHA = Get-StringHash $adminpassword "SHA"
#Write-Host "SHA Password = $passwordSHA"
#Write-Host "NONCE = $nonce"
$prepassword = $nonce + ":" + $passwordSHA
$sessionpassword = Get-StringHash $prepassword "MD5"
#Write-Host "SHA Password = $sessionpassword"
#Write-Host "Session ID = $sessionID"

#### Respond with Authentication
$xml = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="LoginRequest14sp4" xmlns="">
                <userId>$adminuser</userId>
                <signedPassword>$sessionpassword</signedPassword>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$webrequest = Invoke-WebRequest -Uri $uri -Headers @{SOAPAction=''} -Method Post -Body $xml -ContentType "text/xml; charset=utf-8" -WebSession $websession
$Global:sessionID = $sessionID
$Global:websession = $websession
}
######################################################################################################################################
#### Function for PasswordModifyRequest ##############################################################################################
Function Get-PasswordModifyRequest([String] $sessionID, $userID, $newPassword)
{
$xmlPasswordModifyRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="PasswordModifyRequest" xmlns="">
                    <userId>$userID</userId>
                    <newPassword>$newPassword</newPassword>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlPasswordModifyRequest = $xmlPasswordModifyRequest
}

######################################################################################################################################
#### Function for UserPortalPasscodeModifyRequest ####################################################################################
Function Get-UserPortalPasscodeModifyRequest([String] $sessionID, $userID, $newPasscode)
{
$xmlUserPortalPasscodeModifyRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserPortalPasscodeModifyRequest" xmlns="">
                    <userId>$userID</userId>
                    <newPasscode>$newPasscode</newPasscode>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserPortalPasscodeModifyRequest = $xmlUserPortalPasscodeModifyRequest
}
######################################################################################################################################
#### Function for UserAnnouncementFileGetAvailableListRequest ########################################################################
Function Get-UserAnnouncementFileGetAvailableListRequest([String] $sessionID, $userID)
{
$xmlUserAnnouncementFileGetAvailableListRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserAnnouncementFileGetAvailableListRequest" xmlns="">
                    <userId>$userID</userId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:UserAnnouncementFileGetAvailableListRequest = $UserAnnouncementFileGetAvailableListRequest
}
######################################################################################################################################
#### Function for UserVoiceMessagingUserModifyGreetingRequest20 ########################################################################
Function Get-UserVoiceMessagingUserModifyGreetingRequest20([String] $sessionID, $userID)
{
$xmlUserVoiceMessagingUserModifyGreetingRequest20 = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserVoiceMessagingUserModifyGreetingRequest20" xmlns="">
                    <userId>$userID</userId>
                    <busyAnnouncementSelection>Default</busyAnnouncementSelection>
                    <busyPersonalAudioFile xsi:nil="true"/>
                    <busyPersonalVideoFile xsi:nil="true"/>
                    <noAnswerAnnouncementSelection>Default</noAnswerAnnouncementSelection>
                    <noAnswerPersonalAudioFile xsi:nil="true"/>
                    <noAnswerPersonalVideoFile xsi:nil="true"/>
                    <noAnswerAlternateGreeting01>
                      <name xsi:nil="true"/>
                      <audioFile xsi:nil="true"/>
                      <videoFile xsi:nil="true"/>
                    </noAnswerAlternateGreeting01>
                    <noAnswerAlternateGreeting02>
                      <name xsi:nil="true"/>
                      <audioFile xsi:nil="true"/>
                      <videoFile xsi:nil="true"/>
                    </noAnswerAlternateGreeting02>
                    <noAnswerAlternateGreeting03>
                      <name xsi:nil="true"/>
                      <audioFile xsi:nil="true"/>
                      <videoFile xsi:nil="true"/>
                    </noAnswerAlternateGreeting03>
                    <extendedAwayEnabled>false</extendedAwayEnabled>
                    <extendedAwayDisableMessageDeposit>true</extendedAwayDisableMessageDeposit>
                    <extendedAwayAudioFile xsi:nil="true"/>
                    <extendedAwayVideoFile xsi:nil="true"/>
                    <noAnswerNumberOfRings>5</noAnswerNumberOfRings>
                    <disableMessageDeposit>false</disableMessageDeposit>
                    <disableMessageDepositAction>Disconnect</disableMessageDepositAction>
                    <greetingOnlyForwardDestination xsi:nil="true"/>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserVoiceMessagingUserModifyGreetingRequest20 = $xmlUserVoiceMessagingUserModifyGreetingRequest20
}
######################################################################################################################################
#### Function for UserVoiceMessagingUserModifyVoicePortalRequest20 ###################################################################
Function Get-UserVoiceMessagingUserModifyVoicePortalRequest20([String] $sessionID, $userID)
{
$xmlUserVoiceMessagingUserModifyVoicePortalRequest20 = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserVoiceMessagingUserModifyVoicePortalRequest20" xmlns="">
                    <userId>$userID</userId>
                    <voicePortalAutoLogin>false</voicePortalAutoLogin>
                    <personalizedNameAudioFile xsi:nil="true"/>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserVoiceMessagingUserModifyVoicePortalRequest20 = $xmlUserVoiceMessagingUserModifyVoicePortalRequest20
}
######################################################################################################################################
#### Function for UserAnnouncementFileGetListRequest #################################################################################
Function Get-UserAnnouncementFileGetListRequest([String] $sessionID, $userID)
{
$xmlUserAnnouncementFileGetListRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserAnnouncementFileGetListRequest" xmlns="">
                    <userId>$userID</userId>
                    <announcementFileType>Audio</announcementFileType>
                    <includeAnnouncementTable>true</includeAnnouncementTable>
                    <responseSizeLimit>1000</responseSizeLimit>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserAnnouncementFileGetListRequest = $xmlUserAnnouncementFileGetListRequest
}

######################################################################################################################################
#### Function for UserAnnouncementFileDeleteListRequest ##############################################################################
Function Get-UserAnnouncementFileDeleteListRequest([String] $sessionID, $userID, [String] $announcementFile)
{
$xmlUserAnnouncementFileDeleteListRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserAnnouncementFileDeleteListRequest" xmlns="">
                    <userId>$userID</userId>
                    <announcementFileKey>
                      <name>$announcementFile</name>
                      <mediaFileType>WAV</mediaFileType>
                    </announcementFileKey>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserAnnouncementFileDeleteListRequest = $xmlUserAnnouncementFileDeleteListRequest
}

######################################################################################################################################
#### Function for UserVoiceMessagingUserModifyVoiceManagementRequest ##############################################################################
Function Get-UserVoiceMessagingUserModifyVoiceManagementRequest([String] $sessionID, $userID)
{
$xmlUserVoiceMessagingUserModifyVoiceManagementRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserVoiceMessagingUserModifyVoiceManagementRequest" xmlns="">
                    <userId>$userID</userId>
                    <isActive>true</isActive>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserVoiceMessagingUserModifyVoiceManagementRequest = $xmlUserVoiceMessagingUserModifyVoiceManagementRequest
}

######################################################################################################################################
#### Function for GroupGetListInServiceProviderRequest ##############################################################################
Function Get-GroupGetListInServiceProviderRequest([String] $sessionID, $serviceProviderId)
{
$xmlGroupGetListInServiceProviderRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="GroupGetListInServiceProviderRequest" xmlns="">
                    <serviceProviderId>$serviceProviderId</serviceProviderId>  
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlGroupGetListInServiceProviderRequest = $xmlGroupGetListInServiceProviderRequest
}

######################################################################################################################################
#### Function for GroupServiceGetAuthorizationListRequest ##############################################################################
Function Get-GroupServiceGetAuthorizationListRequest([String] $sessionID, $serviceProviderId, $groupId)
{
$xmlGroupServiceGetAuthorizationListRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="GroupServiceGetAuthorizationListRequest" xmlns="">
                    <serviceProviderId>$serviceProviderId</serviceProviderId>
                    <groupId>$groupId</groupId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlGroupServiceGetAuthorizationListRequest = $xmlGroupServiceGetAuthorizationListRequest
}


######################################################################################################################################
#### Function for UserGetListInServiceProviderRequest ##############################################################################
Function Get-UserGetListInServiceProviderRequest([String] $sessionID, $serviceProviderId)
{
$xmlUserGetListInServiceProviderRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserGetListInServiceProviderRequest" xmlns="">
                    <serviceProviderId>$serviceProviderId</serviceProviderId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserGetListInServiceProviderRequest = $xmlUserGetListInServiceProviderRequest
}


######################################################################################################################################
#### Function for UserGetRequest20 ##############################################################################
Function Get-UserGetRequest20([String] $sessionID, $userID)
{
$xmlUserGetRequest20 = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserGetRequest20" xmlns="">
                    <userId>$userID</userId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserGetRequest20 = $xmlUserGetRequest20
}


######################################################################################################################################
#### Function for UserVoiceMessagingUserGetVoiceManagementRequest17 ##############################################################################
Function Get-UserVoiceMessagingUserGetVoiceManagementRequest17([String] $sessionID, $userID)
{
$xmlUserVoiceMessagingUserGetVoiceManagementRequest17 = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserVoiceMessagingUserGetVoiceManagementRequest17" xmlns="">
                    <userId>$userID</userId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserVoiceMessagingUserGetVoiceManagementRequest17 = $xmlUserVoiceMessagingUserGetVoiceManagementRequest17
}


######################################################################################################################################
#### Function for UserServiceGetAssignmentListRequest ##############################################################################
Function Get-UserServiceGetAssignmentListRequest([String] $sessionID, $userID)
{
$xmlUserServiceGetAssignmentListRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserServiceGetAssignmentListRequest" xmlns="">
                    <userId>$userID</userId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserServiceGetAssignmentListRequest = $xmlUserServiceGetAssignmentListRequest
}


######################################################################################################################################
#### Function for GroupAccessDeviceGetRequest18sp1 ##############################################################################
Function Get-GroupAccessDeviceGetRequest18sp1([String] $sessionID, $serviceProviderId, $groupId , $deviceName)
{
$xmlGroupAccessDeviceGetRequest18sp1 = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="GroupAccessDeviceGetRequest18sp1" xmlns="">
                    <serviceProviderId>$serviceProviderId</serviceProviderId>
                    <groupId>$groupId</groupId>
                    <deviceName>$deviceName</deviceName>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlGroupAccessDeviceGetRequest18sp1 = $xmlGroupAccessDeviceGetRequest18sp1
}

######################################################################################################################################
#### Function for SystemAccessDeviceGetAllRequest ##############################################################################################
Function Get-SystemAccessDeviceGetAllRequest([String] $sessionID, $deviceType)
{
$xmlSystemAccessDeviceGetAllRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="SystemAccessDeviceGetAllRequest" xmlns="">
					<searchCriteriaExactDeviceType>
					  <deviceType>$deviceType</deviceType>
					</searchCriteriaExactDeviceType>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlSystemAccessDeviceGetAllRequest = $xmlSystemAccessDeviceGetAllRequest
}

######################################################################################################################################
#### Function for GroupAccessDeviceCustomTagGetListRequest ##############################################################################################
Function Get-GroupAccessDeviceCustomTagGetListRequest([String] $sessionID, $serviceProviderId, $groupId , $deviceName)
{
$xmlGroupAccessDeviceCustomTagGetListRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="GroupAccessDeviceCustomTagGetListRequest" xmlns="">
                    <serviceProviderId>$serviceProviderId</serviceProviderId>
                    <groupId>$groupId</groupId>
                    <deviceName>$deviceName</deviceName>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlGroupAccessDeviceCustomTagGetListRequest = $xmlGroupAccessDeviceCustomTagGetListRequest
}


######################################################################################################################################
#### Function for GroupDeviceTypeCustomTagGetListRequest ##############################################################################################
Function Get-GroupDeviceTypeCustomTagGetListRequest([String] $sessionID, $serviceProviderId, $groupId , $deviceType)
{
$xmlGroupDeviceTypeCustomTagGetListRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="GroupDeviceTypeCustomTagGetListRequest" xmlns="">
                    <serviceProviderId>$serviceProviderId</serviceProviderId>
                    <groupId>$groupId</groupId>
                    <deviceType>$deviceType</deviceType>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlGroupDeviceTypeCustomTagGetListRequest = $xmlGroupDeviceTypeCustomTagGetListRequest
}

######################################################################################################################################
#### Function for GroupDeviceTypeCustomTagDeleteListRequest ##############################################################################################
Function Get-GroupDeviceTypeCustomTagDeleteListRequest([String] $sessionID, $serviceProviderId, $groupId , $deviceType, $tagName)
{
$xmlGroupDeviceTypeCustomTagDeleteListRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="GroupDeviceTypeCustomTagDeleteListRequest" xmlns="">
                    <serviceProviderId>$serviceProviderId</serviceProviderId>
                    <groupId>$groupId</groupId>
                    <deviceType>$deviceType</deviceType>
                    <tagName>$tagName</tagName>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlGroupDeviceTypeCustomTagDeleteListRequest = $xmlGroupDeviceTypeCustomTagDeleteListRequest
}

######################################################################################################################################
#### Function for GroupAccessDeviceCustomTagDeleteListRequest ##############################################################################################
Function Get-GroupAccessDeviceCustomTagDeleteListRequest([String] $sessionID, $serviceProviderId, $groupId , $deviceName, $tagName)
{
$xmlGroupAccessDeviceCustomTagDeleteListRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                  <command xsi:type="GroupAccessDeviceCustomTagDeleteListRequest" xmlns="">
                    <serviceProviderId>$serviceProviderId</serviceProviderId>
                    <groupId>$groupId </groupId>
                    <deviceName>$deviceName</deviceName>
                    <tagName>$tagName</tagName>
                  </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlGroupAccessDeviceCustomTagDeleteListRequest = $xmlGroupAccessDeviceCustomTagDeleteListRequest
}

######################################################################################################################################
#### Function for GroupCPEConfigRebuildDeviceConfigFileRequest ##############################################################################################
Function Get-GroupCPEConfigRebuildDeviceConfigFileRequest([String] $sessionID, $serviceProviderId, $groupId , $deviceName)
{
$xmlGroupCPEConfigRebuildDeviceConfigFileRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                  <command xsi:type="GroupCPEConfigRebuildDeviceConfigFileRequest" xmlns="">
                    <serviceProviderId>$serviceProviderId</serviceProviderId>
                    <groupId>$groupId</groupId>
                    <deviceName>$deviceName</deviceName>
                  </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlGroupCPEConfigRebuildDeviceConfigFileRequest = $xmlGroupCPEConfigRebuildDeviceConfigFileRequest
}

######################################################################################################################################
#### Function for GroupCPEConfigResetDeviceRequest ##############################################################################################
Function Get-GroupCPEConfigResetDeviceRequest([String] $sessionID, $serviceProviderId, $groupId , $deviceName)
{
$xmlGroupCPEConfigResetDeviceRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                  <command xsi:type="GroupCPEConfigResetDeviceRequest" xmlns="">
                    <serviceProviderId>$serviceProviderId</serviceProviderId>
                    <groupId>$groupId</groupId>
                    <deviceName>$deviceName</deviceName>
                  </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlGroupCPEConfigResetDeviceRequest = $xmlGroupCPEConfigResetDeviceRequest
}

######################################################################################################################################
#### Function for GroupAccessDeviceGetListRequest ##############################################################################################
Function Get-GroupAccessDeviceGetListRequest([String] $sessionID, $serviceProviderId, $groupId)
{
$xmlGroupAccessDeviceGetListRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                  <command xsi:type="GroupAccessDeviceGetListRequest" xmlns="">
                    <serviceProviderId>$serviceProviderId</serviceProviderId>
                    <groupId>$groupId</groupId>
                  </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlGroupAccessDeviceGetListRequest = $xmlGroupAccessDeviceGetListRequest
}

######################################################################################################################################
#### UserVoiceMessagingUserGetAdvancedVoiceManagementRequest14sp3 ##############################################################################################
Function Get-UserVoiceMessagingUserGetAdvancedVoiceManagementRequest14sp3([String] $sessionID, $userID)
{
$xmlUserVoiceMessagingUserGetAdvancedVoiceManagementRequest14sp3 = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                  <command xsi:type="UserVoiceMessagingUserGetAdvancedVoiceManagementRequest14sp3" xmlns="">
                    <userId>$userID</userId>
                  </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserVoiceMessagingUserGetAdvancedVoiceManagementRequest14sp3 = $xmlUserVoiceMessagingUserGetAdvancedVoiceManagementRequest14sp3
}

######################################################################################################################################
#### UserVoiceMessagingUserModifyAdvancedVoiceManagementRequest ##############################################################################################
Function Get-UserVoiceMessagingUserModifyAdvancedVoiceManagementRequest([String] $sessionID, $userID, $emailAddress)
{
$xmlUserVoiceMessagingUserModifyAdvancedVoiceManagementRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                  <command xsi:type="UserVoiceMessagingUserModifyAdvancedVoiceManagementRequest" xmlns="">
                        <userId>$userID</userId>
                        <mailServerSelection>Personal Mail Server</mailServerSelection>
                        <groupMailServerEmailAddress>$emailAddress</groupMailServerEmailAddress>
                        <groupMailServerUserId>$emailAddress</groupMailServerUserId>
                        <groupMailServerPassword>123456</groupMailServerPassword>
                        <useGroupDefaultMailServerFullMailboxLimit>true</useGroupDefaultMailServerFullMailboxLimit>
                        <personalMailServerNetAddress>voicemail.voice.encoretg.net</personalMailServerNetAddress>
                        <personalMailServerProtocol>POP3</personalMailServerProtocol>
                        <personalMailServerRealDeleteForImap>false</personalMailServerRealDeleteForImap>
                        <personalMailServerEmailAddress>$emailAddress</personalMailServerEmailAddress>
                        <personalMailServerUserId>$emailAddress</personalMailServerUserId>
                        <personalMailServerPassword>123456</personalMailServerPassword>
                  </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserVoiceMessagingUserModifyAdvancedVoiceManagementRequest = $xmlUserVoiceMessagingUserModifyAdvancedVoiceManagementRequest
}

######################################################################################################################################
#### Function for UserGetListInGroupRequest ##############################################################################
Function Get-UserGetListInGroupRequest([String] $sessionID, $serviceProviderId, $groupId)
{
$xmlUserGetListInGroupRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserGetListInGroupRequest" xmlns="">
                    <serviceProviderId>$serviceProviderId</serviceProviderId>
                    <GroupId>$groupId</GroupId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserGetListInGroupRequest = $xmlUserGetListInGroupRequest
}

######################################################################################################################################
#### Function for GroupEndpointGetListRequest ##############################################################################
Function Get-GroupEndpointGetListRequest([String] $sessionID, $serviceProviderId, $groupId)
{
$xmlGroupEndpointGetListRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="GroupEndpointGetListRequest" xmlns="">
                    <serviceProviderId>$serviceProviderId</serviceProviderId>
                    <groupId>$groupId</groupId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlGroupEndpointGetListRequest = $xmlGroupEndpointGetListRequest
}
######################################################################################################################################
#### Function for UserGetRegistrationListRequest ##############################################################################
Function Get-UserGetRegistrationListRequest([String] $sessionID, $userID)
{
$xmlUserGetRegistrationListRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserGetRegistrationListRequest" xmlns="">
                    <userId>$userID</userId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserGetRegistrationListRequest = $xmlUserGetRegistrationListRequest
}
######################################################################################################################################
#### Function for SystemGetRegistrationContactListRequest ##############################################################################
Function Get-SystemGetRegistrationContactListRequest([String] $sessionID, $searchValue, $mode)
{
$xmlSystemGetRegistrationContactListRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="SystemGetRegistrationContactListRequest" xmlns="">
                        <searchCriteriaRegistrationURI>
                          <mode>$mode</mode>
                          <value>$searchValue</value>
                          <isCaseInsensitive>true</isCaseInsensitive>
                        </searchCriteriaRegistrationURI>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlSystemGetRegistrationContactListRequest = $xmlSystemGetRegistrationContactListRequest
}
######################################################################################################################################
#### Function for ServiceProviderServicePackAddRequest ##############################################################################
Function Get-ServiceProviderServicePackAddRequest([String] $sessionID, $serviceProviderId, $servicePackName, $serviceName)
{
$xmlServiceProviderServicePackAddRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                  <command xsi:type="ServiceProviderServicePackAddRequest" xmlns="">
                    <serviceProviderId>$serviceProviderId</serviceProviderId>
                    <servicePackName>$servicePackName</servicePackName>
                    <isAvailableForUse>true</isAvailableForUse>
                    <servicePackQuantity>
                      <unlimited>true</unlimited>
                    </servicePackQuantity>
                    <serviceName>$serviceName</serviceName>
                  </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlServiceProviderServicePackAddRequest = $xmlServiceProviderServicePackAddRequest
}

######################################################################################################################################
#### Function for ServiceProviderGetListRequestfalse ##############################################################################
Function Get-ServiceProviderGetListRequestfalse([String] $sessionID)
{
$xmlServiceProviderGetListRequestfalse = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="ServiceProviderGetListRequest" xmlns="">
                    <isEnterprise>false</isEnterprise>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlServiceProviderGetListRequestfalse = $xmlServiceProviderGetListRequestfalse
}
######################################################################################################################################
#### Function for ServiceProviderGetListRequest ##############################################################################
Function Get-ServiceProviderGetListRequest([String] $sessionID)
{
$xmlServiceProviderGetListRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="ServiceProviderGetListRequest" xmlns="">
                    <isEnterprise>true</isEnterprise>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlServiceProviderGetListRequest = $xmlServiceProviderGetListRequest
}
######################################################################################################################################
#### Function for ServiceProviderDialPlanPolicyAddAccessCodeRequest ##################################################################
Function Get-ServiceProviderDialPlanPolicyAddAccessCodeRequest([String] $sessionID, $serviceProviderId, $outsideCode)
{
$xmlServiceProviderDialPlanPolicyAddAccessCodeRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="ServiceProviderDialPlanPolicyAddAccessCodeRequest" xmlns="">
                       <serviceProviderId>$serviceProviderId</serviceProviderId>
                        <accessCode>$outsideCode</accessCode>
                        <includeCodeForNetworkTranslationsAndRouting>false</includeCodeForNetworkTranslationsAndRouting>
                        <includeCodeForScreeningServices>false</includeCodeForScreeningServices>
                        <enableSecondaryDialTone>true</enableSecondaryDialTone>
                        <description>Outside Access</description>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlServiceProviderDialPlanPolicyAddAccessCodeRequest = $xmlServiceProviderDialPlanPolicyAddAccessCodeRequest
}
######################################################################################################################################
#### Function for ServiceProviderDialPlanPolicyModifyRequest ##################################################################
Function Get-ServiceProviderDialPlanPolicyModifyRequest([String] $sessionID, $serviceProviderId, $requireAccessCode, $publicDM, $privateDM)
{
$xmlServiceProviderDialPlanPolicyModifyRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="ServiceProviderDialPlanPolicyModifyRequest" xmlns="">
                        <serviceProviderId>$serviceProviderId</serviceProviderId>
                        <requiresAccessCodeForPublicCalls>$requireAccessCode</requiresAccessCodeForPublicCalls>
                        <allowE164PublicCalls>true</allowE164PublicCalls>
                        <preferE164NumberFormatForCallbackServices>false</preferE164NumberFormatForCallbackServices>
                        <publicDigitMap>$publicDM</publicDigitMap>
                        <privateDigitMap>$privateDM</privateDigitMap>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlServiceProviderDialPlanPolicyModifyRequest = $xmlServiceProviderDialPlanPolicyModifyRequest
}
######################################################################################################################################
#### Function for ServiceProviderCallProcessingModifyPolicyRequest15Defaults ##########################################################
Function Get-ServiceProviderCallProcessingModifyPolicyRequest15Defaults([String] $sessionID, $serviceProviderId)
{
$xmlServiceProviderCallProcessingModifyPolicyRequest15Defaults = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="ServiceProviderCallProcessingModifyPolicyRequest15" xmlns="">
                    <serviceProviderId>$serviceProviderId</serviceProviderId>
                    <useServiceProviderDCLIDSetting>false</useServiceProviderDCLIDSetting>
                    <useMaxSimultaneousCalls>true</useMaxSimultaneousCalls>
                    <maxSimultaneousCalls>10</maxSimultaneousCalls>
                    <useMaxSimultaneousVideoCalls>true</useMaxSimultaneousVideoCalls>
                    <maxSimultaneousVideoCalls>1</maxSimultaneousVideoCalls>
                    <useMaxCallTimeForAnsweredCalls>true</useMaxCallTimeForAnsweredCalls>
                    <maxCallTimeForAnsweredCallsMinutes>480</maxCallTimeForAnsweredCallsMinutes>
                    <useMaxCallTimeForUnansweredCalls>false</useMaxCallTimeForUnansweredCalls>
                    <maxCallTimeForUnansweredCallsMinutes>2</maxCallTimeForUnansweredCallsMinutes>
                    <mediaPolicySelection>No Restrictions</mediaPolicySelection>
                    <supportedMediaSetName xsi:nil="true"/>
                    <networkUsageSelection>Do Not Force Enterprise and Group Calls</networkUsageSelection>
                    <enforceGroupCallingLineIdentityRestriction>false</enforceGroupCallingLineIdentityRestriction>
                    <allowEnterpriseGroupCallTypingForPrivateDialingPlan>false</allowEnterpriseGroupCallTypingForPrivateDialingPlan>
                    <allowEnterpriseGroupCallTypingForPublicDialingPlan>false</allowEnterpriseGroupCallTypingForPublicDialingPlan>
                    <overrideCLIDRestrictionForPrivateCallCategory>false</overrideCLIDRestrictionForPrivateCallCategory>
                    <useEnterpriseCLIDForPrivateCallCategory>false</useEnterpriseCLIDForPrivateCallCategory>
                    <enableEnterpriseExtensionDialing>true</enableEnterpriseExtensionDialing>
                    <enforceEnterpriseCallingLineIdentityRestriction>false</enforceEnterpriseCallingLineIdentityRestriction>
                    <useSettingLevel>System</useSettingLevel>
                    <conferenceURI xsi:nil="true"/>
                    <useMaxConcurrentRedirectedCalls>false</useMaxConcurrentRedirectedCalls>
                    <maxConcurrentRedirectedCalls>5</maxConcurrentRedirectedCalls>
                    <useMaxFindMeFollowMeDepth>true</useMaxFindMeFollowMeDepth>
                    <maxFindMeFollowMeDepth>3</maxFindMeFollowMeDepth>
                    <maxRedirectionDepth>5</maxRedirectionDepth>
                    <useMaxConcurrentFindMeFollowMeInvocations>true</useMaxConcurrentFindMeFollowMeInvocations>
                    <maxConcurrentFindMeFollowMeInvocations>3</maxConcurrentFindMeFollowMeInvocations>
                    <clidPolicy>Use DN</clidPolicy>
                    <emergencyClidPolicy>Use DN</emergencyClidPolicy>
                    <allowAlternateNumbersForRedirectingIdentity>true</allowAlternateNumbersForRedirectingIdentity>
                    <enableDialableCallerID>false</enableDialableCallerID>
                    <blockCallingNameForExternalCalls>false</blockCallingNameForExternalCalls>
                    <allowConfigurableCLIDForRedirectingIdentity>true</allowConfigurableCLIDForRedirectingIdentity>
                    <enterpriseCallsCLIDPolicy>Use Location Code plus Extension</enterpriseCallsCLIDPolicy>
                    <groupCallsCLIDPolicy>Use Extension</groupCallsCLIDPolicy>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlServiceProviderCallProcessingModifyPolicyRequest15Defaults = $xmlServiceProviderCallProcessingModifyPolicyRequest15Defaults
}
######################################################################################################################################
#### Function for ServiceProviderRoutingProfileModifyRequest ##################################################################
Function Get-ServiceProviderRoutingProfileModifyRequest([String] $sessionID, $serviceProviderId, $routingProf)
{
$xmlServiceProviderRoutingProfileModifyRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="ServiceProviderRoutingProfileModifyRequest" xmlns="">
                    <serviceProviderId>$serviceProviderId</serviceProviderId>
                    <routingProfile>$routingProf</routingProfile>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlServiceProviderRoutingProfileModifyRequest = $xmlServiceProviderRoutingProfileModifyRequest
}
######################################################################################################################################
#### Function for GroupDialPlanPolicyModifyRequest ##################################################################
Function Get-GroupDialPlanPolicyModifyRequest([String] $sessionID, $serviceProviderId, $groupId)
{
$xmlGroupDialPlanPolicyModifyRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                  <command xsi:type="GroupDialPlanPolicyModifyRequest" xmlns="">
                    <serviceProviderId>$serviceProviderId</serviceProviderId>
                    <groupId>$groupId</groupId>
                    <useSetting>Service Provider</useSetting>
                    <requiresAccessCodeForPublicCalls>false</requiresAccessCodeForPublicCalls>
                    <allowE164PublicCalls>false</allowE164PublicCalls>
                    <preferE164NumberFormatForCallbackServices>false</preferE164NumberFormatForCallbackServices>
                    <publicDigitMap xsi:nil="true"/>
                    <privateDigitMap xsi:nil="true"/>
                  </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlGroupDialPlanPolicyModifyRequest = $xmlGroupDialPlanPolicyModifyRequest
}
######################################################################################################################################
#### Function for GroupCallProcessingModifyPolicyRequest15sp2Defaults ##################################################################
Function Get-GroupCallProcessingModifyPolicyRequest15sp2Defaults([String] $sessionID, $serviceProviderId, $groupId)
{
$xmlGroupCallProcessingModifyPolicyRequest15sp2Defaults = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                    <command xsi:type="GroupCallProcessingModifyPolicyRequest15sp2" xmlns="">
                    <serviceProviderId>$serviceProviderId</serviceProviderId>
                    <groupId>$groupId</groupId>
                    <useGroupCLIDSetting>true</useGroupCLIDSetting>
                    <useGroupMediaSetting>true</useGroupMediaSetting>
                    <useGroupCallLimitsSetting>true</useGroupCallLimitsSetting>
                    <useGroupTranslationRoutingSetting>false</useGroupTranslationRoutingSetting>
                    <useGroupDCLIDSetting>false</useGroupDCLIDSetting>
                    <useMaxSimultaneousCalls>true</useMaxSimultaneousCalls>
                    <maxSimultaneousCalls>24</maxSimultaneousCalls>
                    <useMaxSimultaneousVideoCalls>true</useMaxSimultaneousVideoCalls>
                    <maxSimultaneousVideoCalls>1</maxSimultaneousVideoCalls>
                    <useMaxCallTimeForAnsweredCalls>true</useMaxCallTimeForAnsweredCalls>
                    <maxCallTimeForAnsweredCallsMinutes>600</maxCallTimeForAnsweredCallsMinutes>
                    <useMaxCallTimeForUnansweredCalls>false</useMaxCallTimeForUnansweredCalls>
                    <maxCallTimeForUnansweredCallsMinutes>2</maxCallTimeForUnansweredCallsMinutes>
                    <mediaPolicySelection>No Restrictions</mediaPolicySelection>
                    <supportedMediaSetName xsi:nil="true"/>
                    <networkUsageSelection>Force All Except Extension and Location Calls</networkUsageSelection>
                    <enforceGroupCallingLineIdentityRestriction>false</enforceGroupCallingLineIdentityRestriction>
                    <allowEnterpriseGroupCallTypingForPrivateDialingPlan>false</allowEnterpriseGroupCallTypingForPrivateDialingPlan>
                    <allowEnterpriseGroupCallTypingForPublicDialingPlan>false</allowEnterpriseGroupCallTypingForPublicDialingPlan>
                    <overrideCLIDRestrictionForPrivateCallCategory>false</overrideCLIDRestrictionForPrivateCallCategory>
                    <useEnterpriseCLIDForPrivateCallCategory>false</useEnterpriseCLIDForPrivateCallCategory>
                    <enableEnterpriseExtensionDialing>true</enableEnterpriseExtensionDialing>
                    <useMaxConcurrentRedirectedCalls>false</useMaxConcurrentRedirectedCalls>
                    <maxConcurrentRedirectedCalls>5</maxConcurrentRedirectedCalls>
                    <useMaxFindMeFollowMeDepth>true</useMaxFindMeFollowMeDepth>
                    <maxFindMeFollowMeDepth>5</maxFindMeFollowMeDepth>
                    <maxRedirectionDepth>5</maxRedirectionDepth>
                    <useMaxConcurrentFindMeFollowMeInvocations>true</useMaxConcurrentFindMeFollowMeInvocations>
                    <maxConcurrentFindMeFollowMeInvocations>3</maxConcurrentFindMeFollowMeInvocations>
                    <clidPolicy>Use Group CLID</clidPolicy>
                    <emergencyClidPolicy>Use Group CLID</emergencyClidPolicy>
                    <allowAlternateNumbersForRedirectingIdentity>true</allowAlternateNumbersForRedirectingIdentity>
                    <useGroupName>true</useGroupName>
                    <blockCallingNameForExternalCalls>false</blockCallingNameForExternalCalls>
                    <enableDialableCallerID>false</enableDialableCallerID>
                    <allowConfigurableCLIDForRedirectingIdentity>true</allowConfigurableCLIDForRedirectingIdentity>
                    <allowDepartmentCLIDNameOverride>false</allowDepartmentCLIDNameOverride>
                    <enterpriseCallsCLIDPolicy>Use Extension</enterpriseCallsCLIDPolicy>
                    <groupCallsCLIDPolicy>Use Extension</groupCallsCLIDPolicy>
                    </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlGroupCallProcessingModifyPolicyRequest15sp2Defaults = $xmlGroupCallProcessingModifyPolicyRequest15sp2Defaults
}
######################################################################################################################################
#### Function for GroupAccessDeviceAddRequest14 ##################################################################
Function Get-GroupAccessDeviceAddRequest14([String] $sessionID, $serviceProviderId, $groupId, $deviceName, $deviceType)
{
$xmlGroupAccessDeviceAddRequest14 = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                  <command xsi:type="GroupAccessDeviceAddRequest14" xmlns="">
                    <serviceProviderId>$serviceProviderId</serviceProviderId>
                    <groupId>$groupId</groupId>
                    <deviceName>$deviceName</deviceName>
                    <deviceType>$deviceType</deviceType>
                    <protocol>SIP 2.0</protocol>
                    <transportProtocol>Unspecified</transportProtocol>
                  </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlGroupAccessDeviceAddRequest14 = $xmlGroupAccessDeviceAddRequest14
}
######################################################################################################################################
#### Function for GroupAccessDeviceDeleteRequest ##################################################################
Function Get-GroupAccessDeviceDeleteRequest([String] $sessionID, $serviceProviderId, $groupId, $deviceName)
{
$xmlGroupAccessDeviceDeleteRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                  <command xsi:type="GroupAccessDeviceDeleteRequest" xmlns="">
                    <serviceProviderId>$serviceProviderId</serviceProviderId>
                    <groupId>$groupId</groupId>
                    <deviceName>$deviceName</deviceName>
                  </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlGroupAccessDeviceDeleteRequest = $xmlGroupAccessDeviceDeleteRequest
}
######################################################################################################################################
#### Function for GroupDeviceTypeCustomTagAddRequest ##################################################################
Function Get-GroupDeviceTypeCustomTagAddRequest([String] $sessionID, $serviceProviderId, $groupId, $deviceType, $tagName, $tagValue)
{
$xmlGroupDeviceTypeCustomTagAddRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                  <command xsi:type="GroupDeviceTypeCustomTagAddRequest" xmlns="">
                    <serviceProviderId>$serviceProviderId</serviceProviderId>
                    <groupId>$groupId</groupId>
                    <deviceType>$deviceType</deviceType>
                    <tagName>%$tagName%</tagName>
                    <tagValue>$tagValue</tagValue>
                  </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlGroupDeviceTypeCustomTagAddRequest = $xmlGroupDeviceTypeCustomTagAddRequest
}
######################################################################################################################################
#### Function for UserCallForwardingAlwaysGetRequest ##############################################################################
Function Get-UserCallForwardingAlwaysGetRequest([String] $sessionID, $userID)
{
$xmlUserCallForwardingAlwaysGetRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserCallForwardingAlwaysGetRequest" xmlns="">
                    <userId>$userID</userId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserCallForwardingAlwaysGetRequest = $xmlUserCallForwardingAlwaysGetRequest
}
######################################################################################################################################
#### Function for UserCallForwardingBusyGetRequest ##############################################################################
Function Get-UserCallForwardingBusyGetRequest([String] $sessionID, $userID)
{
$xmlUserCallForwardingBusyGetRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserCallForwardingBusyGetRequest" xmlns="">
                    <userId>$userID</userId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserCallForwardingBusyGetRequest = $xmlUserCallForwardingBusyGetRequest
}
######################################################################################################################################
#### Function for UserCallForwardingNoAnswerGetRequest13mp16 ##############################################################################
Function Get-UserCallForwardingNoAnswerGetRequest13mp16([String] $sessionID, $userID)
{
$xmlUserCallForwardingNoAnswerGetRequest13mp16 = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserCallForwardingNoAnswerGetRequest13mp16" xmlns="">
                    <userId>$userID</userId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserCallForwardingNoAnswerGetRequest13mp16 = $xmlUserCallForwardingNoAnswerGetRequest13mp16
}
######################################################################################################################################
#### Function for UserCallForwardingNotReachableGetRequest ##############################################################################
Function Get-UserCallForwardingNotReachableGetRequest([String] $sessionID, $userID)
{
$xmlUserCallForwardingNotReachableGetRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserCallForwardingNotReachableGetRequest" xmlns="">
                    <userId>$userID</userId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserCallForwardingNotReachableGetRequest = $xmlUserCallForwardingNotReachableGetRequest
}
######################################################################################################################################
#### Function for UserDoNotDisturbGetRequest ##############################################################################
Function Get-UserDoNotDisturbGetRequest([String] $sessionID, $userID)
{
$xmlUserDoNotDisturbGetRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserDoNotDisturbGetRequest" xmlns="">
                    <userId>$userID</userId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserDoNotDisturbGetRequest = $xmlUserDoNotDisturbGetRequest
}
######################################################################################################################################
#### Function for UserAlternateNumbersGetRequest21 ##############################################################################
Function Get-UserAlternateNumbersGetRequest21([String] $sessionID, $userID)
{
$xmlUserAlternateNumbersGetRequest21 = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserAlternateNumbersGetRequest21" xmlns="">
                    <userId>$userID</userId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserAlternateNumbersGetRequest21 = $xmlUserAlternateNumbersGetRequest21
}
######################################################################################################################################
#### Function for UserCallForwardingSelectiveGetRequest16 ##############################################################################
Function Get-UserCallForwardingSelectiveGetRequest16([String] $sessionID, $userID)
{
$xmlUserCallForwardingSelectiveGetRequest16 = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserCallForwardingSelectiveGetRequest16" xmlns="">
                    <userId>$userID</userId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserCallForwardingSelectiveGetRequest16 = $xmlUserCallForwardingSelectiveGetRequest16
}
######################################################################################################################################
#### Function for UserPriorityAlertGetCriteriaListRequest ##############################################################################
Function Get-UserPriorityAlertGetCriteriaListRequest([String] $sessionID, $userID)
{
$xmlUserPriorityAlertGetCriteriaListRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserPriorityAlertGetCriteriaListRequest" xmlns="">
                    <userId>$userID</userId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserPriorityAlertGetCriteriaListRequest = $xmlUserPriorityAlertGetCriteriaListRequest
}
######################################################################################################################################
#### Function for UserSelectiveCallAcceptanceGetCriteriaListRequest ##############################################################################
Function Get-UserSelectiveCallAcceptanceGetCriteriaListRequest([String] $sessionID, $userID)
{
$xmlUserSelectiveCallAcceptanceGetCriteriaListRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserSelectiveCallAcceptanceGetCriteriaListRequest" xmlns="">
                    <userId>$userID</userId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserSelectiveCallAcceptanceGetCriteriaListRequest = $xmlUserSelectiveCallAcceptanceGetCriteriaListRequest
}
######################################################################################################################################
#### Function for UserSelectiveCallRejectionGetCriteriaListRequest ##############################################################################
Function Get-UserSelectiveCallRejectionGetCriteriaListRequest([String] $sessionID, $userID)
{
$xmlUserSelectiveCallRejectionGetCriteriaListRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserSelectiveCallRejectionGetCriteriaListRequest" xmlns="">
                    <userId>$userID</userId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserSelectiveCallRejectionGetCriteriaListRequest = $xmlUserSelectiveCallRejectionGetCriteriaListRequest
}
######################################################################################################################################
#### Function for UserSequentialRingGetRequest14sp4 ##############################################################################
Function Get-UserSequentialRingGetRequest14sp4([String] $sessionID, $userID)
{
$xmlUserSequentialRingGetRequest14sp4 = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserSequentialRingGetRequest14sp4" xmlns="">
                    <userId>$userID</userId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserSequentialRingGetRequest14sp4 = $xmlUserSequentialRingGetRequest14sp4
}
######################################################################################################################################
#### Function for UserSimultaneousRingPersonalGetRequest17 ##############################################################################
Function Get-UserSimultaneousRingPersonalGetRequest17([String] $sessionID, $userID)
{
$xmlUserSimultaneousRingPersonalGetRequest17 = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserSimultaneousRingPersonalGetRequest17" xmlns="">
                    <userId>$userID</userId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserSimultaneousRingPersonalGetRequest17 = $xmlUserSimultaneousRingPersonalGetRequest17
}
######################################################################################################################################
#### Function for UserAutomaticCallbackGetRequest ##############################################################################
Function Get-UserAutomaticCallbackGetRequest([String] $sessionID, $userID)
{
$xmlUserAutomaticCallbackGetRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserAutomaticCallbackGetRequest" xmlns="">
                    <userId>$userID</userId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserAutomaticCallbackGetRequest = $xmlUserAutomaticCallbackGetRequest
}
######################################################################################################################################
#### Function for UserCallWaitingGetRequest17sp4 ##############################################################################
Function Get-UserCallWaitingGetRequest17sp4([String] $sessionID, $userID)
{
$xmlUserCallWaitingGetRequest17sp4 = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserCallWaitingGetRequest17sp4" xmlns="">
                    <userId>$userID</userId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserCallWaitingGetRequest17sp4 = $xmlUserCallWaitingGetRequest17sp4
}
######################################################################################################################################
#### Function for UserBroadWorksAnywhereGetRequest16sp2 ##############################################################################
Function Get-UserBroadWorksAnywhereGetRequest16sp2([String] $sessionID, $userID)
{
$xmlUserBroadWorksAnywhereGetRequest16sp2 = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserBroadWorksAnywhereGetRequest16sp2" xmlns="">
                    <userId>$userID</userId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserBroadWorksAnywhereGetRequest16sp2 = $xmlUserBroadWorksAnywhereGetRequest16sp2
}
######################################################################################################################################
#### Function for UserSharedCallAppearanceGetRequest16sp2 ##############################################################################
Function Get-UserSharedCallAppearanceGetRequest16sp2([String] $sessionID, $userID)
{
$xmlUserSharedCallAppearanceGetRequest16sp2 = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserSharedCallAppearanceGetRequest16sp2" xmlns="">
                    <userId>$userID</userId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserSharedCallAppearanceGetRequest16sp2 = $xmlUserSharedCallAppearanceGetRequest16sp2
}
######################################################################################################################################
#### Function for UserOutgoingCallingPlanOriginatingGetRequest ##############################################################################
Function Get-UserOutgoingCallingPlanOriginatingGetRequest([String] $sessionID, $userID)
{
$xmlUserOutgoingCallingPlanOriginatingGetRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserOutgoingCallingPlanOriginatingGetRequest" xmlns="">
                    <userId>$userID</userId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserOutgoingCallingPlanOriginatingGetRequest = $xmlUserOutgoingCallingPlanOriginatingGetRequest
}
######################################################################################################################################
#### Function for UserBusyLampFieldGetRequest16sp2 ##############################################################################
Function Get-UserBusyLampFieldGetRequest16sp2([String] $sessionID, $userID)
{
$xmlUserBusyLampFieldGetRequest16sp2 = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserBusyLampFieldGetRequest16sp2" xmlns="">
                    <userId>$userID</userId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserBusyLampFieldGetRequest16sp2 = $xmlUserBusyLampFieldGetRequest16sp2
}
######################################################################################################################################
#### Function for UserVoiceMessagingUserGetVoiceManagementRequest17 ##############################################################################
Function Get-UserVoiceMessagingUserGetVoiceManagementRequest17([String] $sessionID, $userID)
{
$xmlUserVoiceMessagingUserGetVoiceManagementRequest17 = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserVoiceMessagingUserGetVoiceManagementRequest17" xmlns="">
                    <userId>$userID</userId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserVoiceMessagingUserGetVoiceManagementRequest17 = $xmlUserVoiceMessagingUserGetVoiceManagementRequest17
}
######################################################################################################################################
#### Function for UserServiceScriptsUserGetRequest ##############################################################################
Function Get-UserServiceScriptsUserGetRequest([String] $sessionID, $userID)
{
$xmlUserServiceScriptsUserGetRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserServiceScriptsUserGetRequest" xmlns="">
                    <userId>$userID</userId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserServiceScriptsUserGetRequest = $xmlUserServiceScriptsUserGetRequest
}
######################################################################################################################################
#### Function for UserCallProcessingGetPolicyRequest19sp1 ##############################################################################
Function Get-UserCallProcessingGetPolicyRequest19sp1([String] $sessionID, $userID)
{
$xmlUserCallProcessingGetPolicyRequest19sp1 = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="UserCallProcessingGetPolicyRequest19sp1" xmlns="">
                    <userId>$userID</userId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlUserCallProcessingGetPolicyRequest19sp1 = $xmlUserCallProcessingGetPolicyRequest19sp1
}
######################################################################################################################################
#### Function for GroupCallPickupGetInstanceListRequest ##############################################################################
Function Get-GroupCallPickupGetInstanceListRequest([String] $sessionID, $serviceProviderId, $groupId)
{
$xmlGroupCallPickupGetInstanceListRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:broadsoft:webservice">
 1  <soapenv:Header/>
   <soapenv:Body>
      <urn:processOCIMessage>
       <arg0 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
            <![CDATA[           
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <sessionId xmlns="">$sessionID</sessionId>
                <command xsi:type="GroupCallPickupGetInstanceListRequest" xmlns="">
                    <serviceProviderId>$serviceProviderId</serviceProviderId>
                    <groupId>$groupId</groupId>
                </command>
                </BroadsoftDocument>          
            ]]>
        </arg0>
      </urn:processOCIMessage>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlGroupCallPickupGetInstanceListRequest = $xmlGroupCallPickupGetInstanceListRequest
}







######################################################################################################################################
#### Function for AddResourceGrpGroup-Telchemy ##############################################################################################
Function Get-AddRsrcGrpGroup([String] $adminID, $adminPass, $transactionID, $grpID, $parentID)
{
$xmlAddRsrcGrpGroup = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:telchemyRsrcGroupConfig">
   <soapenv:Header/>
   <soapenv:Body>
      <urn:addResourceGroupParameters>
         <credentials>
            <username>$adminID</username>
            <password>$adminPass</password>
         </credentials>
         <transactionID>$transactionID</transactionID>
         <resourceGroupConfig>
            <RGname>$grpID</RGname>
			<RGdesc>$grpID</RGdesc>
            <RGtype>Customers</RGtype>
            <RGsubtype>Office</RGsubtype>
            <RGparentID>$parentID</RGparentID>
            <RGserviceProfMappingList>
               <mapping>
                  <serviceProfileName>VOIP SP</serviceProfileName>
                  <mappingRelation>
                     <siteID>$grpID</siteID>
                  </mappingRelation>
               </mapping>
            </RGserviceProfMappingList>
         </resourceGroupConfig>
      </urn:addResourceGroupParameters>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlAddRsrcGrpGroup = $xmlAddRsrcGrpGroup
}
######################################################################################################################################
#### Function for AddResourceGrpEnterprise-Telchemy ##############################################################################################
Function Get-AddRsrcGrpEnterprise([String] $adminID, $adminPass, $transactionID, $entID, $parentID)
{
$xmlAddRsrcGrpEnterprise = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:telchemyRsrcGroupConfig">
   <soapenv:Header/>
   <soapenv:Body>
      <urn:addResourceGroupParameters>
         <credentials>
            <username>$adminID</username>
            <password>$adminPass</password>
         </credentials>
         <transactionID>$transactionID</transactionID>
         <resourceGroupConfig>
            <RGname>$entID</RGname>
			<RGdesc>$entID</RGdesc>
            <RGtype>Customers</RGtype>
            <RGsubtype>Office</RGsubtype>
         </resourceGroupConfig>
      </urn:addResourceGroupParameters>
   </soapenv:Body>
</soapenv:Envelope>
"@

$Global:xmlAddRsrcGrpEnterprise = $xmlAddRsrcGrpEnterprise
}
#######################################################################################################################################
#### Function for ListRsrcGrp-Telchemy ################################################################################################
Function Get-ListRsrcGrp([String] $adminID, $adminPass, $transactionID, $entID, $maxNumber)
{
$xmlListRsrcGrp = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:telchemyRsrcGroupConfig">
   <soapenv:Header/>
   <soapenv:Body>
      <urn:listResourceGroupParameters>
         <credentials>
            <username>$adminID</username>
            <password>$adminPass</password>
         </credentials>
         <transactionID>$transactionID</transactionID>
         <filter>
            <nameSubstring>$entID</nameSubstring>
         </filter>
         <maxNumber>$maxNumber</maxNumber>
      </urn:listResourceGroupParameters>
   </soapenv:Body></soapenv:Envelope>
"@

$Global:xmlListRsrcGrp = $xmlListRsrcGrp
}

