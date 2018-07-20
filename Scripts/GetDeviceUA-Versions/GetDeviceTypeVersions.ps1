
##Admin and Session Variables
#$enterpriseID = "CO-COLORADO-VITURAL-ACADEMY"
$global:localIpAddress=((ipconfig | findstr [0-9].\.)[0]).Split()[-1]
$global:uri = "http://myservice.com/webservice/services/ProvisioningService?wsdl"
$global:adminuser = 'bobby'
$global:adminpassword = "P@ssword1"
$Logfile = "C:\Temp\Logs\ScriptLogs_$(get-date -format `"yyyyMMdd_hhmmsstt`").txt"
$manifest = "C:\Temp\Logs\DeviceDetailReport$(get-date -format `"yyyyMMdd`").csv"
$Global:userInfo = @()
$Global:userList = @()
$deviceType = "PolyTemplate"


######################Authenticate, Create XML OCI Reqest and Send Command for SystemAccessDeviceGetAllRequest
Get-Login $global:uri $global:adminuser $global:adminpassword $global:localIpAddress
Get-SystemAccessDeviceGetAllRequest $global:sessionID $deviceType
#get the Users
[xml] $webrequest = Invoke-WebRequest -Uri $global:uri -Headers @{SOAPAction=''} -Method POST -Body $Global:xmlSystemAccessDeviceGetAllRequest -ContentType "text/xml; charset=utf-8" -WebSession $Global:websession


# Put the Devices into an array
    [xml] $devicelistdoc = $webrequest.Envelope.Body.processOCIMessageResponse.processOCIMessageReturn 
    $Global:deviceList = $devicelistdoc.BroadsoftDocument.command.accessDeviceTable | % {
    foreach ($s in $_.row) {
        $g = New-Object Object
            Add-Member -InputObject $g -MemberType NoteProperty -Name Enterprise -Value $s.col[0]
            Add-Member -InputObject $g -MemberType NoteProperty -Name Group -Value $s.col[2]
            Add-Member -InputObject $g -MemberType NoteProperty -Name DeviceName -Value $s.col[3]
            Add-Member -InputObject $g -MemberType NoteProperty -Name MAC -Value $s.col[6]
        $g
    }
    }


    foreach ($devicearray in $Global:deviceList) {
        # Get the Device Info
        Get-Login $global:uri $global:adminuser $global:adminpassword $global:localIpAddress
        Get-GroupAccessDeviceGetRequest18sp1 $global:sessionID $devicearray.Enterprise $devicearray.Group $devicearray.DeviceName
        [xml] $webrequest2 = Invoke-WebRequest -Uri $global:uri -Headers @{SOAPAction=''} -Method POST -Body $Global:xmlGroupAccessDeviceGetRequest18sp1 -ContentType "text/xml; charset=utf-8" -WebSession $Global:websession
        [xml] $devicedoc = $webrequest2.Envelope.Body.processOCIMessageResponse.processOCIMessageReturn

        # Add MAC and Device Type Information to array
        $Global:deviceDetailList = $devicedoc.BroadsoftDocument.command | % {
        foreach ($s in $_) {
                $f = New-Object Object
                Add-Member -InputObject $f -MemberType NoteProperty -Name Enterprise -Value $devicearray.Enterprise
                Add-Member -InputObject $f -MemberType NoteProperty -Name Group -Value $devicearray.Group
                Add-Member -InputObject $f -MemberType NoteProperty -Name DeviceName -Value $devicearray.DeviceName
                Add-Member -InputObject $f -MemberType NoteProperty -Name DeviceType -Value $s.deviceType
                Add-Member -InputObject $f -MemberType NoteProperty -Name MAC -Value $s.macAddress
                Add-Member -InputObject $f -MemberType NoteProperty -Name Version -Value $s.version
                $f
        }
        }
        $Global:deviceDetailList | Export-Csv -Path $manifest  -Append
        }

