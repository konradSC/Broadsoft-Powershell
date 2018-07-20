# This script will remove custom device tags from the group level. Input it done by a CSV file.
# CSV format is Enterprise,	Group
#

##Admin and Session Variables
$global:localIpAddress=((ipconfig | findstr [0-9].\.)[0]).Split()[-1]
$global:uri = "http://myservice.com/webservice/services/ProvisioningService?wsdl"
$global:adminuser = 'bobby'
$global:adminpassword = "P@ssword1"
$inputFile = "C:\temp\Logs\RemoveGroupAppVersionTags.csv"
$deviceType = "PolyTemplate"
$tagName = "%APP_VERSION%"

$groups = Import-Csv $inputFile


foreach ($groupID in $groups) {
######################Authenticate, Create XML OCI Reqest and Send Command for SystemAccessDeviceGetAllRequest
Get-Login $global:uri $global:adminuser $global:adminpassword $global:localIpAddress
Get-GroupDeviceTypeCustomTagDeleteListRequest $global:sessionID $groupID.Enterprise $groupID.Group $deviceType $tagName
[xml] $webrequest = Invoke-WebRequest -Uri $global:uri -Headers @{SOAPAction=''} -Method POST -Body $Global:xmlGroupDeviceTypeCustomTagDeleteListRequest -ContentType "text/xml; charset=utf-8" -WebSession $Global:websession
}