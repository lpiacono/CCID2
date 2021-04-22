<# 

Script: CCID Discovery
Version: 0.2
Author: leandro.iacono@crowdstrike.com

**************DISCLAIMER**************

This sample scripts is not supported under any CrowdStrike standard support program or service. 

This sample script is provided AS IS without warranty of any kind. 

CrowdStrike further disclaims all implied warranties including, without limitation, any implied warranties of merchantability
or of fitness for a particular purpose. The entire risk arising out of the use or performance of the sample scripts and 
documentation remains with you. In no event shall CrowdStrike, its authors, or anyone else involved in the creation, production, 
or delivery of the script/s be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, 
business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the 
sample scripts or documentation, even if CrowdStrike has been advised of the possibility of such damages.

*********END OF DISCLAIMER************

#>


#Logic to look for config file (JSON)
#You can create more than one config.json file in case you want to query more than one Parent/Cloud
#
write-host ""
write-host "* Looking for Config Files (JSON) in Current Script Path." -BackgroundColor Yellow -ForegroundColor Black
write-host "* You can create more than one config file to query different Parent/Clouds." -BackgroundColor Yellow -ForegroundColor Black
write-host ""
$array = @() ; Get-ChildItem *.json -Path . | foreach-object {$array += $_}
$n=0; $array | foreach-object {write-host $n $_; $n++}

Write-Host ""
[int]$selection = Read-Host "Select JSON Config File"

#If incorrect JSON file selection, exit.
try {
        $config = Get-Content -Path $array[$selection] -Raw | ConvertFrom-Json
    }
catch {
        write-host "An error occurred that could not be resolved." -BackgroundColor Red -ForegroundColor Black;
        exit;
    }

#Else, load config file settings and proceed
$c_id = $config.ClientID
$c_se = $config.ClientSecret
$filepath = $config.CID_File
$uri = $config.URL

#Get Child CIDs from Parent

write-host ""
write-host "* Getting OAuth Token for Parent" -BackgroundColor Green -ForegroundColor Black


#Clear any previous token
$token = ""

#Setup Empty AuthArray
$params_auth = @{
    Uri = ""
    Headers = @{'Authorization' = ""}
    Method = "POST"
    Body = ""
    ContentType = 'application/x-www-form-urlencoded'
}

#Fill AuthArray to get OAuth Token
$params_auth.Uri = $uri + "/oauth2/token"
$params_auth.Body ="client_id=“ + $c_id + “&client_secret=“ + $c_se
$params_auth.ContentType = 'application/x-www-form-urlencoded'

#Execute OAuth Token
$r1 = ""
$r1 = Invoke-RestMethod @params_auth

#Extract Token for Later Use
$token = $r1.access_token


write-host ""
write-host "* Requesting Child CIDs associated to Parent" -BackgroundColor Green -ForegroundColor Black


    #Setup Empty Child CID Array
    $params_cid = @{
    Uri = ""
    Headers = @{'Authorization' = ""}
    Method = "GET"
    ContentType = "application/json"
    }

    #edit child CID Array
    $params_cid.Uri = $uri + "/mssp/queries/children/v1"
    $params_cid.Headers.Authorization = "Bearer $token"    

    #execute child CID list Array
    $r2 = ""
    $r2 = Invoke-RestMethod @params_cid

    #With a List of Child CIDs attached to the Parent, obtain CID Name and CCID
    #Build CID String for CCID Query
    $cidstring = ""
    ForEach ($cid in $r2.resources) 
    {
        $cidstring=$cidstring + "&ids=$cid"
    }
    
    #remove first "&" from string built above for next request
    $cidstring= $cidstring.substring(1) 

    #Empty CCID Array (to get checksum and Name)
    $params_ccid = @{
    Uri = ""
    Headers = @{'Authorization' = ""}
    Method = "GET"
    ContentType = "application/json"
    }

    #edit child CCID Array
    $params_ccid.Uri = $uri + "/mssp/entities/children/v1?$cidstring"
    $params_ccid.Headers.Authorization = "Bearer $token"  

    #execute child CID list Array
    $r3 = ""
    $r3 = Invoke-RestMethod @params_ccid

    #Setup Empty AuthArray
    $params_revoke = @{
        Uri = ""
        Headers = @{'Authorization' = ""}
        Method = "POST"
        Body = ""
        ContentType = 'application/x-www-form-urlencoded'
    }

    #Build Data to be exported to CSV File
    $ccids =""
    $ccids = ForEach ($child_cid in $r3.resources) 
    {

    [PSCustomObject]@{
            CIDNAME = $child_cid.name
            CCID = $child_cid.child_cid+"-"+ $child_cid.checksum
        }
    }

    #export data to CSV File
    try {$ccids | Export-Csv $filepath -NoTypeInformation}
    catch {write-host "Something went wrong exporting the CSV file"; exit;}

    write-host ""
    write-host "* CCID Export to CSV File Complete" -BackgroundColor Green -ForegroundColor Black

    write-host ""
    write-host "* Releasing OAuth Token" -BackgroundColor Yellow -ForegroundColor Black

    #Revoke OAuth Token
    #Convert ClientID and ClientSecret to Basic (required for Revoke API)
    [string]$auth_str = $c_id + ":" + $c_se
    $auth_enc = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($auth_str))

    #Building Revoke Request
    $params_revoke.Uri = $uri + "/oauth2/revoke"
    $params_revoke.Body = "token=$token"
    $params_revoke.Headers.Authorization = "basic $auth_enc"

    #Execute OAuth Token Revoke
    $r0 = ""
    $r0 = Invoke-RestMethod @params_revoke

    write-host ""
    write-host "* Export/Script Execution Complete" -BackgroundColor Green -ForegroundColor Black