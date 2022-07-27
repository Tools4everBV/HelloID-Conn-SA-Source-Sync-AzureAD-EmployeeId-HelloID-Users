##########-------------------- Script parameters --------------------##########
$updateErrorsCritical = $true

### HelloID Parameters ###
#$portalBaseUrl = "https://{customer}.helloid.com"
#$portalApiKey = ""
#$portalApiSecret = ""

# Value to use in wildcard filter for HelloID Users
$HelloIDUserSource = "AzureAD" # By default this sync script is meant to sync the employeeId to users from the source AzureAD, but in theory this can be another source
$HelloIDUserExclusionFilter = "#EXT#" # External users in Azure are marked with #EXT#
$HelloIDUserInclusionFilter = $null

### AzureAD Parameters ###
#$AADtenantID = ""
#$AADAppId = ""
#$AADAppSecret = ""

# Value to use in wildcard filter for Azure Users; filters on UserPrincipalName
$AADUserExclusionFilter = "#EXT#" # External users in Azure are marked with #EXT#
$AADUserInclusionFilter = $null

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#Region Azure Functions
function New-AzureAccessToken{
    param(
        [Parameter(Mandatory=$true)]
        [String]
        $TenantID,

        [Parameter(Mandatory=$true)]
        [String]
        $AppId,

        [Parameter(Mandatory=$true)]
        [String]
        $AppSecret,

        [Parameter(Mandatory=$false)]
        [Boolean]
        $Logging,

        [Parameter(Mandatory=$true)]
        [Ref]
        $Response
    )
    try{
        if($Logging -eq $true){ Hid-Write-Status -Event Information -Message "Creating Graph API Access token for Azure Tenant with id '$AADTenantID'..." }

        $Response.Value = $null

        $baseUri = "https://login.microsoftonline.com/"
        $authUri = $baseUri + "$AADTenantID/oauth2/token"

        $body = @{
            grant_type      = "client_credentials"
            client_id       = "$AADAppId"
            client_secret   = "$AADAppSecret"
            resource        = "https://graph.microsoft.com"
        }

        $accessToken = Invoke-RestMethod -Method Post -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'

        $Response.Value = $accessToken
        if($Logging -eq $true){ Hid-Write-Status -Event Success -Message "Successfully created Graph API Access token for Azure Tenant with id '$AADTenantID'" }
    }catch{
        throw "Could not create Graph API Access token for Azure Tenant with id '$AADTenantID', errorcode: 0x$('{0:X8}' -f $_.Exception.HResult), message: $($_.Exception.Message)"
    }
}

function Get-AzureUsers{
    param(
        [Parameter(Mandatory=$true)]
        $AccessToken,

        [Parameter(Mandatory=$false)]
        $UserPrincipalNameFilter,

        [Parameter(Mandatory=$false)]
        $InclusionFilter,

        [Parameter(Mandatory=$false)]
        $ExclusionFilter,

        [Parameter(Mandatory=$false)]
        [Boolean]
        $Logging,

        [Parameter(Mandatory=$true)]
        [Ref]
        $Response
    )
    try{
        if($Logging -eq $true){ Hid-Write-Status  -Event Information -Message "Gathering users from Graph API..." }
        $Response.Value = $null

        $baseUri = "https://graph.microsoft.com/"
        $usersUri = $baseUri + "v1.0/users"

        $propertiesToSelect = @(
            "UserPrincipalName",
            "EmployeeId",
            "AccountEnabled",
            "Id",
            "onPremisesImmutableId"
        )
        # manager requires special handling
        $managerUriExtension = '&$expand=manager($levels=1;$select=employeeId,userPrincipalName)'

        $usersUri = $usersUri + ('?$select=' + ($propertiesToSelect -join "," | Out-String) + $managerUriExtension)
        Hid-Write-Status -Message "Query graph api with uri [$usersUri]" -Event Information

        $headers = @{
            Authorization = "$($AccessToken.token_type) $($AccessToken.access_token)"
        }

        $data = @()
        $query = Invoke-RestMethod -Method Get -Uri $usersUri -Headers $headers -ContentType 'application/x-www-form-urlencoded'
        $data += $query.value

        while($null -ne $query.'@odata.nextLink'){
            $query = Invoke-RestMethod -Method Get -Uri $query.'@odata.nextLink' -Headers $headers -ContentType 'application/x-www-form-urlencoded'
            $data += $query.value
        }

        if(![string]::IsNullOrEmpty($InclusionFilter)){
            if($Logging -eq $true){ Hid-Write-Status -Event Warning -Message "Found [$($data.userPrincipalName.Count)] users. Filtering for only users with [$InclusionFilter] in their UserPrincipalName." }
            $data = foreach($user in $data){
                if($user.userPrincipalName -like "*$InclusionFilter*"){
                    $user
                }
            }
        }

        if(![string]::IsNullOrEmpty($ExclusionFilter)){
            if($Logging -eq $true){ Hid-Write-Status -Event Warning -Message "Found [$($data.userPrincipalName.Count)] users. Filtering out users with [$ExclusionFilter] in their UserPrincipalName." }
            $data = foreach($user in $data){
                if($user.userPrincipalName -notlike "*$ExclusionFilter*"){
                    $user
                }
            }
        }

        $Response.Value = $data
        if($Logging -eq $true){ Hid-Write-Status -Event Success -Message "Successfully gathered users from Graph API. Found [$($Response.Value.count)] users" }
    }catch{
        throw "Could not gather users from Graph API, errorcode: 0x$('{0:X8}' -f $_.Exception.HResult), message: $($_.Exception.Message)"
    }

}
#Endregion Azure Functions

#Region HelloID Functions
# Create function to create new web request key
function New-WebRequestKey{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [String]
        $ApiKey,

        [Parameter(Mandatory=$true)]
        [String]
        $ApiSecret,

        [Parameter(Mandatory=$false)]
        [Boolean]
        $Logging,

        [Parameter(Mandatory=$true)]
        [Ref]
        $Response
    )
    try{
        if($Logging -eq $true){ Hid-Write-Status -Event Information -Message "Creating HelloID API key..." }
        $Response.Value = $null
        $pair = "${ApiKey}:${ApiSecret}"
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
        $base64 = [System.Convert]::ToBase64String($bytes)
        $key = "Basic $base64"
        $Response.Value = $key
        if($Logging -eq $true){ Hid-Write-Status -Event Success -Message "Successfully created HelloID API key"  }
    }catch{
        throw "Could not create HelloID API key, errorcode: 0x$('{0:X8}' -f $_.Exception.HResult), message: $($_.Exception.Message)"
    }
}

# Create function for Rest method
function Invoke-HidRestMethod{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [String]
        $Method,

        [Parameter(Mandatory=$true)]
        [String]
        $Uri,

        [Parameter(Mandatory=$false)]
        [String]
        $ContentType,

        [Parameter(Mandatory=$false)]
        [String] 
        $Key,

        [Parameter(Mandatory=$false)]
        $Body,

        [Parameter(Mandatory=$true)]
        [Ref]
        $Response,

        [Parameter(Mandatory=$false)]
        $Credential,

        [Parameter(Mandatory=$false)]
        $Headers,

        [Parameter(Mandatory=$false)]
        [Boolean]
        $Logging,

        [Parameter(Mandatory=$false)]
        $PageSize
    )

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
 
    $parameters = @{}
    if($Body){
        $parameters += @{
            Body = $Body
        }
    }
    if($ContentType){
        $parameters += @{
            ContentType = $ContentType
        }
    }
    if($Key){
        $header = @{}
        $header.Add("authorization",$Key)
        $parameters += @{
            Headers = $header
        }
    }
    if($Credential){
        $parameters += @{
            Credential = $Credential
        }
    }
    if($Headers -and !$key){
        $parameters += @{
            Headers = $Headers
        }
    }
    $Response.Value = $null

    try{
        if($Uri.EndsWith("/") -eq $true){
            Hid-Write-Status -Message ("Failed::Get::$Uri::Uri invalid") -Event Error
            return
        }

        if($PageSize -ne $null){
            $take = $PageSize
            $skip = 0
            if($Uri -match '\?'){
                $uriFirstPage = $Uri + "&skip=$skip&take=$take"
            }else{
                $uriFirstPage = $Uri + "?skip=$skip&take=$take"
            }
            $servicePoint = [System.Net.ServicePointManager]::FindServicePoint($uriFirstPage)
            $dataset = Invoke-RestMethod -Method $Method -Uri $uriFirstPage @parameters
            if($dataset.pageData -ne $null){
                $dataset = $dataset.pageData
            }
            $result = $servicePoint.CloseConnectionGroup("")

            $Response.Value += $dataset
            if($Logging -eq $true){ Hid-Write-Status -Event Information  -Message ("Successfully retrieved data from $uriFirstPage") }

            $skip += $take
            while($dataset.Count -eq $take){
                if($Uri -match '\?'){
                    $uriPage = $Uri + "&skip=$skip&take=$take"
                }else{
                    $uriPage = $Uri + "?skip=$skip&take=$take"
                }

                $servicePoint = [System.Net.ServicePointManager]::FindServicePoint($uriPage)
                $dataset = Invoke-RestMethod -Method $Method -Uri $uriPage @parameters
                if($dataset.pageData -ne $null){
                    $dataset = $dataset.pageData
                }
                $result = $servicePoint.CloseConnectionGroup("")

                $skip += $take
                $Response.Value += $dataset
                if($Logging -eq $true){ Hid-Write-Status -Event Information -Message "Successfully retrieved data from $uriPage" }
            }
        }else{
            $Response.Value = $null
            $servicePoint = [System.Net.ServicePointManager]::FindServicePoint($Uri)
            $Response.Value = Invoke-RestMethod -Method $Method -Uri $Uri @parameters
            $result = $servicePoint.CloseConnectionGroup("")
        }
    }catch{
        throw $_
    }
}

function Get-HIDUsers{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [String]
        $PortalBaseUrl,

        [Parameter(Mandatory=$true)]
        $Headers,

        [Parameter(Mandatory=$false)]
        $Source,

        [Parameter(Mandatory=$false)]
        $InclusionFilter,

        [Parameter(Mandatory=$false)]
        $ExclusionFilter,

        [Parameter(Mandatory=$false)]
        [Boolean]
        $Logging,

        [Parameter(Mandatory=$true)]
        [Ref]
        $Response
    )
    try{
        $Response.Value = $null
        if($Logging -eq $true){ Hid-Write-Status -Event Information -Message "Gathering users from HelloID..." }
        if($PortalBaseUrl.EndsWith("/")){
            $uri = ($PortalBaseUrl +"api/v1/users")
        }else{
            $uri = ($PortalBaseUrl +"/api/v1/users")
        }

        $users = [PSCustomObject]::new()
        Invoke-HidRestMethod -Response ([Ref]$users) -Method Get -Uri $uri -Headers $Headers -ContentType "application/json" -PageSize 500

        if(![string]::IsNullOrEmpty($Source)){
            if($Logging -eq $true){ Hid-Write-Status -Event Warning -Message "Found [$($users.userName.Count)] users. Filtering for users of source [$Source]." }
            $users = foreach($user in $users){
                if($user.source -eq "$Source"){
                    $user
                }
            }
        }

        if(![string]::IsNullOrEmpty($InclusionFilter)){
            if($Logging -eq $true){ Hid-Write-Status -Event Warning -Message "Found [$($users.userName.Count)] users. Filtering out users with [$InclusionFilter] NOT in their username." }
            $users = foreach($user in $users){
                if($user.username -like "*$InclusionFilter*"){
                    $user
                }
            }
        }

        if(![string]::IsNullOrEmpty($ExclusionFilter)){
            if($Logging -eq $true){ Hid-Write-Status -Event Warning -Message "Found [$($users.userName.Count)] users. Filtering out users with [$ExclusionFilter] in their username." }
            $users = foreach($user in $users){
                if($user.username -notlike "*$ExclusionFilter*"){
                    $user
                }
            }
        }

        $Response.Value = $users
        if($Logging -eq $true){ Hid-Write-Status -Event Success -Message "Successfully gathered users from HelloID. Found [$($users.userName.Count)] users" }   
    }catch{
        throw "Could not gather users from HelloID, errorcode: 0x$('{0:X8}' -f $_.Exception.HResult), message: $($_.Exception.Message)"
    }
}

function Update-HIDUser{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] 
        [String] 
        $PortalBaseUrl,

        [Parameter(Mandatory=$true)] 
        $Headers,

        [Parameter(Mandatory=$true)]
        [String]
        $Username,

        [Parameter(Mandatory=$false)]
        $UserGuid,

        [Parameter(Mandatory=$false)]
        [Boolean]
        $IsEnabled,

        [Parameter(Mandatory=$false)]
        [Boolean]
        $IsLocked,

        [Parameter(Mandatory=$false)]
        [Boolean]
        $MustChangePassword,

        [Parameter(Mandatory=$false)]
        [String]
        $FirstName,

        [Parameter(Mandatory=$false)]
        [String]
        $LastName,

        [Parameter(Mandatory=$false)]
        [String]
        $ContactEmail,

        [Parameter(Mandatory=$false)]
        [String]
        $PhoneNumber,

        [Parameter(Mandatory=$false)]
        [String]
        $EmployeeId,

        [Parameter(Mandatory=$false)]
        [String]
        $SamAccountName,

        [Parameter(Mandatory=$false)]
        [String]
        $ManagedByUserGuid,

        [Parameter(Mandatory=$false)]
        [Array]
        $Roles,

        [Parameter(Mandatory=$false)]
        [Hashtable]
        $UserAttributes,

        [Parameter(Mandatory=$false)]
        [Boolean]
        $Logging,

        [Parameter(Mandatory=$true)]
        [Ref]
        $Response
    )
    try{
        $Response.Value = $null

        if($Logging){
            Hid-Write-Status -Message "Updating HelloID user '$Username'..." -Event Information
        }

        if($PortalBaseUrl.EndsWith("/")){
            $uri = ($PortalBaseUrl + "api/v1/users/")
        }else{
            $uri = ($PortalBaseUrl + "/api/v1/users/")
        }

        if(![string]::IsNullOrEmpty($UserGuid)){
            $uri = ($uri + "$UserGuid")
        }else{
            $uri = ($uri + "$Username")
        }

        $userBody = @{
            userName  = $Username
        }

        $Attributes = [Ordered]@{
            firstName = $FirstName
            lastName = $LastName
            isEnabled = $IsEnabled
            isLocked = $IsLocked
            mustChangePassword = $MustChangePassword
            contactEmail = $ContactEmail
            roles = $Roles
            userAttributes = $UserAttributes
            phoneNumber = $PhoneNumber
            employeeId = $EmployeeId
            samAccountName = $SamAccountName
            managedByUserGUID = $ManagedByUserGuid
        }

        foreach($inputKey in $Attributes.Keys){
            if(![string]::IsNullOrEmpty($Attributes.$inputKey)){
                if($inputKey -eq "phoneNumber" -or $inputKey -eq "employeeId" -or $inputKey -eq "samAccountName"){
                    if($userBody.userAttributes){
                        $userBody.userAttributes += @{
                            "$inputKey" = $Attributes.$inputKey
                        }
                    }else{
                        $userBody += @{
                            userAttributes = @{
                                "$inputKey" = $Attributes.$inputKey
                            }
                        }
                    }
                }else{
                    $userBody += @{
                        "$inputKey" = $Attributes.$inputKey
                    }
                }
            }
        }
        $jsonUserBody = $userBody | ConvertTo-Json

        $user = [PSCustomObject]::new()
        Invoke-HidRestMethod -Response ([Ref]$user) -Method Put -Uri $uri -Headers $Headers -Body ([System.Text.Encoding]::UTF8.GetBytes($jsonUserBody)) -ContentType "application/json"
        $Response.Value = $user
        if($Logging){
            Hid-Write-Status -Message "Successfully updated HelloID user '$Username'" -Event Success
        }
    }catch{
        if($_.Exception.Message -eq "The remote server returned an error: (400) Bad Request."){
            $message = ($_.ErrorDetails.Message | ConvertFrom-Json).message
            throw "Could not update HelloID user '$Username', errorcode: 'x$('{0:X8}' -f $_.Exception.HResult), message: $($_.Exception.Message) $message"
        }else{
            throw "Could not update HelloID user '$Username', errorcode: 'x$('{0:X8}' -f $_.Exception.HResult), message: $($_.Exception.Message)"
        }
    }
}

function Compare-HIDUserData{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $HidUser,

        [Parameter(Mandatory=$true)]
        $UserDataToCheck,

        [Parameter(Mandatory=$false)]
        [Boolean]
        $Logging,

        [Parameter(Mandatory=$true)]
        [Ref]
        $Response
    )
    try{
        $Response.Value = $null
        if($Logging){
            Hid-Write-Status -Message "HelloID User '$($HidUser.userName)' already exists. Comparing provided data with HelloID data..." -Event Information
        }

        foreach($key in $UserDataToCheck.keys){
            if(![string]::IsNullOrEmpty($UserDataToCheck.$key)){
                if($key -eq "userAttributes"){
                    foreach($userAttributeKey in $UserDataToCheck.userAttributes.keys){
                        if($UserDataToCheck.userAttributes.$userAttributeKey -notlike $HidUser.userAttributes.$userAttributeKey){
                            $userChanged = $true
                        }
                    }
                }elseif($key -eq "PhoneNumber" -or $key -eq "EmployeeId" -or $key -eq "SamAccountName"){
                    if($UserDataToCheck.$key -notlike $HidUser.userAttributes.$key){
                        $userChanged = $true
                    }
                }else{
                    if($HidUser.$key.Count -gt 1){
                        for($i = 0; $i -lt $HidUser.$key.Count; $i++){
                            if($UserDataToCheck.$key[$i] -ne $HidUser.$key[$i]){
                                $userChanged = $true
                            }
                        }
                    }else{
                        if($UserDataToCheck.$key -notlike $HidUser.$key){
                            $userChanged = $true
                        }
                    }
                }
            }
        }
        if($Logging){
            if($userChanged -eq $true){
                Hid-Write-Status -Message "Successfully compared provided data with HelloID data for user '$($HidUser.userName)'. Provided data differs from HelloID data" -Event Warning 
            }else{
                Hid-Write-Status -Message "Successfully compared provided data with HelloID data for user '$($HidUser.userName)'. Provided data does not differ from HelloID data" -Event Warning 
            }
        }
        $Response.Value = $userChanged
    }catch{
        throw "Could not compare provided data with HelloID data for user '$($HidUser.userName)', errorcode: 'x$('{0:X8}' -f $_.Exception.HResult), message: $($_.Exception.Message)"
    }
}
#Endregion HelloID Functions

##########-------------------- Script --------------------##########

# Microsoft Graph API - Get access token
try{
    $azureAccessToken = [PSCustomObject]::new()
    New-AzureAccessToken -TenantID $AADtenantID -AppId $AADAppId -AppSecret $AADAppSecret -Response ([Ref]$azureAccessToken) -Logging:$false
}catch{
    throw $_
}

# Microsoft Graph API - Get Azure users
Try{
    $azureUsers = [PSCustomObject]::new()
    Get-AzureUsers -AccessToken $azureAccessToken -InclusionFilter $AADUserInclusionFilter -ExclusionFilter $AADUserExclusionFilter -Response ([Ref]$azureUsers) -Logging:$false

    $azureUserHashtable = @{}
    foreach($azureUser in $azureUsers){
        $azureUserHashtable += @{$azureUser.userPrincipalName = $azureUser}
    }
}catch{
    throw $_
}


# HelloID API - Get Web request key
try{
    $key = [PSCustomObject]::new()
    New-WebRequestKey -ApiKey $portalApiKey -ApiSecret $portalApiSecret -Response ([Ref]$key) -Logging:$false
    $headers = @{}
    $headers.Add("authorization",$key)
}catch{
    throw $_
}

# HelloID API - Get HelloID users
try{
    $hidUsers = [PSCustomObject]::new()
    Get-HIDUsers -PortalBaseUrl $portalBaseUrl -Headers $headers -Source $HelloIDUserSource -InclusionFilter $HelloIDUserInclusionFilter -ExclusionFilter $HelloIDUserExclusionFilter -Response ([Ref]$hidUsers) -Logging:$false
    $hidUserHashtable = @{}

    foreach($hidUser in $hidUsers){
        $hidUserHashtable += @{$hidUser.userName = $hidUser}
    }
}catch{
    throw $_
}

#-------------------- User sync --------------------#
[System.Collections.Generic.List[object]]$hidUsersToUpdate = @()
[Int]$updateSuccess = 0
[Int]$updateFailed = 0

# Update existing users
if($hidUsers.Username.Count -gt 0){
    Hid-Write-Status -Message "Comparing [$($hidUsers.Username.Count)] HelloID users for changes.." -Event Warning
}

foreach($hidUser in $hidUsers){
    try{
        $azureUser = $azureUserHashtable[$hidUser.UserName]
        if (![String]::IsNullOrEmpty($azureUser.Manager.userPrincipalName)) {
            $hidUserManager = $hidUserHashtable[$azureUser.Manager.userPrincipalName]
        }

        $userObject = [Ordered]@{
            Username = $hidUser.UserName
            EmployeeId = $azureUser.EmployeeId
            IsEnabled = $hidUser.isEnabled
            managedByUserGUID = $hidUserManager.userGUID
        }

        $userChanged = [PSCustomObject]::new()
        Compare-HIDUserData -HidUser $hidUserHashtable[$userObject.Username] -UserDataToCheck $userObject -Response ([Ref]$userChanged) -Logging:$false

        if($userChanged -eq $true){
            $userObject.Add('UserGUID', $hidUserHashtable[$userObject.Username].UserGUID)
            $null = $hidUsersToUpdate.Add($userObject)

            $updatedHidUser = [PSCustomObject]::new()
            Update-HIDUser @userObject -PortalBaseUrl $portalBaseUrl -Headers $headers -Response ([Ref]$updatedHidUser) -Logging:$false
            $updateSuccess++
        }
    }catch{
        $updateFailed++
        if($updateErrorsCritical){
            throw $_
        }else{
            Hid-Write-Status -Message $_ -Event Error
        }
    }
}

if($hidUsersToUpdate.username.Count -gt 0){
    if($updateSuccess -gt 0){
        Hid-Write-Status -Message "Successfully updated [$updateSuccess] HelloID users" -Event Success
    }
    if($updateFailed -gt 0){
        Hid-Write-Status -Message "Failed to update [$updateFailed] HelloID users" -Event Error
    }
    Hid-Write-Summary -Message "Finished updating HelloID users. Success: [$updateSuccess] Failed: [$updateFailed], check the Progress for more details" -Event Success
}else{
    Hid-Write-Status -Message "No HelloID users updated. There were no changes between Azure AD users and HelloID users" -Event Success
    Hid-Write-Summary -Message "There were no HelloID users updated, check the Progress for more details" -Event Success
}

Hid-Write-Summary -Message "Finished synchronizing EmployeeId from Azure for [$($hidUsers.UserName.Count)] HelloID users" -Event Success