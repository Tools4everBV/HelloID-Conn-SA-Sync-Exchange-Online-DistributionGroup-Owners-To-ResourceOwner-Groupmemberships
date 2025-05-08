#####################################################
# HelloID-Conn-SA-Sync-EXO-DistributionGroup-Owners-To-ResourceOwner-Groupmemberships
#
# Version: 1.0.0
#####################################################
# Set to false to acutally perform actions - Only run as DryRun when testing/troubleshooting!
$dryRun = $false
# Set to true to log each individual action - May cause lots of logging, so use with cause, Only run testing/troubleshooting!
$verboseLogging = $false

switch ($verboseLogging) {
    $true { $VerbosePreference = "Continue" }
    $false { $VerbosePreference = "SilentlyContinue" }
}
$informationPreference = "Continue"
$WarningPreference = "Continue"

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

# Make sure to create the Global variables defined below in HelloID
#HelloID Connection Configuration
#$script:PortalBaseUrl = "" # Set from Global Variable
#$portalApiKey = "" # Set from Global Variable
#$portalApiSecret = "" # Set from Global Variable

# Exchange Online Connection Configuration
#$EntraOrganization = '' # Set from Global Variable
#$EntraTenantID = '' # Set from Global Variable
#$EntraAppID = ''# Set from Global Variable
#$EntraAppSecret = '' # Set from Global Variable
 
$exchangeGroupsFilter = "(DisplayName -like '*X*')"
# PowerShell commands to import
$commands = @(
    "Get-User"
    , "Get-DistributionGroup"
) # Fixed list of commands required by script - only change when missing commands

#HelloID Configuration
$resourceOwnerGroupSource = "Local" # Specify the source of the groups - if source is any other than "Local", the sync of the target system itself might overwrite the memberships set form this sync
# The HelloID Resource owner group will be queried based on the distribution group name and the specified prefix and suffix
$resourceOwnerGroupPrefix = "" # Specify prefix to recognize the resource owner group
$resourceOwnerGroupSuffix = " - Owner" # Specify suffix to recognize the resource owner group
$removeMembers = $false # If true, existing members will be removed if they no longer have full access to the corresponding mailbox - This will overwrite manual added users

#region functions

function Remove-StringLatinCharacters {
    PARAM ([string]$String)
    [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($String))
}

function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ""
        }

        if ($ErrorObject.Exception.GetType().FullName -eq "Microsoft.PowerShell.Commands.HttpResponseException") {
            # $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message # Does not show the correct error message for the Raet IAM API calls
            $httpErrorObj.ErrorMessage = $ErrorObject.Exception.Message

        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq "System.Net.WebException") {
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }

        Write-Output $httpErrorObj
    }
}

function Get-ErrorMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $errorMessage = [PSCustomObject]@{
            VerboseErrorMessage = $null
            AuditErrorMessage   = $null
        }

        if ( $($ErrorObject.Exception.GetType().FullName -eq "Microsoft.PowerShell.Commands.HttpResponseException") -or $($ErrorObject.Exception.GetType().FullName -eq "System.Net.WebException")) {
            $httpErrorObject = Resolve-HTTPError -Error $ErrorObject

            $errorMessage.VerboseErrorMessage = $httpErrorObject.ErrorMessage

            $errorMessage.AuditErrorMessage = $httpErrorObject.ErrorMessage
        }

        # If error message empty, fall back on $ex.Exception.Message
        if ([String]::IsNullOrEmpty($errorMessage.VerboseErrorMessage)) {
            $errorMessage.VerboseErrorMessage = $ErrorObject.Exception.Message
        }
        if ([String]::IsNullOrEmpty($errorMessage.AuditErrorMessage)) {
            $errorMessage.AuditErrorMessage = $ErrorObject.Exception.Message
        }

        Write-Output $errorMessage
    }
}

function Invoke-HIDRestmethod {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Method,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Uri,

        [object]
        $Body,

        [Parameter(Mandatory = $false)]
        $PageSize,

        [string]
        $ContentType = "application/json"
    )

    try {
        Write-Verbose "Switching to TLS 1.2"
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

        Write-Verbose "Setting authorization headers"
        $apiKeySecret = "$($portalApiKey):$($portalApiSecret)"
        $base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($apiKeySecret))
        $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
        $headers.Add("Authorization", "Basic $base64")
        $headers.Add("Content-Type", $ContentType)
        $headers.Add("Accept", $ContentType)

        $splatWebRequest = @{
            Uri             = "$($script:PortalBaseUrl)/api/v1/$($Uri)"
            Headers         = $headers
            Method          = $Method
            UseBasicParsing = $true
            ErrorAction     = "Stop"
        }
        
        if (-not[String]::IsNullOrEmpty($PageSize)) {
            $data = [System.Collections.ArrayList]@()

            $skip = 0
            $take = $PageSize
            Do {
                $splatWebRequest["Uri"] = "$($script:PortalBaseUrl)/api/v1/$($Uri)?skip=$($skip)&take=$($take)"

                Write-Verbose "Invoking [$Method] request to [$Uri]"
                $response = $null
                $response = Invoke-RestMethod @splatWebRequest -Verbose:$false
                if (($response.PsObject.Properties.Match("pageData") | Measure-Object).Count -gt 0) {
                    $dataset = $response.pageData
                }
                else {
                    $dataset = $response
                }

                if ($dataset -is [array]) {
                    [void]$data.AddRange($dataset)
                }
                else {
                    [void]$data.Add($dataset)
                }
            
                $skip += $take
            }until(($dataset | Measure-Object).Count -ne $take)

            return $data
        }
        else {
            if ($Body) {
                Write-Verbose "Adding body to request"
                $splatWebRequest["Body"] = ([System.Text.Encoding]::UTF8.GetBytes($body))
            }

            Write-Verbose "Invoking [$Method] request to [$Uri]"
            $response = $null
            $response = Invoke-RestMethod @splatWebRequest -Verbose:$false

            return $response
        }

    }
    catch {
        throw $_
    }
}
#endregion functions

#region script
HID-Write-Status -Event Information -Message "Starting synchronization of Exchange Online Distribution Group Owners to Distributiongroup to HelloID ResourceOwner Groupmemberships"
HID-Write-Status -Event Information -Message "------[Exchange Online]-----------"

# Import module
try {
    $moduleName = "ExchangeOnlineManagement"
    $importModule = Import-Module -Name $moduleName -ErrorAction Stop -Verbose:$false
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error importing module [$moduleName]. Error Message: $($errorMessage.AuditErrorMessage)"
}

# Connect to Exchange
try {
    # Create access token
    Write-Verbose "Creating Access Token"

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$EntraTenantID/oauth2/token"
    
    $body = @{
        grant_type    = "client_credentials"
        client_id     = "$EntraAppID"
        client_secret = "$EntraAppSecret"
        resource      = "https://outlook.office365.com"
    }
    
    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType "application/x-www-form-urlencoded" -UseBasicParsing:$true -Verbose:$false
    $accessToken = $Response.access_token

    # Connect to Exchange Online in an unattended scripting scenario using an access token.
    Write-Verbose "Connecting to Exchange Online"

    $exchangeSessionParams = @{
        Organization     = $EntraOrganization
        AppID            = $EntraAppID
        AccessToken      = $accessToken
        CommandName      = $exchangeOnlineCommands
        ShowBanner       = $false
        ShowProgress     = $false
        TrackPerformance = $false
        ErrorAction      = "Stop"
    }
    $exchangeSession = Connect-ExchangeOnline @exchangeSessionParams -Verbose:$false
    
    Write-Information "Successfully connected to Exchange Online"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"
    throw "Error connecting to Exchange Online. Error Message: $($errorMessage.AuditErrorMessage)"
}

# Get Exchange Online Distribution groups
try {  
    $exchangeQuerySplatParams = @{
        Filter               = $exchangeGroupsFilter
        ResultSize           = "Unlimited"
        Verbose              = $false
        ErrorAction          = "Stop"
    }

    HID-Write-Status -Event Information -Message "Querying Exchange Online Distribution Groups that match filter [$($exchangeQuerySplatParams.Filter)]"
    $exoDBGroups = Get-DistributionGroup @exchangeQuerySplatParams

    if (($exoDBGroups | Measure-Object).Count -eq 0) {
        throw "No Distribution groups have been found"
    }

    HID-Write-Status -Event Success -Message "Successfully queried Exchange Online Distribution Groups. Result count: $(($exoDBGroups | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    HID-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Exchange Online DistributionGroups that match filter [$($exchangeQuerySplatParams.Filter)]. Error Message: $($errorMessage.AuditErrorMessage)"
}

#region Get Exchange online users grouped on Displayname
# Exchange Online users are needed so all the attributes are available
try {
    Write-Verbose "Querying Exchange users"

    $exoUsers = Get-User -ResultSize Unlimited -Verbose:$false

    if (($exoUsers | Measure-Object).Count -eq 0) {
        throw "No Users have been found"
    }

    $exoUsersGroupedOnDisplayName = $exoUsers | Group-Object DisplayName -AsHashTable 
    HID-Write-Status -Event Success -Message "Successfully queried Exchange Online Users. Result count: $(($exoUsers | Measure-Object).Count)"
}
catch { 
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    HID-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
    throw "Error querying all Exchange users. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Get Exchange online groups

HID-Write-Status -Event Information -Message "------[HelloID]------"
#region Get HelloID Users
try {
    Write-Verbose "Querying Users from HelloID"

    $splatWebRequest = @{
        Method   = "GET"
        Uri      = "users"
        PageSize = 1000
    }
    $helloIDUsers = Invoke-HIDRestMethod @splatWebRequest

    $helloIDUsersGroupedOnUserName = $helloIDUsers | Group-Object -Property "userName" -AsHashTable -AsString
    $helloIDUsersGroupedOnUserGUID = $helloIDUsers | Group-Object -Property "userGUID" -AsHashTable -AsString

    HID-Write-Status -Event Success -Message "Successfully queried Users from HelloID. Result count: $(($helloIDUsers | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    HID-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Users from HelloID. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Get HelloID Users

#region Get HelloID Groups
try {
    Write-Verbose "Querying Groups from HelloID"

    $splatWebRequest = @{
        Method   = "GET"
        Uri      = "groups"
        PageSize = 1000
    }
    $helloIDGroups = Invoke-HIDRestMethod @splatWebRequest

    HID-Write-Status -Event Success -Message "Successfully queried Groups from HelloID. Result count: $(($helloIDGroups | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    HID-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Groups from HelloID. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Get HelloID Groups

#region Get members of HelloID groups
try {
    [System.Collections.ArrayList]$helloIDGroupsWithMembers = @()
    Write-Verbose "Querying HelloID groups with members"
    foreach ($helloIDGroup in $helloIDGroups) {
        #region Get HelloID users that are member of HelloID group
        try {
            Write-Verbose "Querying HelloID group [$($helloIDGroup.name) ($($helloIDGroup.groupGuid))] with members"

            $splatWebRequest = @{
                Method   = "GET"
                Uri      = "groups/$($helloIDGroup.groupGuid)"
                PageSize = 1000
            }
            $helloIDGroup = Invoke-HIDRestMethod @splatWebRequest

            [void]$helloIDGroupsWithMembers.Add($helloIDGroup)

            if ($verboseLogging -eq $true) {
                HID-Write-Status -Event Success "Successfully queried HelloID group [$($helloIDGroup.name) ($($helloIDGroup.groupGuid))] with members. Result count: $(($helloIDGroup.users | Measure-Object).Count)"
            }
        }
        catch {
            $ex = $PSItem
            $errorMessage = Get-ErrorMessage -ErrorObject $ex
        
            HID-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
        
            throw "Error querying HelloID group [$($helloIDGroup.name) ($($helloIDGroup.groupGuid))] with members. Error Message: $($errorMessage.AuditErrorMessage)"
        }
        #endregion Get HelloID users that are member of HelloID group
    }

    $helloIDGroupsWithMembers | Add-Member -MemberType NoteProperty -Name SourceAndName -Value $null
    $helloIDGroupsWithMembers | ForEach-Object {
        if ([string]::IsNullOrEmpty($_.source)) {
            $_.source = "Local"
        }
        $_.SourceAndName = "$($_.source)/$($_.name)"
    }

    $helloIDGroupsWithMembers = $helloIDGroupsWithMembers | Where-Object { $_.SourceAndName -like "$($resourceOwnerGroupSource)/*" }

    $helloIDGroupsWithMembersGroupedBySourceAndName = $helloIDGroupsWithMembers | Group-Object -Property "SourceAndName" -AsHashTable -AsString

    HID-Write-Status -Event Success -Message "Successfully queried HelloID groups with members. Result count: $(($helloIDGroupsWithMembers.users | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    HID-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying HelloID users that are member of HelloID groups. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregionGet members of HelloID groups

HID-Write-Status -Event Information -Message "------[Calculations of combined data]------"
# Calculate new and obsolete groupmemberships
try {
    # Define existing & new groupmemberships
    $existingGroupMembershipObjects = [System.Collections.ArrayList]@()
    $newGroupMembershipObjects = [System.Collections.ArrayList]@()
    
    
    foreach ($exoDBGroup in $ExoDBGroups) {
        # Define Resource owner Group
        $resourceOwnerGroupName = "$($resourceOwnerGroupSource)/" + "$($resourceOwnerGroupPrefix)" + "$($exoDBGroup.DisplayName)" + "$($resourceOwnerGroupSuffix)"

        # Get HelloID Resource Owner Group
        $helloIDResourceOwnerGroup = $null
        if (-not[string]::IsNullOrEmpty($resourceOwnerGroupName)) {
            $resourceOwnerGroupName = Remove-StringLatinCharacters $resourceOwnerGroupName
            $helloIDResourceOwnerGroup = $helloIDGroupsWithMembersGroupedBySourceAndName["$($resourceOwnerGroupName)"]
            if ($null -eq $helloIDResourceOwnerGroup) {
                if ($verboseLogging -eq $true) {
                    HID-Write-Status -Event Warning "Resource owner group [$($resourceOwnerGroupName)] for Distribution Group not found in HelloID"
                }

                # Skip further actions for this record
                Continue
            }
        }
        else {
            if ($verboseLogging -eq $true) {
                HID-Write-Status -Event Warning "No Resource owner group name provided for Distribution Group"
            }
        }

        # Define existing groupmemberships
        foreach ($helloIDResourceOwnerGroupUser in $helloIDResourceOwnerGroup.Users) {
            # Get HelloID User
            $helloIDUser = $null
            $helloIDUser = $helloIDUsersGroupedOnUserGUID["$($helloIDResourceOwnerGroupUser)"]
            if ($null -eq $helloIDUser) {
                if ($verboseLogging -eq $true) {
                    HID-Write-Status -Event Warning "No HelloID user found for Exchange User Resource owner group [$($helloIDResourceOwnerGroupUser)]"
                }

                # Skip further actions for this record
                Continue
            }
            
            $existingGroupMembershipObject = [PSCustomObject]@{
                GroupName    = "$($helloIDResourceOwnerGroup.name)"
                GroupId      = "$($helloIDResourceOwnerGroup.groupGuid)"
                UserUsername = "$($helloIDUser.userName)"
                UserId       = "$($helloIDUser.userGUID)"
            }

            [void]$existingGroupMembershipObjects.Add($existingGroupMembershipObject)
        }

        # Define new groupmemberships
        foreach ($exoDBGroupOwner in $exoDBGroup.ManagedBy) {
            
            # Get HelloID User
            $helloIDUser = $null
            $exoDBGroupOwnerFullUser = "" 

            $exoDBGroupOwnerFullUser = $exoUsersGroupedOnDisplayName["$exoDBGroupOwner"]

            if (-not[string]::IsNullOrEmpty($exoDBGroupOwnerFullUser.UserPrincipalName)) {
                $helloIDUser = $helloIDUsersGroupedOnUserName["$($exoDBGroupOwnerFullUser.UserPrincipalName)"]
                if ($null -eq $helloIDUser) {
                    if ($verboseLogging -eq $true) {
                        HID-Write-Status -Event Warning "No HelloID user found for Exchange User [$($exoDBGroupOwnerFullUser.UserPrincipalName)]"
                    }

                    # Skip further actions for this record
                    Continue
                }
            }
            else {
                if ($verboseLogging -eq $true) {
                    HID-Write-Status -Event Warning "No UserPrincipalName provided for full access user [$($exoDBGroupOwnerFullUser.Id)]"
                }
            }

            $newGroupMembershipObject = [PSCustomObject]@{
                GroupName    = "$($helloIDResourceOwnerGroup.name)"
                GroupId      = "$($helloIDResourceOwnerGroup.groupGuid)"
                UserUsername = "$($helloIDUser.userName)"
                UserId       = "$($helloIDUser.userGUID)"
            }

            [void]$newGroupMembershipObjects.Add($newGroupMembershipObject)
        }
    }

    # Define new groupmemberships
    $newGroupMemberships = [System.Collections.ArrayList]@()
    $newGroupMemberships = $newGroupMembershipObjects | Where-Object { $_ -notin $existingGroupMembershipObjects }

    # Define obsolete groupmemberships
    $obsoleteGroupMemberships = [System.Collections.ArrayList]@()
    $obsoleteGroupMemberships = $existingGroupMembershipObjects | Where-Object { $_ -notin $newGroupMembershipObjects }

    # Define existing groupmemberships
    $existingGroupMemberships = [System.Collections.ArrayList]@()
    $existingGroupMemberships = $existingGroupMembershipObjects | Where-Object { $_ -notin $obsoleteGroupMemberships }

    # Define total groupmemberships (existing + new)
    $totalGroupMemberships = ($(($existingGroupMemberships | Measure-Object).Count) + $(($newGroupMemberships | Measure-Object).Count))
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    HID-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error calculating new and obsolete groupmemberships. Error Message: $($errorMessage.AuditErrorMessage)"
}


HID-Write-Status -Event Information -Message "------[Summary]------"

HID-Write-Status -Event Information -Message "New HelloID Resource Owner Groupmembership(s) that will be granted [$(($newGroupMemberships | Measure-Object).Count)]"

if ($removeMembers) {
    HID-Write-Status -Event Information "Obsolete HelloID Resource Owner Groupmembership(s) that will be revoked [$(($obsoleteGroupMemberships | Measure-Object).Count)]"
}
else {
    HID-Write-Status -Event Information -Message "Obsolete HelloID Resource Owner Groupmembership(s) that won't be revoked [$(($obsoleteGroupMemberships | Measure-Object).Count)]"
}


HID-Write-Status -Event Information -Message "------[Processing]------------------"


try {
    $addUserToGroupSuccess = 0
    $addUserToGroupError = 0
    foreach ($newGroupMembership in $newGroupMemberships) {
        # Add HelloID User to HelloID Group
        try {
            if ($verboseLogging -eq $true) {
                HID-Write-Status -Event Information "Adding HelloID user [$($newGroupMembership.UserUsername) ($($newGroupMembership.UserId))] to HelloID group [$($newGroupMembership.GroupName) ($($newGroupMembership.GroupId))]"
            }

            if($($newGroupMembership.UserId) -ne ""){
                $addUserToGroupBody = [PSCustomObject]@{
                    UserGUID = "$($newGroupMembership.UserId)"
                }
                $body = ($addUserToGroupBody | ConvertTo-Json -Depth 10)
                $splatWebRequest = @{
                    Uri    = "groups/$($newGroupMembership.GroupId)/users"
                    Method = 'POST'
                    Body   = $body
                }
    
                if ($dryRun -eq $false) {
                    $addUserToGroupResult = Invoke-HIDRestMethod @splatWebRequest
                    $addUserToGroupSuccess++
    
                    if ($verboseLogging -eq $true) {
                        HID-Write-Status -Event Success "Successfully added HelloID user [$($newGroupMembership.UserUsername) ($($newGroupMembership.UserId))] to HelloID group [$($newGroupMembership.GroupName) ($($newGroupMembership.GroupId))]"
                    }
                }
                else {
                    if ($verboseLogging -eq $true) {
                        HID-Write-Status -Event Warning "DryRun: Would add HelloID user [$($newGroupMembership.UserUsername) ($($newGroupMembership.UserId))] to HelloID group [$($newGroupMembership.GroupName) ($($newGroupMembership.GroupId))]"
                    }
                }
                
            } else {
                HID-Write-Status -Event Warning "Adding user to Resource group failed, because user was not found. [$($newGroupMembership.GroupName) ($($newGroupMembership.GroupId))] "
                $addUserToGroupError++
            }
            
        }
        catch {
            $addUserToGroupError++

            $ex = $PSItem
            $errorMessage = Get-ErrorMessage -ErrorObject $ex
            
            HID-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
            
            throw "Error adding HelloID user [$($newGroupMembership.UserUsername) ($($newGroupMembership.UserId))] to HelloID group [$($newGroupMembership.GroupName) ($($newGroupMembership.GroupId))]. Error Message: $($errorMessage.AuditErrorMessage)"
        }
    }
    if ($dryRun -eq $false) {
        if ($addUserToGroupSuccess -ge 1 -or $addUserToGroupError -ge 1) {
            HID-Write-Status -Event Information -Message "Added HelloID users to HelloID groups. Success: $($addUserToGroupSuccess). Error: $($addUserToGroupError)"
            HID-Write-Summary -Event Information -Message "Added HelloID users to HelloID groups. Success: $($addUserToGroupSuccess). Error: $($addUserToGroupError)"
        }
    }
    else {
        HID-Write-Status -Event Warning -Message "DryRun: Would add [$(($newGroupMemberships | Measure-Object).Count)] HelloID users to HelloID groups"
        HID-Write-Status -Event Warning -Message "DryRun: Would add [$(($newGroupMemberships | Measure-Object).Count)] HelloID users to HelloID groups"
    }

    if ($removeMembers -eq $true) {
        $removeUserFromGroupSuccess = 0
        $removeUserFromGroupError = 0
        foreach ($obsoleteGroupMembership in $obsoleteGroupMemberships) {
            # Remove HelloID User from HelloID Group
            try {
                if ($verboseLogging -eq $true) {
                    HID-Write-Status -Event Information "Removing HelloID user [$($obsoleteGroupMembership.UserUsername) ($($obsoleteGroupMembership.UserId))] to HelloID group [$($obsoleteGroupMembership.GroupName) ($($obsoleteGroupMembership.GroupId))]"
                }

                $splatWebRequest = @{
                    Uri    = "groups/$($obsoleteGroupMembership.GroupId)/users/$($obsoleteGroupMembership.UserId)"
                    Method = 'DELETE'
                }

                if ($dryRun -eq $false) {
                    $removeUserToGroupResult = Invoke-HIDRestMethod @splatWebRequest
                    $removeUserFromGroupSuccess++

                    if ($verboseLogging -eq $true) {
                        HID-Write-Status -Event Success "Successfully removed HelloID user [$($obsoleteGroupMembership.UserUsername) ($($obsoleteGroupMembership.UserId))] to HelloID group [$($obsoleteGroupMembership.GroupName) ($($obsoleteGroupMembership.GroupId))]"
                    }
                }
                else {
                    if ($verboseLogging -eq $true) {
                        HID-Write-Status -Event Warning "DryRun: Would remove HelloID user [$($obsoleteGroupMembership.UserUsername) ($($obsoleteGroupMembership.UserId))] to HelloID group [$($obsoleteGroupMembership.GroupName) ($($obsoleteGroupMembership.GroupId))]"
                    }
                }
            }
            catch {
                $removeUserFromGroupError++

                $ex = $PSItem
                $errorMessage = Get-ErrorMessage -ErrorObject $ex
            
                HID-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
            
                throw "Error removing HelloID user [$($obsoleteGroupMembership.UserUsername) ($($obsoleteGroupMembership.UserId))] to HelloID group [$($obsoleteGroupMembership.GroupName) ($($obsoleteGroupMembership.GroupId))]. Error Message: $($errorMessage.AuditErrorMessage)"
            }
        }
        if ($dryRun -eq $false) {
            if ($removeUserFromGroupSuccess -ge 1 -or $removeUserFromGroupError -ge 1) {
                HID-Write-Status -Event Information -Message "Removed HelloID users from HelloID groups. Success: $($removeUserFromGroupSuccess). Error: $($removeUserFromGroupError)"
                HID-Write-Summary -Event Information -Message "Removed HelloID users from HelloID groups. Success: $($removeUserFromGroupSuccess). Error: $($removeUserFromGroupError)"
            }
        }
        else {
            HID-Write-Status -Event Warning -Message "DryRun: Would remove [$(($obsoleteGroupMemberships | Measure-Object).Count)] HelloID users from HelloID groups"
            HID-Write-Status -Event Warning -Message "DryRun: Would remove [$(($obsoleteProducts | Measure-Object).Count)] HelloID users from HelloID groups"
        }
    }
    else {
        HID-Write-Status -Event Warning -Message "Option to remove members is set to [$removeMembers]. Skipped removing [$(($obsoleteGroupMemberships | Measure-Object).Count)] HelloID users to HelloID groups"
    }

    if ($dryRun -eq $false) {
        HID-Write-Status -Event Success -Message "Successfully synchronized [$(($newGroupMemberships | Measure-Object).Count)] Exchange Online DB Group Owners to [$totalGroupMemberships] HelloID ResourceOwner Groupmemberships"
        HID-Write-Summary -Event Success -Message "Successfully synchronized [$(($newGroupMemberships | Measure-Object).Count)] Exchange Online DB Group Owners to [$totalGroupMemberships] HelloID ResourceOwner Groupmemberships"
    }
    else {
        HID-Write-Status -Event Success -Message "DryRun: Would synchronize [$(($newGroupMemberships | Measure-Object).Count)] Exchange Online DB Group Owners to [$totalGroupMemberships] HelloID ResourceOwner Groupmemberships"
        HID-Write-Summary -Event Success -Message "DryRun: Would synchronize [$(($newGroupMemberships | Measure-Object).Count)] Exchange Online DB Group Owners to [$totalGroupMemberships] HelloID ResourceOwner Groupmemberships"
    }
}
catch {
    HID-Write-Status -Event Error -Message "Error synchronization of [$(($newGroupMemberships | Measure-Object).Count)] Exchange Online DB Group Owners to [$totalGroupMemberships] HelloID ResourceOwner Groupmemberships"
    HID-Write-Status -Event Error -Message "Error at Line [$($_.InvocationInfo.ScriptLineNumber)]: $($_.InvocationInfo.Line)."
    HID-Write-Status -Event Error -Message "Exception message: $($_.Exception.Message)"
    HID-Write-Status -Event Error -Message "Exception details: $($_.errordetails)"
    HID-Write-Summary -Event Failed -Message "Error synchronization of [$(($newGroupMemberships | Measure-Object).Count)] Exchange Online DB Group Owners to [$totalGroupMemberships] HelloID ResourceOwner Groupmemberships"
}

#endregion