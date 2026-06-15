#####################################################
# HelloID-Conn-SA-Sync-EXO-DistributionGroup-Owners-To-ResourceOwner-Groupmemberships
#
# Version: 1.1.0
#####################################################
# Set to false to actually perform actions - Only run as DryRun when testing/troubleshooting!
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
# HelloID API connection (required)
# $helloIDPortalBaseUrl = $portalBaseUrl # When running from HelloID, set from default Global Variable
# $helloIDPortalApiKey = $portalApiKey # When running from HelloID, set from default Global Variable
# $helloIDPortalApiSecret = $portalApiSecret # When running from HelloID, set from default Global Variable

# Exchange Online connection (required)
# $EntraIdOrganization = "" # Set from Global Variable
# $EntraIdAppId = "" # Set from Global Variable
# $EntraIdCertificateBase64String = "" # Set from Global Variable
# $EntraIdCertificatePassword = "" # Set from Global Variable
 
$exchangeGroupsFilter = "DisplayName -like 'DistributionGroup*'" # Optional, when no filter is provided ($exchangeGroupsFilter = $null), all groups will be queried

# PowerShell commands to import
$commands = @(
    "Get-User"
    , "Get-DistributionGroup"
) # Fixed list of commands required by script - only change when missing commands

#HelloID Configuration
$resourceOwnerGroupSource = "Local" # Specify the source of the groups - if source is any other than "Local", the sync of the target system itself might overwrite the memberships set form this sync
# The HelloID Resource owner group will be queried based on the distribution group name and the specified prefix and suffix
$resourceOwnerGroupPrefix = "" # Specify prefix to recognize the resource owner group
$resourceOwnerGroupSuffix = " Resource Owner" # Specify suffix to recognize the resource owner group
$removeMembers = $true # If true, existing members will be removed if they no longer have full access to the corresponding mailbox - This will overwrite manual added users

#region functions
function Write-StatusMessage {
    <#
    .SYNOPSIS
    Writes a status message to the appropriate logging system.
    
    .DESCRIPTION
    When running locally: Uses native PowerShell cmdlets (Write-Information, Write-Warning, Write-Error)
    When running in HelloID: Uses HelloID's native Hid-Write-Status function
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Message,

        [Parameter(Mandatory = $true)]
        [String]
        $Event
    )
    
    if ($null -eq $portalBaseUrl) {
        # Running locally - use native PowerShell cmdlets
        switch ($Event) {
            "Information" { Write-Information ($Message) -InformationAction Continue }
            "Warning" { Write-Warning ($Message) -WarningAction Continue }
            "Success" { Write-Information ($Message) -InformationAction Continue }
            "Error" { Write-Error ($Message) -ErrorAction Continue }
            "Critical" { Write-Error ($Message) -ErrorAction Continue }
            "Failed" { Write-Error ($Message) -ErrorAction Continue }
        }
    }
    else {
        # Running in HelloID - use native HelloID function
        Hid-Write-Status -Message $Message -Event $Event
    }
}

function Write-SummaryMessage {
    <#
    .SYNOPSIS
    Writes a summary message to the appropriate logging system.
    
    .DESCRIPTION
    When running locally: Uses native PowerShell cmdlets (Write-Information, Write-Warning, Write-Error)
    When running in HelloID: Uses HelloID's native Hid-Write-Summary function
    #>
    [cmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Message,

        [Parameter(Mandatory = $true)]
        [String]
        $Event
    )
    
    if ($null -eq $portalBaseUrl) {
        # Running locally - use native PowerShell cmdlets
        switch ($Event) {
            "Information" { Write-Information ($Message) -InformationAction Continue }
            "Warning" { Write-Warning ($Message) -WarningAction Continue }
            "Success" { Write-Information ($Message) -InformationAction Continue }
            "Error" { Write-Error ($Message) -ErrorAction Continue }
            "Critical" { Write-Error ($Message) -ErrorAction Continue }
            "Failed" { Write-Error ($Message) -ErrorAction Continue }
        }
    }
    else {
        # Running in HelloID - use native HelloID function
        Hid-Write-Summary -Message $Message -Event $Event
    }
}

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
        $apiKeySecret = "$($helloIDPortalApiKey):$($helloIDPortalApiSecret)"
        $base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($apiKeySecret))
        $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
        $headers.Add("Authorization", "Basic $base64")
        $headers.Add("Content-Type", $ContentType)
        $headers.Add("Accept", $ContentType)

        $splatWebRequest = @{
            Uri             = "$($helloIDPortalBaseUrl)/api/v1/$($Uri)"
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
                $splatWebRequest["Uri"] = "$($helloIDPortalBaseUrl)/api/v1/$($Uri)?skip=$($skip)&take=$($take)"

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

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $CertificateBase64String,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $CertificatePassword
    )
    try {
        $rawCertificate = [system.convert]::FromBase64String($CertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $CertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
#endregion functions

#region script
Write-StatusMessage -Event Information -Message "Starting synchronization of Exchange Online Distribution Group Owners to Distributiongroup to HelloID ResourceOwner Groupmemberships"
Write-StatusMessage -Event Information -Message "------[Exchange Online]-----------"

# Import module
try {    
    $actionMessage = "importing module [ExchangeOnlineManagement]"
    $importModuleSplatParams = @{
        Name        = "ExchangeOnlineManagement"
        Cmdlet      = $commands
        Verbose     = $false
        ErrorAction = "Stop"
    }
    $null = Import-Module @importModuleSplatParams

    #region Retrieving certificate
    $actionMessage = "retrieving certificate"
    $certificate = Get-MSEntraCertificate -CertificateBase64String $EntraIdCertificateBase64String -CertificatePassword $EntraIdCertificatePassword
    #endregion Retrieving certificate
    
    #region Connect to Microsoft Exchange Online
    # Docs: https://learn.microsoft.com/en-us/powershell/module/exchange/connect-exchangeonline?view=exchange-ps
    $actionMessage = "connecting to Microsoft Exchange Online"
    $createExchangeSessionSplatParams = @{
        Organization          = $EntraIdOrganization
        AppID                 = $EntraIdAppId
        Certificate           = $certificate
        CommandName           = $commands
        ShowBanner            = $false
        ShowProgress          = $false
        TrackPerformance      = $false
        SkipLoadingCmdletHelp = $true
        SkipLoadingFormatData = $true
        ErrorAction           = "Stop"
    }
    $null = Connect-ExchangeOnline @createExchangeSessionSplatParams
    Write-Information "Connected to Microsoft Exchange Online"
} 
catch {
    $ex = $PSItem
    if (-not [string]::IsNullOrEmpty($ex.Exception.Data.RemoteException.Message)) {
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Data.RemoteException.Message)"
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Data.RemoteException.Message)"        
    }
    else {
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
    }
    Write-StatusMessage -Event Error -Message $warningMessage
    Write-StatusMessage -Event Error -Message $auditMessage
    throw $auditMessage
}

# Get Exchange Online Distribution groups
try {  
    $exchangeQuerySplatParams = @{
        Filter      = $exchangeGroupsFilter
        ResultSize  = "Unlimited"
        Verbose     = $false
        ErrorAction = "Stop"
    }

    Write-StatusMessage -Event Information -Message "Querying Exchange Online Distribution Groups that match filter [$($exchangeQuerySplatParams.Filter)]"
    $exoDBGroups = Get-DistributionGroup @exchangeQuerySplatParams

    if (($exoDBGroups | Measure-Object).Count -eq 0) {
        throw "No Distribution groups have been found"
    }

    Write-StatusMessage -Event Success -Message "Successfully queried Exchange Online Distribution Groups. Result count: $(($exoDBGroups | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-StatusMessage -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

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

    $exoUsersGroupedOnId = $exoUsers | Group-Object Id -AsHashTable
    Write-StatusMessage -Event Success -Message "Successfully queried Exchange Online Users. Result count: $(($exoUsers | Measure-Object).Count)"
}
catch { 
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-StatusMessage -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
    throw "Error querying all Exchange users. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Get Exchange online groups

Write-StatusMessage -Event Information -Message "------[HelloID]------"
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

    Write-StatusMessage -Event Success -Message "Successfully queried Users from HelloID. Result count: $(($helloIDUsers | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-StatusMessage -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

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

    Write-StatusMessage -Event Success -Message "Successfully queried Groups from HelloID. Result count: $(($helloIDGroups | Measure-Object).Count)"

    $helloIDGroups = $helloIDGroups | Where-Object { $_.source -eq $resourceOwnerGroupSource -and $_.name -like "$resourceOwnerGroupPrefix*$resourceOwnerGroupSuffix" }
    
    Write-StatusMessage -Event Success -Message "Successfully queried Groups from HelloID. Result count after filtering [source] = [$resourceOwnerGroupSource] and [name] = [$($resourceOwnerGroupPrefix)*$($resourceOwnerGroupSuffix)]: $(($helloIDGroups | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-StatusMessage -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

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
                Write-Verbose "Successfully queried HelloID group [$($helloIDGroup.name) ($($helloIDGroup.groupGuid))] with members. Result count: $(($helloIDGroup.users | Measure-Object).Count)"
            }
        }
        catch {
            $ex = $PSItem
            $errorMessage = Get-ErrorMessage -ErrorObject $ex
        
            Write-StatusMessage -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
        
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

    Write-StatusMessage -Event Success -Message "Successfully queried HelloID groups with members. Result count: $(($helloIDGroupsWithMembers.users | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-StatusMessage -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying HelloID users that are member of HelloID groups. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregionGet members of HelloID groups

Write-StatusMessage -Event Information -Message "------[Calculations of combined data]------"
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
                    Write-Verbose "Resource owner group [$($resourceOwnerGroupName)] for Distribution Group not found in HelloID"
                }

                # Skip further actions for this record
                Continue
            }
        }
        else {
            if ($verboseLogging -eq $true) {
                Write-Verbose "No Resource owner group name provided for Distribution Group"
            }
        }

        # Define existing groupmemberships
        foreach ($helloIDResourceOwnerGroupUser in $helloIDResourceOwnerGroup.Users) {
            # Get HelloID User
            $helloIDUser = $null
            $helloIDUser = $helloIDUsersGroupedOnUserGUID["$($helloIDResourceOwnerGroupUser)"]
            if ($null -eq $helloIDUser) {
                if ($verboseLogging -eq $true) {
                    Write-Verbose "No HelloID user found for Exchange User Resource owner group [$($helloIDResourceOwnerGroupUser)]"
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

            $exoDBGroupOwnerFullUser = $exoUsersGroupedOnId["$exoDBGroupOwner"]

            if (-not[string]::IsNullOrEmpty($exoDBGroupOwnerFullUser.UserPrincipalName)) {
                $helloIDUser = $helloIDUsersGroupedOnUserName["$($exoDBGroupOwnerFullUser.UserPrincipalName)"]
                if ($null -eq $helloIDUser) {
                    if ($verboseLogging -eq $true) {
                        Write-Verbose "No HelloID user found for Exchange User [$($exoDBGroupOwnerFullUser.UserPrincipalName)]"
                    }

                    # Skip further actions for this record
                    Continue
                }
            }
            else {
                if ($verboseLogging -eq $true) {
                    Write-Verbose "No UserPrincipalName provided for full access user [$($exoDBGroupOwnerFullUser.Id)]"
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

    $existingGroupMembershipObjects | Add-Member -MemberType NoteProperty -Name MembershipKey -Value $null -Force
    $existingGroupMembershipObjects | ForEach-Object { $_.MembershipKey = "$($_.GroupId)|$($_.UserId)" }

    $newGroupMembershipObjects | Add-Member -MemberType NoteProperty -Name MembershipKey -Value $null -Force
    $newGroupMembershipObjects | ForEach-Object { $_.MembershipKey = "$($_.GroupId)|$($_.UserId)" }

    # Define new group memberships
    $newGroupMemberships = [System.Collections.ArrayList]@()
    $newGroupMemberships = $newGroupMembershipObjects | Where-Object { $_.MembershipKey -notin $existingGroupMembershipObjects.MembershipKey }

    # Define obsolete group memberships
    $obsoleteGroupMemberships = [System.Collections.ArrayList]@()
    $obsoleteGroupMemberships = $existingGroupMembershipObjects | Where-Object { $_.MembershipKey -notin $newGroupMembershipObjects.MembershipKey }

    # Define existing group memberships
    $existingGroupMemberships = [System.Collections.ArrayList]@()
    $existingGroupMemberships = $existingGroupMembershipObjects | Where-Object { $_.MembershipKey -in $newGroupMembershipObjects.MembershipKey }

    # Define total groupmemberships (existing + new)
    $totalGroupMemberships = ($(($existingGroupMemberships | Measure-Object).Count) + $(($newGroupMemberships | Measure-Object).Count))
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-StatusMessage -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error calculating new and obsolete groupmemberships. Error Message: $($errorMessage.AuditErrorMessage)"
}


Write-StatusMessage -Event Information -Message "------[Summary]------"

Write-StatusMessage -Event Information -Message "New HelloID Resource Owner Groupmembership(s) that will be granted [$(($newGroupMemberships | Measure-Object).Count)]"

if ($removeMembers) {
    Write-StatusMessage -Event Information "Obsolete HelloID Resource Owner Groupmembership(s) that will be revoked [$(($obsoleteGroupMemberships | Measure-Object).Count)]"
}
else {
    Write-StatusMessage -Event Information -Message "Obsolete HelloID Resource Owner Groupmembership(s) that won't be revoked [$(($obsoleteGroupMemberships | Measure-Object).Count)]"
}


Write-StatusMessage -Event Information -Message "------[Processing]------------------"


try {
    $addUserToGroupSuccess = 0
    $addUserToGroupError = 0
    foreach ($newGroupMembership in $newGroupMemberships) {
        # Add HelloID User to HelloID Group
        try {
            if ($verboseLogging -eq $true) {
                Write-Verbose "Adding HelloID user [$($newGroupMembership.UserUsername) ($($newGroupMembership.UserId))] to HelloID group [$($newGroupMembership.GroupName) ($($newGroupMembership.GroupId))]"
            }

            if ($($newGroupMembership.UserId) -ne "") {
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
                        Write-Verbose "Successfully added HelloID user [$($newGroupMembership.UserUsername) ($($newGroupMembership.UserId))] to HelloID group [$($newGroupMembership.GroupName) ($($newGroupMembership.GroupId))]"
                    }
                }
                else {
                    if ($verboseLogging -eq $true) {
                        Write-Verbose "DryRun: Would add HelloID user [$($newGroupMembership.UserUsername) ($($newGroupMembership.UserId))] to HelloID group [$($newGroupMembership.GroupName) ($($newGroupMembership.GroupId))]"
                    }
                }
                
            }
            else {
                Write-StatusMessage -Event Warning -Message "Adding user [$($newGroupMembership)] to Resource group failed, because user was not found. [$($newGroupMembership.GroupName) ($($newGroupMembership.GroupId))] "
                $addUserToGroupError++
            }
            
        }
        catch {
            $addUserToGroupError++

            $ex = $PSItem
            $errorMessage = Get-ErrorMessage -ErrorObject $ex
            
            Write-StatusMessage -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
            
            throw "Error adding HelloID user [$($newGroupMembership.UserUsername) ($($newGroupMembership.UserId))] to HelloID group [$($newGroupMembership.GroupName) ($($newGroupMembership.GroupId))]. Error Message: $($errorMessage.AuditErrorMessage)"
        }
    }
    if ($dryRun -eq $false) {
        if ($addUserToGroupSuccess -ge 1 -or $addUserToGroupError -ge 1) {
            Write-StatusMessage -Event Information -Message "Added HelloID users to HelloID groups. Success: $($addUserToGroupSuccess). Error: $($addUserToGroupError)"
            Write-SummaryMessage -Event Information -Message "Added HelloID users to HelloID groups. Success: $($addUserToGroupSuccess). Error: $($addUserToGroupError)"
        }
    }
    else {
        Write-StatusMessage -Event Warning -Message "DryRun: Would add [$(($newGroupMemberships | Measure-Object).Count)] HelloID users to HelloID groups"
        Write-SummaryMessage -Event Warning -Message "DryRun: Would add [$(($newGroupMemberships | Measure-Object).Count)] HelloID users to HelloID groups"
    }

    if ($removeMembers -eq $true) {
        $removeUserFromGroupSuccess = 0
        $removeUserFromGroupError = 0
        foreach ($obsoleteGroupMembership in $obsoleteGroupMemberships) {
            # Remove HelloID User from HelloID Group
            try {
                if ($verboseLogging -eq $true) {
                    Write-Verbose "Removing HelloID user [$($obsoleteGroupMembership.UserUsername) ($($obsoleteGroupMembership.UserId))] to HelloID group [$($obsoleteGroupMembership.GroupName) ($($obsoleteGroupMembership.GroupId))]"
                }

                $splatWebRequest = @{
                    Uri    = "groups/$($obsoleteGroupMembership.GroupId)/users/$($obsoleteGroupMembership.UserId)"
                    Method = 'DELETE'
                }

                if ($dryRun -eq $false) {
                    $removeUserToGroupResult = Invoke-HIDRestMethod @splatWebRequest
                    $removeUserFromGroupSuccess++

                    if ($verboseLogging -eq $true) {
                        Write-Verbose "Successfully removed HelloID user [$($obsoleteGroupMembership.UserUsername) ($($obsoleteGroupMembership.UserId))] to HelloID group [$($obsoleteGroupMembership.GroupName) ($($obsoleteGroupMembership.GroupId))]"
                    }
                }
                else {
                    if ($verboseLogging -eq $true) {
                        Write-Verbose "DryRun: Would remove HelloID user [$($obsoleteGroupMembership.UserUsername) ($($obsoleteGroupMembership.UserId))] to HelloID group [$($obsoleteGroupMembership.GroupName) ($($obsoleteGroupMembership.GroupId))]"
                    }
                }
            }
            catch {
                $removeUserFromGroupError++

                $ex = $PSItem
                $errorMessage = Get-ErrorMessage -ErrorObject $ex
            
                Write-StatusMessage -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
            
                throw "Error removing HelloID user [$($obsoleteGroupMembership.UserUsername) ($($obsoleteGroupMembership.UserId))] to HelloID group [$($obsoleteGroupMembership.GroupName) ($($obsoleteGroupMembership.GroupId))]. Error Message: $($errorMessage.AuditErrorMessage)"
            }
        }
        if ($dryRun -eq $false) {
            if ($removeUserFromGroupSuccess -ge 1 -or $removeUserFromGroupError -ge 1) {
                Write-StatusMessage -Event Information -Message "Removed HelloID users from HelloID groups. Success: $($removeUserFromGroupSuccess). Error: $($removeUserFromGroupError)"
                Write-SummaryMessage -Event Information -Message "Removed HelloID users from HelloID groups. Success: $($removeUserFromGroupSuccess). Error: $($removeUserFromGroupError)"
            }
        }
        else {
            Write-StatusMessage -Event Warning -Message "DryRun: Would remove [$(($obsoleteGroupMemberships | Measure-Object).Count)] HelloID users from HelloID groups"
            Write-StatusMessage -Event Warning -Message "DryRun: Would remove [$(($obsoleteProducts | Measure-Object).Count)] HelloID users from HelloID groups"
        }
    }
    else {
        Write-StatusMessage -Event Warning -Message "Option to remove members is set to [$removeMembers]. Skipped removing [$(($obsoleteGroupMemberships | Measure-Object).Count)] HelloID users to HelloID groups"
    }

    if ($dryRun -eq $false) {
        Write-StatusMessage -Event Success -Message "Successfully synchronized [$(($newGroupMemberships | Measure-Object).Count)] Exchange Online DB Group Owners to [$totalGroupMemberships] HelloID ResourceOwner Groupmemberships"
        Write-SummaryMessage -Event Success -Message "Successfully synchronized [$(($newGroupMemberships | Measure-Object).Count)] Exchange Online DB Group Owners to [$totalGroupMemberships] HelloID ResourceOwner Groupmemberships"
    }
    else {
        Write-StatusMessage -Event Success -Message "DryRun: Would synchronize [$(($newGroupMemberships | Measure-Object).Count)] Exchange Online DB Group Owners to [$totalGroupMemberships] HelloID ResourceOwner Groupmemberships"
        Write-SummaryMessage -Event Success -Message "DryRun: Would synchronize [$(($newGroupMemberships | Measure-Object).Count)] Exchange Online DB Group Owners to [$totalGroupMemberships] HelloID ResourceOwner Groupmemberships"
    }
}
catch {
    Write-StatusMessage -Event Error -Message "Error synchronization of [$(($newGroupMemberships | Measure-Object).Count)] Exchange Online DB Group Owners to [$totalGroupMemberships] HelloID ResourceOwner Groupmemberships"
    Write-StatusMessage -Event Error -Message "Error at Line [$($_.InvocationInfo.ScriptLineNumber)]: $($_.InvocationInfo.Line)."
    Write-StatusMessage -Event Error -Message "Exception message: $($_.Exception.Message)"
    Write-StatusMessage -Event Error -Message "Exception details: $($_.errordetails)"
    Write-SummaryMessage -Event Failed -Message "Error synchronization of [$(($newGroupMemberships | Measure-Object).Count)] Exchange Online DB Group Owners to [$totalGroupMemberships] HelloID ResourceOwner Groupmemberships"
}

#endregion
