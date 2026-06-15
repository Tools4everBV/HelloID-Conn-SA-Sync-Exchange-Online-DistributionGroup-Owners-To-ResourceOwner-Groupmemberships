# HelloID-Conn-SA-Sync-Exchange-Online-DistributionGroup-Owners-To-ResourceOwner-Groupmemberships

> [!IMPORTANT]
> **Best Practice - Maximum Synchronization Frequency: Once per week**
>
> **Why this maximum?**
> Resource ownership changes infrequently (weekly or monthly). More frequent synchronization causes unnecessary processing load without business value, as owner changes rarely happen multiple times per week.
>
> If a higher frequency is required for your organization, please contact **Tools4ever Support**. This helps us understand your use case and provide proper guidance.

> [!IMPORTANT]  
> This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.

## Table of Contents
- [HelloID-Conn-SA-Sync-Exchange-Online-DistributionGroup-Owners-To-ResourceOwner-Groupmemberships](#helloid-conn-sa-sync-exchange-online-distributiongroup-owners-to-resourceowner-groupmemberships)
  - [Table of Contents](#table-of-contents)
  - [Requirements](#requirements)
  - [Introduction](#introduction)
  - [Getting started](#getting-started)
    - [Requirements](#requirements-1)
    - [App Registration \& Certificate Setup](#app-registration--certificate-setup)
    - [HelloID-specific configuration](#helloid-specific-configuration)
    - [Convert .pfx to base64 string](#convert-pfx-to-base64-string)
    - [Synchronization settings](#synchronization-settings)
  - [Remarks](#remarks)
  - [Getting help](#getting-help)
  - [HelloID Docs](#helloid-docs)

## Requirements
- Make sure you have Windows PowerShell 5.1 installed on the server where the HelloID agent and Service Automation agent are running.
- Installed and available **Microsoft Exchange Online PowerShell V3.1 module**. Please see the [Microsoft documentation](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps) for more information. The download [can be found here](https://www.powershellgallery.com/packages/ExchangeOnlineManagement/3.0.0).
- Required to run **On-Premises** since it is not allowed to import a module with the Cloud Agent.
- An **App Registration in Azure AD** is required.
- Make sure the sychronization is configured to meet your requirements.

## Introduction

By using this connector, you will have the ability to create and remove HelloID Groupmemberships based on the users who are owners of distribution groups in Exchange Online.

The groupmemberships will be granted for each user with full access to a distribution group in scope. This way you won't have to manually add the users to the resource owner group for each group.

And vice versa for the removing of the groupmemberships. The groupmemberships will be removed when a user no longer has owner rights to a distribution group. The removal of members is optional, as this removes the possibility to manually manage the users of these groups.

This is intended for scenarios where there are (lots of) distribution groups that we want to be requestable as a product. Currently, there is no corresponding productassignments sync for this distribution group sync.

This is intended for scenarios where the product sync automatically creates the self service products for distribution groups and creates a resource owner for these products. This groupmembership sync is designed to work in combination with the [Exchange Online Distribution Groups to Products Sync](https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-Exchange-Online-DistributionGroup-To-SelfService-Products) in the scenario where you'd want the users owner rights to act as the resource owner.

## Getting started

### Requirements

- Windows PowerShell 5.1 installed on the server where the HelloID agent and Service Automation agent are running
- **Microsoft Exchange Online PowerShell V3 module** installed and available. See the [Microsoft documentation](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps) for more information. The download [can be found here](https://www.powershellgallery.com/packages/ExchangeOnlineManagement)
- Required to run **On-Premises** (not supported with Cloud Agent due to module import requirements)
- An **App Registration in Microsoft Entra ID** configured with certificate-based authentication
- The synchronization must be configured to meet your requirements before scheduling

### App Registration & Certificate Setup

Before implementing this scheduled task, you must configure a Microsoft Entra ID App Registration. During the setup process, you'll create a new App Registration in the Entra portal, assign the necessary API permissions, and generate and assign a certificate.

Follow the official Microsoft documentation for creating an App Registration and setting up certificate-based authentication:

- [App-only authentication with certificate (Exchange Online)](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps#set-up-app-only-authentication)

### HelloID-specific configuration

Once you have completed the Microsoft setup and followed their best practices, configure the following HelloID-specific requirements.

**API Permissions** (Application permissions):
- `Exchange.ManageAsApp` - To read group information and manage group memberships

**Entra ID Role assignment:**
- Assign the **Exchange Administrator** role to the App Registration

**Certificate:**
- Upload the public key file (.cer) in Entra ID
- Provide the certificate as a Base64 string in HelloID

> [!NOTE]  
> For more information about the required permissions, please see the Microsoft docs:
> - [Permissions in Exchange Online](https://learn.microsoft.com/en-us/exchange/permissions-exo/permissions-exo)
> - [Find the permissions required to run any Exchange cmdlet](https://learn.microsoft.com/en-us/powershell/exchange/find-exchange-cmdlet-permissions?view=exchange-ps)
> - [View and assign administrator roles in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/manage-roles-portal)

### Convert .pfx to base64 string

HelloID requires a base64 string to import the certificate. Use the example below to create a base64 string:

```powershell
$filePath = 'C:\Cert'
$pfxCertName = 'Cert.pfx'
$pfxPath = "$filePath\$pfxCertName"

$fileContentBytes = [System.IO.File]::ReadAllBytes("$pfxPath")
[System.Convert]::ToBase64String($fileContentBytes) | Set-Content "$filePath\HelloID_Cert_Base64.txt"
```

### Synchronization settings
| Variable name                   | Description                                                                                                | Notes                                                                                                                                                                                                                                                                                                                                  |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| $portalBaseUrl                  | String value of HelloID Base Url                                                                           | (Default Global Variable)                                                                                                                                                                                                                                                                                                              |
| $portalApiKey                   | String value of HelloID Api Key                                                                            | (Default Global Variable)                                                                                                                                                                                                                                                                                                              |
| $portalApiSecret                | String value of HelloID Api Secret                                                                         | (Default Global Variable)                                                                                                                                                                                                                                                                                                              |
| $EntraIdOrganization            | The Entra ID Organization yourCompany.onmicrosoft.com                                                      | Recommended to set as Global Variable                                                                                                                                                                                                                                                                                                  |
| $EntraIdAppId                   | String value of Entra ID App ID                                                                            | Recommended to set as Global Variable                                                                                                                                                                                                                                                                                                  |
| $EntraIdCertificateBase64String | Base64 string of Entra ID App Certificate                                                                  | Recommended to set as Global Variable                                                                                                                                                                                                                                                                                                  |
| $EntraIdCertificatePassword     | Password of Entra ID App Certificate                                                                       | Recommended to set as Global Variable                                                                                                                                                                                                                                                                                                  |
| $exchangeGroupsFilter           | String value of seachfilter of which Exchange distribution groups to include                               | Optional, when no filter is provided ($exchangeGroupsFilter = $null), all groups will be queried. This should match the filter used in the configuration of the [Exchange Online Distribution Groups to Products Sync](https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-Exchange-Online-DistributionGroup-To-SelfService-Products) |
| $resourceOwnerGroupSource       | String value of source of the resource groups in HelloID                                                   | Ff source is any other than "Local", the sync of the target system itself might overwrite the memberships set form this sync                                                                                                                                                                                                           |
| $resourceOwnerGroupPrefix       | String value of prefix to recognize the resource owner group                                               | Optional, the owner group will be queried based on the distribution group name and the specified prefix and suffix                                                                                                                                                                                                                     |
| $resourceOwnerGroupSuffix       | String value of suffix to recognize the resource owner group                                               | Optional, the owner group will be queried based on the distribution group name and the specified prefix and suffix                                                                                                                                                                                                                     |
| $removeMembers                  | Boolean value of whether to remove the groupmemberships when they are no longer in scope. Default = $false |                                                                                                                                                                                                                                                                                                                                        |

## Remarks
- This Resource Owner sync is designed to work in combination with the [Exchange Online Distribution Groups to Products Sync](https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-Exchange-Online-DistributionGroup-To-SelfService-Products). If this is not configured, this sync task might not work (as the resource owner groups probably won't exist) and might need changes accordingly.

## Getting help
> _For more information on how to configure a HelloID PowerShell scheduled task, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/115003253294-Create-Custom-Scheduled-Tasks) pages_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
