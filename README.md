<!-- Description -->
## Description
This script will to extend the users already synchronized from Built-in AzureAD Directory [AzureAD Directory](https://docs.helloid.com/hc/en-us/articles/360013386020).
By default, the EmployeeId isn't included in this synchronization. This script is therefore meant to synchronize the EmployeeId of the AzureAD user to the corresponding HelloID User.
In some cases it is required to have the EmployeeId in HelloID, e.g. for SSO or the use of the [Rolemodel scripts](https://github.com/Tools4everBV/HelloID-Conn-Prov-Source-HelloID-RoleModel).

## Versioning
| Version | Description | Date |
| - | - | - |
| 1.0.0   | Initial release | 2021/12/20  |

<!-- TABLE OF CONTENTS -->
## Table of Contents
- [Table of Contents](#table-of-contents)
- [Introduction](#introduction)
- [Getting the Azure AD graph API access](#getting-the-azure-ad-graph-api-access)
  - [Application Registration](#application-registration)
  - [Configuring App Permissions](#configuring-app-permissions)
  - [Authentication and Authorization](#authentication-and-authorization)
  - [Connection settings](#connection-settings)
- [Getting help](#getting-help)
- [HelloID Docs](#helloid-docs)

<!-- GETTING STARTED -->
## Getting the Azure AD graph API access

By using this connector you will have the ability to manage Azure AD Guest accounts.

### Application Registration
The first step to connect to Graph API and make requests, is to register a new <b>Azure Active Directory Application</b>. The application is used to connect to the API and to manage permissions.

* Navigate to <b>App Registrations</b> in Azure, and select “New Registration” (<b>Azure Portal > Azure Active Directory > App Registration > New Application Registration</b>).
* Next, give the application a name. In this example we are using “<b>HelloID PowerShell</b>” as application name.
* Specify who can use this application (<b>Accounts in this organizational directory only</b>).
* Specify the Redirect URI. You can enter any url as a redirect URI value. In this example we used http://localhost because it doesn't have to resolve.
* Click the “<b>Register</b>” button to finally create your new application.

Some key items regarding the application are the Application ID (which is the Client ID), the Directory ID (which is the Tenant ID) and Client Secret.

### Configuring App Permissions
The [Microsoft Graph documentation](https://docs.microsoft.com/en-us/graph) provides details on which permission are required for each permission type.

To assign your application the right permissions, navigate to <b>Azure Portal > Azure Active Directory >App Registrations</b>.
Select the application we created before, and select “<b>API Permissions</b>” or “<b>View API Permissions</b>”.
To assign a new permission to your application, click the “<b>Add a permission</b>” button.
From the “<b>Request API Permissions</b>” screen click “<b>Microsoft Graph</b>”.
For this connector the following permissions are used as <b>Application permissions</b>:
*	Read and Write all user’s full profiles by using <b><i>User.ReadWrite.All</i></b>
*	Read and Write all groups in an organization’s directory by using <b><i>Group.ReadWrite.All</i></b>
*	Read and Write data to an organization’s directory by using <b><i>Directory.ReadWrite.All</i></b>

Some high-privilege permissions can be set to admin-restricted and require an administrators consent to be granted.

To grant admin consent to our application press the “<b>Grant admin consent for TENANT</b>” button.

### Authentication and Authorization
There are multiple ways to authenticate to the Graph API with each has its own pros and cons, in this example we are using the Authorization Code grant type.

*	First we need to get the <b>Client ID</b>, go to the <b>Azure Portal > Azure Active Directory > App Registrations</b>.
*	Select your application and copy the Application (client) ID value.
*	After we have the Client ID we also have to create a <b>Client Secret</b>.
*	From the Azure Portal, go to <b>Azure Active Directory > App Registrations</b>.
*	Select the application we have created before, and select "<b>Certificates and Secrets</b>". 
*	Under “Client Secrets” click on the “<b>New Client Secret</b>” button to create a new secret.
*	Provide a logical name for your secret in the Description field, and select the expiration date for your secret.
*	It's IMPORTANT to copy the newly generated client secret, because you cannot see the value anymore after you close the page.
*	At last we need to get is the <b>Tenant ID</b>. This can be found in the Azure Portal by going to <b>Azure Active Directory > Custom Domain Names</b>, and then finding the .onmicrosoft.com domain.

### Connection settings
The following settings are required to connect to the API.

| Setting     | Description |
| ------------ | ----------- |
| Azure AD Tenant ID | Id of the Azure tenant |
| Azure AD App ID | Id of the Azure app |
| Azure AD App Secret | Secret of the Azure app |

### Script variables
| Variable name | Description   | Example value |
| -| -  | - |
| portalBaseUrl | Base URI of the HelloID environment (filled by default in HelloID SA) | 	https://enyoi.helloid.com   |
| portalApiKey  | API key of the HelloID environment (filled by default in HelloID SA)  |   ABCDEFGHIJLMNOPUGYPQVLSSU   |
| portalApiSecret   | API Secret of the HelloID environment (filled by default in HelloID SA)  |   JrGpGNhijklQLChhsmABCDEFE   |
| HelloIDUserSource | Source of the HelloID users (by default this is and should be 'AzureAD', since this script is meant to sync the employeeId to users from the source AzureAD, but in theory this can be another source) | 	AzureAD   |
| HelloIDUserExclusionFilter  | Wildcard value to exclude HelloID users in the sync (note: only 1 filter should be used, either the include or exclude, not both!) |   adm_   |
| HelloIDUserInclusionFilter  | Wildcard value to include HelloID users in the sync (note: only 1 filter should be used, either the include or exclude, not both!)  |  test_   |
| AADtenantID | Id of the Azure tenant | 	12ab345c-0c41-4cde-9908-dabf3cad26b6   |
| AADAppId  | Id of the Azure app  |   12ab123c-fe99-4bdc-8d2e-87405fdb2379   |
| AADAppSecret   |  Secret of the Azure app  |   AB01C~DeFgHijkLMN.k-11AVdZSRzVnltkPqr   |
| AADUserExclusionFilter  | Wildcard value to exclude AzureAD users in the sync (note: only 1 filter should be used, either the include or exclude, not both!) |   "#EXT#"   |
| AADUserInclusionFilter  | Wildcard value to include AzureAD users in the sync (note: only 1 filter should be used, either the include or exclude, not both!)  |  test_   |

## Remarks
- The users are only updated, no update or deletion will take place.
    > If you want to create Azure accounts, please use the built-in [AzureAD Directory](https://docs.helloid.com/hc/en-us/articles/360013386020).
    > When the employeeId is already the same in HelloID as in AzureAD, the users will be skipped (no update will take place), this is to limit the amount of calls performed.

- This script is meant to be run in HelloID Service Automation as a Scheduled task.
    > Therefore it uses the cmds Hid-Write-Status en Hid-Write-Summary for logging in HelloID. This will not work in anything other than HelloID Service Automation.

## Getting help
_If you need help, feel free to ask questions on our [forum](https://forum.helloid.com/forum/helloid-connectors/service-automation/678-helloid-sa-sync-helloid-azuread-employeeid-to-helloid-users)_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
