# API & Permissions Reference

Complete reference for Azure Sentinel API endpoints, authentication, and required permissions.

---

## Table of Contents
- [API Overview](#api-overview)
- [Authentication](#authentication)
- [API Endpoints](#api-endpoints)
- [Required Permissions](#required-permissions)
- [Role Definitions](#role-definitions)
- [Best Practices](#best-practices)

---

## API Overview

The Sentinel MITRE Analyzer uses the **Azure Resource Manager (ARM) REST API** to query analytical rules.

### Base Endpoint
```
https://management.azure.com
```

### API Resource URI
```
https://management.azure.com/subscriptions/{subscriptionId}/
resourceGroups/{resourceGroupName}/
providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/
providers/Microsoft.SecurityInsights/alertRules
```

### Supported API Versions
The module automatically tries these versions in order:
- `2024-09-01` (latest)
- `2024-03-01`
- `2023-12-01-preview`

---

## Authentication

### OAuth 2.0 Flow

The module uses Azure Active Directory (AAD) OAuth 2.0 authentication:

1. **User authenticates** via Az PowerShell or Azure CLI
2. **Access token is obtained** for `https://management.azure.com/` resource
3. **Token is passed** in Authorization header: `Bearer {token}`
4. **Token expires** after ~1 hour (must re-authenticate)

### Token Acquisition Methods

#### Method 1: Az PowerShell Module
```powershell
# Login
Connect-AzAccount

# Get token
$token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/").Token

# Token structure (SecureString in Az 9.0+)
if ($token -is [System.Security.SecureString]) {
    # Convert to plain text
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($token)
    $token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}
```

#### Method 2: Azure CLI
```bash
# Login
az login

# Get token
az account get-access-token --resource https://management.azure.com --query accessToken -o tsv
```

#### Method 3: Managed Identity (Azure VMs)
```powershell
# Automatic token retrieval from IMDS endpoint
$response = Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" -Headers @{Metadata="true"}
$token = $response.access_token
```

---

## API Endpoints

### 1. List Analytical Rules

**Endpoint:**
```
GET https://management.azure.com/subscriptions/{subscriptionId}/
    resourceGroups/{resourceGroupName}/
    providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/
    providers/Microsoft.SecurityInsights/alertRules
    ?api-version=2024-09-01
```

**Headers:**
```
Authorization: Bearer {access_token}
Content-Type: application/json
```

**Response Structure:**
```json
{
  "value": [
    {
      "id": "/subscriptions/.../alertRules/{ruleId}",
      "name": "{ruleId}",
      "type": "Microsoft.SecurityInsights/alertRules",
      "kind": "Scheduled",
      "properties": {
        "displayName": "Suspicious Login Activity",
        "enabled": true,
        "severity": "High",
        "tactics": ["InitialAccess", "CredentialAccess"],
        "techniques": ["T1078", "T1110"],
        "query": "SigninLogs | where ...",
        "queryFrequency": "PT5M",
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 0
      }
    }
  ],
  "nextLink": "https://...?$skiptoken=..."
}
```

### 2. Get Single Rule (Not Used by Analyzer)

**Endpoint:**
```
GET https://management.azure.com/.../alertRules/{ruleName}
    ?api-version=2024-09-01
```

### 3. Pagination

The API returns paginated results:
- **Default page size**: ~50 rules per page
- **nextLink**: Present when more data available
- **Module handles automatically**: Follows nextLink until null

**Example Pagination Handling:**
```powershell
$allRules = @()
$nextUrl = $initialUrl

do {
    $response = Invoke-RestMethod -Uri $nextUrl -Headers $headers
    $allRules += $response.value
    $nextUrl = $response.nextLink
} while ($nextUrl)
```

---

## Required Permissions

### Minimum Required Role

**Microsoft Sentinel Reader**
- **Scope**: Log Analytics Workspace
- **Permissions**: Read-only access to Sentinel data
- **Sufficient for**: This analyzer tool

### Resource Provider Requirements

Your subscription must have these resource providers registered:
- `Microsoft.OperationalInsights` (Log Analytics)
- `Microsoft.SecurityInsights` (Sentinel)

**Check registration:**
```powershell
Get-AzResourceProvider -ProviderNamespace Microsoft.SecurityInsights |
    Select-Object ProviderNamespace, RegistrationState
```

**Register if needed:**
```powershell
Register-AzResourceProvider -ProviderNamespace Microsoft.SecurityInsights
```

---

## Role Definitions

### 1. Microsoft Sentinel Reader

**Role ID:** `8d289c81-5878-46d4-8554-54e1e3d8b5cb`

**Permissions:**
```json
{
  "actions": [
    "Microsoft.SecurityInsights/*/read"
  ],
  "notActions": [],
  "dataActions": [],
  "notDataActions": []
}
```

**What you CAN do:**
- ✅ Read analytical rules
- ✅ View rule properties
- ✅ View MITRE mappings
- ✅ View incidents (read-only)
- ✅ View workbooks and dashboards

**What you CANNOT do:**
- ❌ Create/modify rules
- ❌ Enable/disable rules
- ❌ Delete rules
- ❌ Modify incidents

### 2. Microsoft Sentinel Responder

**Role ID:** `3e150937-b8fe-4cfb-8069-0eaf05ecd056`

**Includes:** All Reader permissions +
- Manage incidents
- Run playbooks
- Add comments

### 3. Microsoft Sentinel Contributor

**Role ID:** `ab8e14d6-4a74-4a29-9ba8-549422addade`

**Includes:** All Responder permissions +
- Create/modify rules
- Create/modify workbooks
- Manage data connectors

### Role Comparison Matrix

| Action | Reader | Responder | Contributor |
|--------|--------|-----------|-------------|
| View rules | ✅ | ✅ | ✅ |
| View MITRE data | ✅ | ✅ | ✅ |
| View incidents | ✅ | ✅ | ✅ |
| Manage incidents | ❌ | ✅ | ✅ |
| Modify rules | ❌ | ❌ | ✅ |
| Create rules | ❌ | ❌ | ✅ |
| Delete rules | ❌ | ❌ | ✅ |

---

## Best Practices

### 1. Least Privilege Principle
Use **Microsoft Sentinel Reader** role for this analyzer:
```powershell
New-AzRoleAssignment `
    -SignInName user@domain.com `
    -RoleDefinitionName "Microsoft Sentinel Reader" `
    -Scope $workspaceId
```

### 2. Service Principal for Automation

For CI/CD or scheduled runs, use a service principal:

```powershell
# Create service principal
$sp = New-AzADServicePrincipal -DisplayName "SentinelAnalyzerSP"

# Assign Reader role
New-AzRoleAssignment `
    -ObjectId $sp.Id `
    -RoleDefinitionName "Microsoft Sentinel Reader" `
    -Scope $workspaceId

# Login with service principal
$cred = Get-Credential  # Use AppId and Secret
Connect-AzAccount -ServicePrincipal -Credential $cred -Tenant $tenantId
```

### 3. Token Management

**Token Expiration:**
- Default: 1 hour
- **Best practice**: Re-authenticate before long-running operations

```powershell
# Check token expiration
$token = Get-AzAccessToken -ResourceUrl "https://management.azure.com/"
$token.ExpiresOn  # DateTime when token expires

# Refresh if needed
if ((Get-Date) -gt $token.ExpiresOn.AddMinutes(-5)) {
    Connect-AzAccount -Force
}
```

### 4. Rate Limiting

Azure ARM API has rate limits:
- **Read operations**: 12,000 per hour per subscription
- **Write operations**: 1,200 per hour per subscription

**This analyzer uses only read operations** and is well within limits.

### 5. Audit Logging

All API calls are logged in Azure Activity Log:

**View via PowerShell:**
```powershell
Get-AzActivityLog -StartTime (Get-Date).AddHours(-1) |
    Where-Object { $_.ResourceProvider -eq "Microsoft.SecurityInsights" } |
    Select-Object EventTimestamp, Caller, OperationName, Status
```

**View via Portal:**
1. Go to your Sentinel workspace
2. Click **Activity log** (left menu)
3. Filter by **Operation name**: "Get alert rules"

---

## Error Codes Reference

| Code | Meaning | Solution |
|------|---------|----------|
| 401 | Unauthorized | Token expired or invalid - re-authenticate |
| 403 | Forbidden | Missing RBAC permissions - request Reader role |
| 404 | Not Found | Invalid subscription/RG/workspace name |
| 429 | Too Many Requests | Rate limit hit - wait and retry |
| 500 | Internal Server Error | Azure service issue - retry later |

---

## API Request Examples

### Example: Get Rules with PowerShell

```powershell
# Setup
$subId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$rg = "my-sentinel-rg"
$ws = "my-workspace"
$apiVersion = "2024-09-01"

# Get token
$token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/").Token

# Build URL
$url = "https://management.azure.com/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$ws/providers/Microsoft.SecurityInsights/alertRules?api-version=$apiVersion"

# Call API
$headers = @{ "Authorization" = "Bearer $token" }
$response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get

# Process results
foreach ($rule in $response.value) {
    Write-Host "$($rule.properties.displayName) - Enabled: $($rule.properties.enabled)"
}
```

### Example: Get Rules with cURL

```bash
# Get token
TOKEN=$(az account get-access-token --resource https://management.azure.com --query accessToken -o tsv)

# Call API
curl -X GET \
  "https://management.azure.com/subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{ws}/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-09-01" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"
```

---

## Additional Resources

- [Azure Sentinel REST API Reference](https://docs.microsoft.com/en-us/rest/api/securityinsights/)
- [Azure RBAC Documentation](https://docs.microsoft.com/en-us/azure/role-based-access-control/)
- [Azure AD Authentication](https://docs.microsoft.com/en-us/azure/active-directory/develop/)

---

**Questions?** Open an issue on [GitHub](https://github.com/yourusername/sentinel-mitre-analyzer/issues)
