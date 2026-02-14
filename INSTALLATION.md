# Installation Guide

This guide provides detailed installation instructions for the Sentinel MITRE ATT&CK Coverage Analyzer.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Installation Methods](#installation-methods)
- [Azure Setup](#azure-setup)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### 1. PowerShell

**Check your version:**
```powershell
$PSVersionTable.PSVersion
```

**Required:** Version 5.1 or later

**Install/Update PowerShell:**
- **Windows**: PowerShell 5.1 is pre-installed on Windows 10/11
- **Cross-platform**: Install [PowerShell 7.x](https://github.com/PowerShell/PowerShell#get-powershell)

### 2. Azure Authentication

Choose **ONE** of the following:

#### Option A: Azure PowerShell Module (Recommended)

```powershell
# Install Az module
Install-Module Az -Scope CurrentUser -Force -AllowClobber

# Verify installation
Get-Module Az -ListAvailable

# Import module
Import-Module Az
```

#### Option B: Azure CLI

**Download from:** [Azure CLI Installation](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)

**Verify installation:**
```powershell
az --version
```

### 3. Azure Permissions

Ensure you have **Microsoft Sentinel Reader** role (or higher) on the target workspace.

---

## Installation Methods

### Method 1: Git Clone (Recommended)

```powershell
# Clone the repository
git clone https://github.com/yourusername/sentinel-mitre-analyzer.git

# Navigate to the directory
cd sentinel-mitre-analyzer

# Import the module
Import-Module .\SentinelMITREAnalyzer.psm1
```

### Method 2: Direct Download

1. Download the latest release from [Releases](https://github.com/yourusername/sentinel-mitre-analyzer/releases)
2. Extract the ZIP file
3. Open PowerShell and navigate to the extracted folder
4. Import the module:

```powershell
Import-Module .\SentinelMITREAnalyzer.psm1
```

### Method 3: PowerShell Modules Directory

```powershell
# Create module directory
$modulePath = "$HOME\Documents\PowerShell\Modules\SentinelMITREAnalyzer"
New-Item -ItemType Directory -Path $modulePath -Force

# Copy files
Copy-Item .\SentinelMITREAnalyzer.psm1, .\SentinelMITREAnalyzer.psd1 -Destination $modulePath

# Module will auto-load when you use the command
Get-SentinelAnalyticalRulesReport
```

---

## Azure Setup

### Step 1: Find Your Sentinel Workspace Details

#### Via Azure Portal
1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to **Azure Sentinel**
3. Select your workspace
4. Note down:
   - **Subscription ID** (from the Overview page)
   - **Resource Group** (from the Overview page)
   - **Workspace Name** (from the top of the page)

#### Via PowerShell
```powershell
# Login to Azure
Connect-AzAccount

# List all Sentinel workspaces
Get-AzOperationalInsightsWorkspace | 
    Select-Object Name, ResourceGroupName, 
    @{N='SubscriptionId';E={(Get-AzContext).Subscription.Id}} |
    Format-Table
```

#### Via Azure CLI
```bash
# Login
az login

# List workspaces
az monitor log-analytics workspace list --output table
```

### Step 2: Verify Permissions

#### Check Your Role Assignment

**Via PowerShell:**
```powershell
# Get your current user ID
$userId = (Get-AzContext).Account.Id

# Check role assignments
Get-AzRoleAssignment -SignInName $userId | 
    Where-Object { $_.RoleDefinitionName -like "*Sentinel*" -or 
                   $_.RoleDefinitionName -like "*Reader*" } |
    Select-Object RoleDefinitionName, Scope |
    Format-Table
```

**Via Azure CLI:**
```bash
# Get your account
az account show --query user.name -o tsv

# List role assignments
az role assignment list --assignee user@domain.com --output table
```
---

## Verification

### Verify Installation

```powershell
# Check if module is loaded
Get-Module SentinelMITREAnalyzer

# Check available commands
Get-Command -Module SentinelMITREAnalyzer

# View help
Get-Help Get-SentinelAnalyticalRulesReport -Full
```

### Test Authentication

```powershell
# For Az PowerShell
Connect-AzAccount
Get-AzContext

# For Azure CLI
az login
az account show
```

### Test API Access

```powershell
# Replace with your details
$subId = "your-subscription-id"
$rg = "your-resource-group"
$ws = "your-workspace-name"

# Get access token
$token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/").Token

# Build API URL
$url = "https://management.azure.com/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$ws/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-09-01"

# Test API call
$headers = @{ "Authorization" = "Bearer $token" }
$response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get

# Check results
Write-Host "Found $($response.value.Count) analytical rules" -ForegroundColor Green
```

---

## Troubleshooting

### Issue: Module Import Fails

**Error:** `Import-Module : The specified module 'SentinelMITREAnalyzer' was not loaded`

**Solution:**
```powershell
# Use full path
Import-Module "C:\path\to\SentinelMITREAnalyzer.psm1" -Force

# Or navigate to the directory first
cd C:\path\to\module
Import-Module .\SentinelMITREAnalyzer.psm1
```

### Issue: Execution Policy Error

**Error:** `cannot be loaded because running scripts is disabled`

**Solution:**
```powershell
# Check current policy
Get-ExecutionPolicy

# Set for current user (recommended)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Or bypass for single session
powershell -ExecutionPolicy Bypass -File script.ps1
```

### Issue: Az Module Not Found

**Error:** `Get-AzContext : The term 'Get-AzContext' is not recognized`

**Solution:**
```powershell
# Install Az module
Install-Module Az -Scope CurrentUser -Force -AllowClobber

# If behind proxy
$proxyUrl = "http://proxy.company.com:8080"
Install-Module Az -Proxy $proxyUrl -Scope CurrentUser
```

---

## Next Steps

Once installed, proceed to the [Quick Start Guide](../README.md#quick-start) to run your first analysis!

---
