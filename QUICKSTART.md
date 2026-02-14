# Quick Start Guide

Get up and running with the Sentinel MITRE Analyzer in 5 minutes!

---

## ⚡ 5-Minute Setup

### Step 1: Download (30 seconds)

```powershell
# Clone the repository
git clone https://github.com/yourusername/sentinel-mitre-analyzer.git
cd sentinel-mitre-analyzer
```

### Step 2: Authenticate (1 minute)

```powershell
# Login to Azure
Connect-AzAccount

# Set your subscription
Set-AzContext -SubscriptionId 'your-subscription-id'
```

### Step 3: Run (3 minutes)

```powershell
# Import and run
Import-Module .\SentinelMITREAnalyzer.psm1
Get-SentinelAnalyticalRulesReport -ExportHtml
```

**That's it!** Your report is in the Downloads folder.

---

## 📝 What You Need

Before starting, have these ready:

| Item | Where to Find |
|------|---------------|
| **Subscription ID** | Azure Portal → Subscriptions |
| **Resource Group** | Azure Portal → Sentinel → Overview |
| **Workspace Name** | Azure Portal → Sentinel → Overview |

---

## 🎯 Your First Report

### Interactive Mode

```powershell
# The script will prompt you for inputs
Get-SentinelAnalyticalRulesReport -ExportHtml

# Enter when prompted:
# - Subscription ID
# - Resource Group
# - Workspace Name
```

### Direct Mode (Skip Prompts)

```powershell
Get-SentinelAnalyticalRulesReport `
    -SubscriptionId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' `
    -ResourceGroup 'my-sentinel-rg' `
    -WorkspaceName 'my-workspace' `
    -ExportHtml
```

---

## 📊 What You'll Get

The HTML report includes:

✅ Total/Enabled/Disabled rule counts  
✅ Interactive radar chart of MITRE coverage  
✅ Enabled rules per tactic breakdown  
✅ Custom vs Gallery rule split  
✅ List of disabled rules  
✅ Rules without MITRE mapping  
✅ Coverage gaps (tactics needing attention)  
✅ Overall coverage grade (A-F)  
✅ Executive summary dashboard  

---

## 🆘 Common Issues

### "Connect-AzAccount not found"

```powershell
# Install Az module
Install-Module Az -Scope CurrentUser -Force
```

### "HTTP 403 Forbidden"

You need the **Microsoft Sentinel Reader** role.

Ask your Azure admin to grant access:
```powershell
# (Admin runs this)
New-AzRoleAssignment `
    -SignInName user@domain.com `
    -RoleDefinitionName "Microsoft Sentinel Reader" `
    -Scope "/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{workspace}"
```

### "Can't find workspace"

```powershell
# List all workspaces you have access to
Get-AzOperationalInsightsWorkspace | Select Name, ResourceGroupName
```

---

## 🚀 Next Steps

Once your first report is complete:

1. **Review the HTML report** in your browser
2. **Check the coverage grade** - aim for B or higher
3. **Enable disabled high-severity rules** if any
4. **Map unmapped rules** to MITRE tactics
5. **Schedule monthly reports** for tracking

---

## 📖 Learn More

- [Full Installation Guide](docs/INSTALLATION.md)
- [API & Permissions](docs/API-REFERENCE.md)
- [Usage Examples](examples/EXAMPLES.md)
- [Troubleshooting](README.md#troubleshooting)

---

**Questions?** [Open an issue](https://github.com/yourusername/sentinel-mitre-analyzer/issues) on GitHub!
