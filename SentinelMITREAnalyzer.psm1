#Requires -Version 5.1

<#
.SYNOPSIS
    Sentinel MITRE ATT&CK Coverage Analyzer
    
.DESCRIPTION
    Analyzes Azure Sentinel analytical rules and generates comprehensive
    MITRE ATT&CK coverage reports with visual radar charts.
    
.NOTES
    Author: Rohit Ashok
    Version: 2.6.0
    Date: 2024
#>

# Global configuration
$script:Version = "2.6.0"
$script:Author = "Rohit Ashok"
$script:ManagementEndpoint = "https://management.azure.com"
$script:MitreTotalTechniques = 211

# MITRE tactic definitions
$script:TacticOrder = @(
    "InitialAccess","Execution","Persistence","PrivilegeEscalation",
    "DefenseEvasion","CredentialAccess","Discovery","LateralMovement",
    "Collection","CommandAndControl","Exfiltration","Impact",
    "Reconnaissance","ResourceDevelopment"
)

$script:TacticNames = @{
    "InitialAccess"="Initial Access"; "Execution"="Execution"
    "Persistence"="Persistence"; "PrivilegeEscalation"="Privilege Escalation"
    "DefenseEvasion"="Defense Evasion"; "CredentialAccess"="Credential Access"
    "Discovery"="Discovery"; "LateralMovement"="Lateral Movement"
    "Collection"="Collection"; "CommandAndControl"="Command & Control"
    "Exfiltration"="Exfiltration"; "Impact"="Impact"
    "Reconnaissance"="Reconnaissance"; "ResourceDevelopment"="Resource Development"
}

# Helper functions
function Get-UserDownloadsPath {
    if ($IsWindows -or $null -eq $IsWindows) {
        return Join-Path $env:USERPROFILE "Downloads"
    }
    return Join-Path $env:HOME "Downloads"
}

function Get-TechniqueBase {
    param([string]$TechId)
    # Extract base technique from sub-techniques (e.g., T1547.002 -> T1547)
    if ($TechId -match '^(T\d+)') {
        return $Matches[1]
    }
    return $TechId
}

function Extract-MitreData {
    param($RuleObject)
    
    $props = $RuleObject.properties
    $tactics = @()
    $techniques = @()
    
    if ($props.tactics) {
        $tactics = $props.tactics
    }
    
    if ($props.techniques) {
        $techniques = $props.techniques
    } elseif ($props.mitreTechniques) {
        $techniques = $props.mitreTechniques
    }
    
    return @{
        Tactics = $tactics
        Techniques = $techniques
    }
}

# Authentication handler
function Get-AzureToken {
    Write-Host ""
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Authentication Check" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""

    $issues = @()

    # Try Az PowerShell first
    Write-Host "  [Method 1] Checking Az PowerShell..." -ForegroundColor White
    
    $azMod = Get-Module -Name Az.Accounts -ListAvailable
    if ($azMod) {
        Write-Host "      ✓ Az module found (v$($azMod[0].Version))" -ForegroundColor Green
        
        try {
            Import-Module Az.Accounts -ErrorAction Stop
            $context = Get-AzContext -ErrorAction Stop
            
            if ($context) {
                Write-Host "      ✓ Logged in as: $($context.Account.Id)" -ForegroundColor Green
                Write-Host "      ✓ Subscription: $($context.Subscription.Name)" -ForegroundColor Green
                
                try {
                    $tokenObj = Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -ErrorAction Stop
                    $token = $tokenObj.Token
                    
                    # Handle newer Az modules that return SecureString
                    if ($token -is [System.Security.SecureString]) {
                        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($token)
                        $token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr)
                        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
                    }
                    
                    if ($token.Length -gt 100) {
                        Write-Host "      ✓ Token obtained successfully" -ForegroundColor Green
                        Write-Host ""
                        return $token
                    }
                } catch {
                    # Fallback method for older Az versions
                    try {
                        $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
                        $client = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azProfile)
                        $tokenResult = $client.AcquireAccessToken($context.Subscription.TenantId)
                        
                        if ($tokenResult.AccessToken.Length -gt 100) {
                            Write-Host "      ✓ Token obtained (fallback method)" -ForegroundColor Green
                            Write-Host ""
                            return $tokenResult.AccessToken
                        }
                    } catch {
                        $issues += "Failed to get token from Az module"
                    }
                }
            } else {
                $issues += "Not logged in to Az (run Connect-AzAccount)"
            }
        } catch {
            $issues += "Az module error: $($_.Exception.Message)"
        }
    } else {
        $issues += "Az module not installed"
    }

    # Try Azure CLI
    Write-Host "  [Method 2] Checking Azure CLI..." -ForegroundColor White
    
    $cliPath = Get-Command az -ErrorAction SilentlyContinue
    if (-not $cliPath) {
        $cliPath = Get-Command az.cmd -ErrorAction SilentlyContinue
    }
    
    if ($cliPath) {
        Write-Host "      ✓ CLI installed" -ForegroundColor Green
        
        try {
            $accountInfo = & $cliPath.Source account show --output json 2>&1
            if ($LASTEXITCODE -eq 0) {
                $acct = $accountInfo | ConvertFrom-Json
                Write-Host "      ✓ Logged in as: $($acct.user.name)" -ForegroundColor Green
                
                $tokenInfo = & $cliPath.Source account get-access-token --resource "https://management.azure.com" --output json 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $tokenData = $tokenInfo | ConvertFrom-Json
                    if ($tokenData.accessToken.Length -gt 100) {
                        Write-Host "      ✓ Token obtained successfully" -ForegroundColor Green
                        Write-Host ""
                        return $tokenData.accessToken
                    }
                }
            } else {
                $issues += "Not logged in to CLI (run az login)"
            }
        } catch {
            $issues += "CLI error: $($_.Exception.Message)"
        }
    } else {
        $issues += "Azure CLI not installed"
    }

    # Authentication failed
    Write-Host ""
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host "  Authentication Failed" -ForegroundColor Red
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Issues detected:" -ForegroundColor Yellow
    foreach ($issue in $issues) {
        Write-Host "    • $issue" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "  Fix: Run one of these commands first:" -ForegroundColor Yellow
    Write-Host "    Connect-AzAccount" -ForegroundColor White
    Write-Host "    az login" -ForegroundColor White
    Write-Host ""
    
    throw "Authentication required"
}

# API helper
function Call-SentinelAPI {
    param(
        [string]$Uri,
        [string]$Token
    )
    
    $headers = @{
        "Authorization" = "Bearer $Token"
        "Content-Type" = "application/json"
    }
    
    $results = @()
    $nextUrl = $Uri
    
    while ($nextUrl) {
        try {
            $response = Invoke-RestMethod -Uri $nextUrl -Headers $headers -Method Get -ErrorAction Stop
            
            if ($response.value) {
                $results += $response.value
            }
            
            $nextUrl = $response.nextLink
        } catch {
            $status = $null
            try { $status = [int]$_.Exception.Response.StatusCode } catch {}
            
            switch ($status) {
                401 { throw "Unauthorized - token may have expired" }
                403 { throw "Forbidden - need 'Microsoft Sentinel Reader' role" }
                404 { throw "Not found - check subscription/resource group/workspace names" }
                default { throw $_.Exception.Message }
            }
        }
    }
    
    return $results
}

# HTML report generator
function Build-HtmlReport {
    param(
        [array]$AllRules,
        [array]$EnabledRules,
        [array]$DisabledRules,
        [hashtable]$TacticData,
        [string]$WorkspaceName,
        [string]$OutputFile
    )

    Write-Host "  → Generating HTML report..." -ForegroundColor Cyan

    $total = $AllRules.Count
    $enabled = $EnabledRules.Count
    $disabled = $DisabledRules.Count
    $enabledPct = if ($total) { [math]::Round(($enabled / $total) * 100, 1) } else { 0 }

    # Calculate unique techniques for enabled rules
    $uniqueTechs = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($rule in $EnabledRules) {
        $mitreInfo = Extract-MitreData $rule
        foreach ($tech in $mitreInfo.Techniques) {
            $base = Get-TechniqueBase $tech
            [void]$uniqueTechs.Add($base)
        }
    }
    $techCount = $uniqueTechs.Count
    $coverage = [math]::Round(($techCount / $script:MitreTotalTechniques) * 100, 1)

    # Coverage grade
    $grade = if ($coverage -ge 80) { "A - Excellent" }
        elseif ($coverage -ge 60) { "B - Good" }
        elseif ($coverage -ge 40) { "C - Moderate" }
        elseif ($coverage -ge 20) { "D - Limited" }
        else { "F - Needs Improvement" }

    # Custom vs Gallery
    $gallery = $EnabledRules | Where-Object {
        $_.properties.templateVersion -or $_.properties.templateId -or
        $_.kind -in @('MicrosoftSecurityIncidentCreation','Fusion','ThreatIntelligence')
    }
    $custom = $EnabledRules | Where-Object {
        -not ($_.properties.templateVersion -or $_.properties.templateId) -and
        $_.kind -notin @('MicrosoftSecurityIncidentCreation','Fusion','ThreatIntelligence')
    }

    # Radar chart data
    $radarLabels = @()
    $radarValues = @()
    foreach ($tactic in $script:TacticOrder) {
        if ($TacticData[$tactic]) {
            $label = $script:TacticNames[$tactic]
            $radarLabels += """$label"""
            $radarValues += $TacticData[$tactic].EnabledCount
        }
    }

    # Build disabled rules table
    $disabledRows = ""
    foreach ($rule in ($DisabledRules | Sort-Object { $_.properties.displayName } | Select-Object -First 25)) {
        $rname = $rule.properties.displayName
        $sev = $rule.properties.severity ?? "N/A"
        $tacticList = if ($rule.properties.tactics) {
            ($rule.properties.tactics | ForEach-Object { $script:TacticNames[$_] ?? $_ }) -join ", "
        } else { "—" }
        
        $sevColor = switch ($sev) {
            "High" { "#dc3545" }
            "Medium" { "#ffc107" }
            "Low" { "#17a2b8" }
            default { "#6c757d" }
        }
        
        $disabledRows += "<tr><td>$rname</td><td><span class='badge' style='background:$sevColor'>$sev</span></td><td>$tacticList</td></tr>`n"
    }

    # Build unmapped rules table
    $unmapped = $AllRules | Where-Object { -not $_.properties.tactics -or $_.properties.tactics.Count -eq 0 }
    $unmappedRows = ""
    foreach ($rule in ($unmapped | Sort-Object { $_.properties.displayName } | Select-Object -First 20)) {
        $rname = $rule.properties.displayName
        $isOn = if ($rule.properties.enabled) { "✓" } else { "✗" }
        $sev = $rule.properties.severity ?? "N/A"
        $type = $rule.kind ?? "N/A"
        $statusColor = if ($rule.properties.enabled) { "#28a745" } else { "#dc3545" }
        
        $unmappedRows += "<tr><td>$rname</td><td style='color:$statusColor'>$isOn</td><td>$sev</td><td>$type</td></tr>`n"
    }

    # Build enabled rules per tactic table
    $tacticRows = ""
    foreach ($tactic in $script:TacticOrder) {
        if ($TacticData[$tactic]) {
            $label = $script:TacticNames[$tactic]
            $enCount = $TacticData[$tactic].EnabledCount
            $totCount = $TacticData[$tactic].Total
            $barWidth = if ($totCount) { [math]::Round(($enCount / $totCount) * 100) } else { 0 }
            
            $tacticRows += @"
<tr>
    <td>$label</td>
    <td>$enCount</td>
    <td>$totCount</td>
    <td>
        <div style='background:#e9ecef;border-radius:4px;height:20px;width:200px'>
            <div style='background:#3b82f6;height:20px;width:${barWidth}%;border-radius:4px'></div>
        </div>
    </td>
</tr>
"@
        }
    }

    # Build gap analysis table
    $gapItems = $TacticData.GetEnumerator() | 
        Where-Object { $_.Key -in $script:TacticOrder } |
        Sort-Object { $_.Value.EnabledCount } |
        Select-Object -First 5

    $gapRows = ""
    foreach ($item in $gapItems) {
        $label = $script:TacticNames[$item.Key]
        $count = $item.Value.EnabledCount
        $priority = if ($count -eq 0) { "CRITICAL" }
            elseif ($count -le 2) { "High" }
            elseif ($count -le 5) { "Medium" }
            else { "Low" }
        
        $prioColor = switch ($priority) {
            "CRITICAL" { "#dc3545" }
            "High" { "#ffc107" }
            "Medium" { "#17a2b8" }
            default { "#6c757d" }
        }
        
        $gapRows += "<tr><td>$label</td><td>$count</td><td><span class='badge' style='background:$prioColor'>$priority</span></td></tr>`n"
    }

    $timestamp = Get-Date -Format "MMMM dd, yyyy - HH:mm:ss"

$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel Coverage Report - $WorkspaceName</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }
        .header {
            background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 { font-size: 2.2em; margin-bottom: 8px; }
        .header .subtitle { font-size: 1.1em; opacity: 0.95; }
        .header .meta { font-size: 0.9em; margin-top: 15px; opacity: 0.8; }
        .content { padding: 40px; }
        .section { margin-bottom: 45px; }
        .section h2 {
            color: #1e3a8a;
            font-size: 1.6em;
            margin-bottom: 12px;
            padding-bottom: 8px;
            border-bottom: 3px solid #3b82f6;
        }
        .section-desc {
            color: #64748b;
            font-size: 0.95em;
            margin-bottom: 20px;
            line-height: 1.5;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 18px;
            margin-bottom: 25px;
        }
        .stat-box {
            background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%);
            padding: 22px;
            border-radius: 8px;
            border-left: 4px solid #3b82f6;
        }
        .stat-box h3 {
            font-size: 0.85em;
            color: #64748b;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }
        .stat-box .number {
            font-size: 2.2em;
            font-weight: 700;
            color: #1e3a8a;
        }
        .chart-wrapper {
            max-width: 650px;
            height: 450px;
            margin: 25px auto;
            background: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            box-shadow: 0 1px 6px rgba(0,0,0,0.06);
        }
        thead {
            background: #1e3a8a;
            color: white;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
        }
        tbody tr:hover { background: #f9fafb; }
        .badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 10px;
            font-size: 0.85em;
            font-weight: 600;
            color: white;
        }
        .summary-panel {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: white;
            padding: 28px;
            border-radius: 8px;
            margin-top: 25px;
        }
        .summary-panel h3 {
            font-size: 1.4em;
            margin-bottom: 18px;
            text-align: center;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
        }
        .summary-row {
            display: flex;
            justify-content: space-between;
            padding: 10px;
            background: rgba(255,255,255,0.1);
            border-radius: 5px;
        }
        .footer {
            text-align: center;
            padding: 18px;
            background: #f8fafc;
            color: #64748b;
            font-size: 0.9em;
        }
        .info-box {
            background: #fef3c7;
            border-left: 4px solid #f59e0b;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }
        .info-box p {
            color: #92400e;
            font-size: 0.9em;
            line-height: 1.6;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Sentinel Coverage Analyzer</h1>
            <div class="subtitle">MITRE ATT&CK Detection Coverage Report</div>
            <div class="subtitle" style="margin-top:8px"><strong>$WorkspaceName</strong></div>
            <div class="meta">Generated: $timestamp</div>
        </div>

        <div class="content">
            <!-- Overview Stats -->
            <div class="section">
                <h2>📊 Overview</h2>
                <p class="section-desc">Summary of analytical rule status and MITRE ATT&CK coverage across your Sentinel workspace.</p>
                <div class="stats-grid">
                    <div class="stat-box">
                        <h3>Total Rules</h3>
                        <div class="number">$total</div>
                    </div>
                    <div class="stat-box" style="border-left-color:#22c55e">
                        <h3>Enabled</h3>
                        <div class="number" style="color:#22c55e">$enabled</div>
                    </div>
                    <div class="stat-box" style="border-left-color:#ef4444">
                        <h3>Disabled</h3>
                        <div class="number" style="color:#ef4444">$disabled</div>
                    </div>
                    <div class="stat-box" style="border-left-color:#f59e0b">
                        <h3>Coverage</h3>
                        <div class="number" style="color:#f59e0b">$coverage%</div>
                    </div>
                </div>
            </div>

            <!-- Radar Chart -->
            <div class="section">
                <h2>📡 MITRE ATT&CK Tactics Coverage</h2>
                <p class="section-desc">Visual representation of enabled detection rules mapped to each MITRE ATT&CK tactic. Larger areas indicate stronger coverage.</p>
                <div class="chart-wrapper">
                    <canvas id="radarChart"></canvas>
                </div>
            </div>

            <!-- Enabled Rules Per Tactic -->
            <div class="section">
                <h2>🎯 Enabled Rules by Tactic</h2>
                <p class="section-desc">Number of active detection rules covering each MITRE ATT&CK tactic in your environment.</p>
                <table>
                    <thead>
                        <tr>
                            <th>MITRE Tactic</th>
                            <th>Enabled</th>
                            <th>Total</th>
                            <th>Distribution</th>
                        </tr>
                    </thead>
                    <tbody>
                        $tacticRows
                    </tbody>
                </table>
            </div>

            <!-- Custom vs Gallery -->
            <div class="section">
                <h2>📦 Rule Source Breakdown</h2>
                <p class="section-desc">Distribution of enabled rules between Microsoft-provided templates (Gallery) and custom-created detections.</p>
                <div class="info-box">
                    <p><strong>Gallery Rules:</strong> Pre-built detection templates from Microsoft and the community.<br>
                    <strong>Custom Rules:</strong> Organization-specific detections created by your security team.</p>
                </div>
                <div class="stats-grid">
                    <div class="stat-box" style="border-left-color:#8b5cf6">
                        <h3>Gallery Rules</h3>
                        <div class="number" style="color:#8b5cf6">$($gallery.Count)</div>
                    </div>
                    <div class="stat-box" style="border-left-color:#ec4899">
                        <h3>Custom Rules</h3>
                        <div class="number" style="color:#ec4899">$($custom.Count)</div>
                    </div>
                </div>
            </div>

            <!-- Disabled Rules -->
            <div class="section">
                <h2>⚠️ Disabled Rules</h2>
                <p class="section-desc">Analytical rules that are currently disabled and not actively generating alerts.</p>
                <table>
                    <thead>
                        <tr>
                            <th>Rule Name</th>
                            <th>Severity</th>
                            <th>MITRE Tactics</th>
                        </tr>
                    </thead>
                    <tbody>
                        $disabledRows
                    </tbody>
                </table>
            </div>

            <!-- Unmapped Rules -->
            <div class="section">
                <h2>🔍 Rules Without MITRE Mapping</h2>
                <p class="section-desc">Detection rules that haven't been mapped to MITRE ATT&CK tactics, representing potential gaps in your threat coverage framework.</p>
                <table>
                    <thead>
                        <tr>
                            <th>Rule Name</th>
                            <th>Status</th>
                            <th>Severity</th>
                            <th>Type</th>
                        </tr>
                    </thead>
                    <tbody>
                        $unmappedRows
                    </tbody>
                </table>
            </div>

            <!-- Gap Analysis -->
            <div class="section">
                <h2>📉 Coverage Gaps</h2>
                <p class="section-desc">Tactics with the fewest enabled detection rules, indicating areas where additional coverage may be needed.</p>
                <table>
                    <thead>
                        <tr>
                            <th>Tactic</th>
                            <th>Enabled Rules</th>
                            <th>Priority</th>
                        </tr>
                    </thead>
                    <tbody>
                        $gapRows
                    </tbody>
                </table>
            </div>

            <!-- Coverage Grade -->
            <div class="section">
                <h2>📈 Coverage Assessment</h2>
                <p class="section-desc">Overall rating of your MITRE ATT&CK technique coverage based on enabled detection rules.</p>
                <div class="info-box">
                    <p><strong>Grading Scale:</strong> A (≥80%) Excellent • B (≥60%) Good • C (≥40%) Moderate • D (≥20%) Limited • F (<20%) Needs Improvement</p>
                </div>
                <div class="summary-panel">
                    <h3>Executive Summary</h3>
                    <div class="summary-grid">
                        <div class="summary-row">
                            <span>Enabled Rules</span>
                            <span style="color:#22c55e;font-weight:700">$enabled</span>
                        </div>
                        <div class="summary-row">
                            <span>Disabled Rules</span>
                            <span style="color:#ef4444;font-weight:700">$disabled</span>
                        </div>
                        <div class="summary-row">
                            <span>Total MITRE Techniques</span>
                            <span style="font-weight:700">211</span>
                        </div>
                        <div class="summary-row">
                            <span>Techniques Covered</span>
                            <span style="color:#f59e0b;font-weight:700">$techCount</span>
                        </div>
                        <div class="summary-row">
                            <span>Coverage Percentage</span>
                            <span style="color:#3b82f6;font-weight:700">$coverage%</span>
                        </div>
                        <div class="summary-row">
                            <span>Coverage Grade</span>
                            <span style="font-weight:700">$grade</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="footer">
            Sentinel Analytical Analyzer v$script:Version | Designed by <strong>$script:Author</strong>
        </div>
    </div>

    <script>
        const ctx = document.getElementById('radarChart').getContext('2d');
        new Chart(ctx, {
            type: 'radar',
            data: {
                labels: [$($radarLabels -join ',')],
                datasets: [{
                    label: 'Enabled Rules',
                    data: [$($radarValues -join ',')],
                    fill: true,
                    backgroundColor: 'rgba(59, 130, 246, 0.25)',
                    borderColor: 'rgb(59, 130, 246)',
                    pointBackgroundColor: 'rgb(59, 130, 246)',
                    pointBorderColor: '#fff',
                    pointRadius: 5,
                    pointHoverRadius: 7,
                    borderWidth: 2.5
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    title: {
                        display: true,
                        text: 'MITRE ATT&CK Tactics - Enabled Detection Coverage',
                        font: { size: 16, weight: 'bold' },
                        color: '#1e3a8a',
                        padding: 15
                    },
                    legend: { display: false }
                },
                scales: {
                    r: {
                        beginAtZero: true,
                        ticks: { stepSize: 5 },
                        pointLabels: {
                            font: { size: 12, weight: '600' },
                            color: '#475569'
                        }
                    }
                }
            }
        });
    </script>
</body>
</html>
"@

    try {
        $htmlContent | Out-File -FilePath $OutputFile -Encoding UTF8 -Force
        Write-Host "  ✓ Report saved: $OutputFile" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "  ✗ Failed to save report: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Main function
function Get-SentinelAnalyticalRulesReport {
    param(
        [string]$SubscriptionId,
        [string]$ResourceGroup,
        [string]$WorkspaceName,
        [switch]$ExportHtml,
        [switch]$ExportPdf
    )

    # Display banner
    Clear-Host
    Write-Host ""
    Write-Host "  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     " -ForegroundColor Cyan
    Write-Host "  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     " -ForegroundColor Cyan
    Write-Host "  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     " -ForegroundColor Cyan
    Write-Host "  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     " -ForegroundColor Cyan
    Write-Host "  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗" -ForegroundColor Cyan
    Write-Host "  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "          ANALYTICAL ANALYZER" -ForegroundColor White
    Write-Host "          Developed by Rohit Ashok" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host ""

    # Collect configuration
    Write-Host "  Configuration" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host ""
    
    if (-not $SubscriptionId) {
        Write-Host "  Subscription ID : " -NoNewline -ForegroundColor Yellow
        $SubscriptionId = Read-Host
    }
    if (-not $ResourceGroup) {
        Write-Host "  Resource Group  : " -NoNewline -ForegroundColor Yellow
        $ResourceGroup = Read-Host
    }
    if (-not $WorkspaceName) {
        Write-Host "  Workspace Name  : " -NoNewline -ForegroundColor Yellow
        $WorkspaceName = Read-Host
    }

    # Authenticate
    try {
        $token = Get-AzureToken
    } catch {
        return $null
    }

    # Fetch rules
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Fetching Data" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  → Connecting to Sentinel workspace..." -ForegroundColor White

    $apiVersions = @("2024-09-01", "2024-03-01", "2023-12-01-preview")
    $baseUrl = "$script:ManagementEndpoint/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
               "/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName" +
               "/providers/Microsoft.SecurityInsights/alertRules"

    $rules = $null
    foreach ($ver in $apiVersions) {
        try {
            $url = "$baseUrl`?api-version=$ver"
            $rules = Call-SentinelAPI -Uri $url -Token $token
            break
        } catch {
            if ($_.Exception.Message -notmatch "Not found") {
                Write-Host "  ✗ Error: $($_.Exception.Message)" -ForegroundColor Red
                return $null
            }
        }
    }

    if (-not $rules) {
        Write-Host "  ✗ No rules found" -ForegroundColor Red
        return $null
    }

    Write-Host "  ✓ Retrieved $($rules.Count) analytical rules" -ForegroundColor Green
    Write-Host "  → Processing MITRE mappings..." -ForegroundColor White

    # Process rules
    $enabled = @()
    $disabled = @()
    $tacticData = @{}

    foreach ($rule in $rules) {
        if ($rule.properties.enabled) {
            $enabled += $rule
        } else {
            $disabled += $rule
        }

        $mitreInfo = Extract-MitreData $rule
        foreach ($tactic in $mitreInfo.Tactics) {
            if (-not $tactic) { continue }
            
            $key = $tactic -replace '\s', ''
            if (-not $tacticData[$key]) {
                $tacticData[$key] = @{
                    Total = 0
                    EnabledCount = 0
                    Techniques = @{}
                }
            }
            
            $tacticData[$key].Total++
            if ($rule.properties.enabled) {
                $tacticData[$key].EnabledCount++
            }
        }
    }

    Write-Host "  ✓ Analysis complete" -ForegroundColor Green

    # Generate report
    if ($ExportHtml -or $ExportPdf) {
        Write-Host ""
        Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  Report Generation" -ForegroundColor Cyan
        Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""

        $downloadsPath = Get-UserDownloadsPath
        $htmlFile = Join-Path $downloadsPath "Sentinel Analytical Analyzer.html"

        Build-HtmlReport -AllRules $rules -EnabledRules $enabled -DisabledRules $disabled `
                         -TacticData $tacticData -WorkspaceName $WorkspaceName -OutputFile $htmlFile
    }

    Write-Host ""
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "  Complete" -ForegroundColor Green
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""

    return @{
        Rules = $rules
        Enabled = $enabled
        Disabled = $disabled
        TacticStats = $tacticData
        HtmlPath = if ($ExportHtml -or $ExportPdf) { $htmlFile } else { $null }
    }
}

Export-ModuleMember -Function 'Get-SentinelAnalyticalRulesReport'
