#
# Module manifest for SentinelMITREAnalyzer
#

@{
    # Script module file associated with this manifest
    RootModule        = 'SentinelMITREAnalyzer.psm1'

    # Version number
    ModuleVersion     = '1.0.0'

    # Unique identifier for this module
    GUID              = 'a3f5d812-7c2e-4b9a-8f1d-6e3c0b4d2a9f'

    # Author
    Author            = 'Sentinel MITRE Analyzer'

    # Description
    Description       = 'Analyzes Azure Sentinel Analytical Rules and generates MITRE ATT&CK coverage reports with interactive terminal graphs.'

    # Minimum PowerShell version
    PowerShellVersion = '5.1'

    # Functions to export from this module
    FunctionsToExport = @(
        'Get-SentinelAnalyticalRulesReport',
        'Export-SentinelRulesCsv',
        'Show-SentinelHelp'
    )

    # Private data
    PrivateData = @{
        PSData = @{
            Tags       = @('Azure', 'Sentinel', 'MITRE', 'Security', 'ATT&CK', 'SIEM')
            ProjectUri = ''
        }
    }
}
