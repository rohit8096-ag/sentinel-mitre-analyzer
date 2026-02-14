# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.6.0] - 2024-12-XX

### Added
- Natural, human-readable code structure
- "Designed by Rohit Ashok" branding in reports
- Large ASCII banner on script execution
- "Enabled Rules by Tactic" table in HTML report
- Section descriptions for all report components
- Coverage grade explanation (A-F scale)
- Custom vs Gallery rules breakdown with descriptions

### Changed
- Improved authentication diagnostics with detailed error messages
- Simplified function and variable naming
- Enhanced HTML report with info boxes and tooltips
- Better visual hierarchy in report sections

### Fixed
- Token acquisition for Az PowerShell 9.0+ (SecureString handling)
- Authentication fallback mechanisms

---

## [2.5.1] - 2024-12-XX

### Added
- Comprehensive authentication diagnostics
- Support for multiple authentication methods (Az, CLI, Managed Identity)
- Detailed error messages with fix instructions

### Fixed
- Authentication failures with clear troubleshooting steps
- Token expiration handling

---

## [2.5.0] - 2024-12-XX

### Added
- HTML report generation with interactive radar chart
- PDF export support (requires wkhtmltopdf or Chrome)
- Auto-save to Downloads folder
- Chart.js integration for visualizations
- Professional dashboard design

### Changed
- Report filename standardized to "Sentinel Analytical Analyzer"

---

## [2.0.0] - 2024-12-XX

### Added
- MITRE technique coverage calculation (against 211 techniques)
- Sub-technique rollup (T1547.002 → T1547)
- Custom vs Gallery rule detection
- Gap analysis (least coverage table)
- Coverage grading system (A-F)
- Executive summary section
- Disabled rules with MITRE tactics report
- Rules without MITRE mapping identification

### Changed
- Enhanced tactic processing logic
- Improved data aggregation

---

## [1.1.0] - 2024-12-XX

### Added
- Azure CLI authentication support
- Managed Identity support

### Fixed
- Authentication issues with newer Az modules
- API version fallback mechanism

---

## [1.0.0] - 2024-12-XX

### Added
- Initial release
- Basic rule fetching from Azure Sentinel
- MITRE ATT&CK tactic mapping
- Terminal-based reporting
- Console output with statistics

---

## Future Roadmap

### Planned for v3.0.0
- [ ] PDF generation without external dependencies
- [ ] Multi-workspace comparison in single report
- [ ] Historical trend tracking
- [ ] Azure Government Cloud support
- [ ] Playbook coverage analysis

### Under Consideration
- [ ] PowerShell Gallery publication
- [ ] Microsoft Teams notification integration
- [ ] Scheduled Azure Automation support
- [ ] REST API for programmatic access

---

**Note**: Release dates and version numbers will be updated as releases are published.
