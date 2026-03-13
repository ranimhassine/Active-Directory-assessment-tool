# Consultim-IT — Active Directory Security Assessment Tool

**Author:** Ranim Hassine — Consultim-IT  
**Version:** 1.0.0  
**Requires:** PowerShell 5.1+ · RSAT ActiveDirectory module · Domain Admin rights

---

## What it does

Runs a security audit against an Active Directory domain and produces a self-contained HTML report covering:

- Password policy weaknesses
- Privilege escalation paths (delegation, DCSync, sensitive accounts)
- Lateral movement risks (Print Spooler, stale accounts, machine quota)
- Kerberos security (Kerberoastable accounts, KRBTGT rotation)
- GPO hygiene (unlinked GPOs, audit gaps)
- ACL / delegation issues

The report includes an **interactive remediation timeline** (Gantt + tracker table) with progress tracking, owner assignment, and one-click **Excel / PDF export**.

---

## Quick Start

```powershell
# Run against the current domain
.\ConsultimIT-AD-Assessment.ps1

# Run against a specific domain
.\ConsultimIT-AD-Assessment.ps1 -Domain corp.example.com

# Custom output folder
.\ConsultimIT-AD-Assessment.ps1 -OutputPath "C:\Reports"
```

The report is saved to `.\ConsultimIT-Reports\ConsultimIT-AD-Report_<timestamp>.html`.

---

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-Domain` | Current domain | Target domain DNS name |
| `-OutputPath` | `.\ConsultimIT-Reports` | Folder for the HTML report |
| `-ReportTitle` | `Active Directory Security Assessment` | Report heading |
| `-SkipPasswordPolicy` | — | Skip password policy checks |
| `-SkipPrivilegeEscalation` | — | Skip privilege escalation checks |
| `-SkipLateralMovement` | — | Skip lateral movement checks |
| `-SkipKerberos` | — | Skip Kerberos checks |
| `-SkipGPO` | — | Skip GPO analysis |
| `-SkipDelegation` | — | Skip ACL/delegation audit |

---

## Prerequisites

```powershell
# Install RSAT on Windows Server
Install-WindowsFeature -Name RSAT-AD-PowerShell

# Install RSAT on Windows 10/11
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

The report's export features (Excel, PDF) require an internet connection to load SheetJS and jsPDF from cdnjs.cloudflare.com.

---

## Report Sections

| Section | Description |
|---|---|
| Security Dashboard | Secure score gauge, KPI counters, user health donuts, findings chart |
| Key Findings | Critical and High severity findings at a glance |
| Remediation Timeline | Interactive 26-week Gantt with progress tracking and exports |
| Prioritized Recommendations | Phased action plan (Immediate → Long-Term) with PowerShell fix commands |
| Detailed Findings | Full finding list grouped by category with technical details |

---

## Notes

- Run as **Domain Administrator** or equivalent for full coverage
- The HTML report is fully self-contained — safe to share or archive
- Progress tracked in the timeline is stored in the browser's `localStorage` and persists across page reloads
- Dark mode toggle is available in the top-right corner of the report
