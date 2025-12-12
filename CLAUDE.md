# CLAUDE.md - Entra Security Assessment Tool

## Projekt-Übersicht

Dieses Projekt ist ein PowerShell-basiertes Security Assessment Framework für Microsoft Entra ID und M365, aufbauend auf Maester mit erweiterten Custom Tests.

## Tech Stack

- **Sprache:** PowerShell 7.x
- **Test Framework:** Pester 5.x (Maester-kompatibel)
- **API:** Microsoft Graph API
- **Optional:** MCP Integration (TypeScript)

## Architektur

```
EntraSecurityAssessment/
├── src/
│   ├── EntraSecurityAssessment.psd1    # Module Manifest
│   ├── EntraSecurityAssessment.psm1    # Hauptmodul
│   ├── Core/
│   │   ├── Connect-EntraAssessment.ps1 # Graph Auth (Interactive + Service Principal)
│   │   ├── Get-TenantHealth.ps1        # Basis Health Check
│   │   └── Export-AssessmentData.ps1   # Datenexport
│   ├── Tests/
│   │   ├── Maester/                    # Standard Maester Tests (optional)
│   │   └── Custom/                     # Eigene Pester Tests
│   │       ├── Copilot.Tests.ps1
│   │       ├── PIM.Tests.ps1
│   │       ├── RBAC.Tests.ps1
│   │       ├── ConditionalAccess.Tests.ps1
│   │       └── IdentityProtection.Tests.ps1
│   ├── Reports/
│   │   └── New-AssessmentReport.ps1    # HTML/JSON/MD Reports
│   └── Config/
│       └── assessment-config.json
├── mcp/tools/                          # Optional: MCP Integration
│   └── entra-health-check.ts
└── docs/
    └── CHECKS.md
```

## Erforderliche Graph API Scopes

```powershell
$Scopes = @(
    'Directory.Read.All',
    'Policy.Read.All',
    'RoleManagement.Read.All',
    'IdentityRiskyUser.Read.All',
    'IdentityRiskEvent.Read.All',
    'AuditLog.Read.All',
    'User.Read.All',
    'Group.Read.All',
    'Application.Read.All',
    'PrivilegedAccess.Read.AzureAD'
)
```

## Security Checks zu implementieren

### COPILOT (Microsoft 365 Copilot)
| ID | Check | Risk |
|----|-------|------|
| COPILOT-001 | Sensitivity Labels konfiguriert | High |
| COPILOT-002 | DLP Policies vorhanden | High |
| COPILOT-003 | Audit Logging aktiviert | Medium |
| COPILOT-004 | Tenant Isolation | Medium |

### PIM (Privileged Identity Management)
| ID | Check | Risk |
|----|-------|------|
| PIM-001 | Keine permanenten privilegierten Zuweisungen | High |
| PIM-002 | Approval für kritische Rollen | High |
| PIM-003 | Aktivierungsdauer ≤ 8h | Medium |
| PIM-004 | Justification erforderlich | Medium |
| PIM-005 | MFA bei Aktivierung | High |

### RBAC (Role-Based Access Control)
| ID | Check | Risk |
|----|-------|------|
| RBAC-001 | Global Admins zwischen 2-5 | High |
| RBAC-002 | Keine Gäste mit Admin-Rollen | High |
| RBAC-003 | Keine Service Principals als Global Admin | Medium |
| RBAC-004 | Custom Roles dokumentiert | Low |
| RBAC-005 | Privilegierte Benutzer < 5% | Medium |

### Conditional Access
| ID | Check | Risk |
|----|-------|------|
| CA-001 | MFA für alle Benutzer | High |
| CA-002 | Legacy Auth blockiert | High |
| CA-003 | Admin MFA Policy | High |
| CA-004 | Risky Sign-In Policy | Medium |

### Identity Protection
| ID | Check | Risk |
|----|-------|------|
| IDP-001 | Keine High Risk Users | High |
| IDP-002 | Risk Detections monitored | Medium |

## Graph API Endpoints

```powershell
# Directory Roles
GET /v1.0/directoryRoles
GET /v1.0/directoryRoles/{id}/members

# PIM
GET /v1.0/roleManagement/directory/roleDefinitions
GET /v1.0/policies/roleManagementPolicies
GET /v1.0/roleManagement/directory/roleEligibilityScheduleInstances

# Conditional Access
GET /v1.0/identity/conditionalAccess/policies

# Identity Protection
GET /v1.0/identityProtection/riskyUsers
GET /v1.0/identityProtection/riskDetections

# Sensitivity Labels
GET /v1.0/informationProtection/policy/labels

# Audit Logs
GET /v1.0/auditLogs/directoryAudits
GET /v1.0/auditLogs/signIns
```

## Pester Test Struktur (Maester-kompatibel)

```powershell
Describe "PIM-001 - Permanente privilegierte Zuweisungen" -Tag "PIM", "Security" {
    
    BeforeAll {
        # Graph Verbindung prüfen, Daten laden
    }
    
    It "PIM-001.1: Global Admin hat max 2 permanente Zuweisungen" {
        $count | Should -BeLessOrEqual 2
    }
    
    It "PIM-001.2: Security Admin hat keine permanenten Zuweisungen" {
        $count | Should -Be 0
    }
}
```

## Report Output Format

```powershell
[PSCustomObject]@{
    CheckId = 'PIM-001'
    Category = 'PIM'
    Title = 'Permanente privilegierte Zuweisungen'
    Risk = 'High'           # High, Medium, Low, Info
    Status = 'Failed'       # Failed, Passed, Warning, ManualReview, Error
    Description = '...'
    Remediation = '...'
    Reference = 'https://learn.microsoft.com/...'
    Details = @{}           # Optional: Zusätzliche Daten
}
```

## Wichtige Hinweise für Claude Code

1. **Graph API Calls** immer mit Error Handling:
```powershell
try {
    $result = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
} catch {
    # Handle gracefully
}
```

2. **Multi-Tenant Support** über `Connect-MgGraph -TenantId`

3. **Maester Kompatibilität**: Tests als `.Tests.ps1` Dateien mit Pester Syntax

4. **HTML Report** sollte interaktiv sein (Sections auf/zuklappen)

5. **Risiko-Klassifizierung** konsistent verwenden:
   - **High**: Sofort beheben (24h SLA)
   - **Medium**: Zeitnah beheben (7 Tage)
   - **Low**: Bei Gelegenheit

## Beispiel-Aufruf

```powershell
# Single Tenant
Connect-EntraAssessment -TenantId "xxx-xxx-xxx"
$results = Invoke-EntraSecurityAssessment
New-AssessmentReport -Results $results -Format HTML

# Multi-Tenant
$tenants = @("tenant1", "tenant2", "tenant3")
Invoke-MultiTenantAssessment -TenantIds $tenants -OutputPath "./Reports"
```
