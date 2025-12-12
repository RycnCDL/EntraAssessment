# Entra Security Assessment Tool

Ein PowerShell-basiertes Security Assessment Framework für Microsoft Entra ID und Microsoft 365, aufbauend auf Maester/Pester mit erweiterten Custom Tests.

## Features

- **20 Security Checks** in 5 Kategorien (PIM, RBAC, Conditional Access, Identity Protection, Copilot)
- **Multi-Tenant Support** via Azure Lighthouse
- **Flexible Authentication** (Interactive, Device Code, Service Principal, Managed Identity)
- **Interaktive HTML Reports** mit Dashboard und Security Score
- **Maester/Pester kompatibel** für CI/CD Integration
- **Microsoft Graph API** basiert

## Schnellstart

```powershell
# 1. Modul importieren
Import-Module ./src/EntraSecurityAssessment.psd1

# 2. Mit Tenant verbinden
Connect-EntraAssessment -TenantId "contoso.onmicrosoft.com"

# 3. Assessment ausführen
$results = Invoke-EntraSecurityAssessment

# 4. HTML Report generieren
New-AssessmentReport -Results $results -Format HTML
```

## Installation

### Voraussetzungen

- PowerShell 7.x
- Microsoft.Graph.Authentication Modul

```powershell
# Graph Modul installieren
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

# Modul importieren
Import-Module ./src/EntraSecurityAssessment.psd1
```

### Erforderliche Berechtigungen

Das Tool benötigt folgende Microsoft Graph API Berechtigungen:

| Berechtigung | Verwendung |
|--------------|------------|
| `Directory.Read.All` | Rollen und Benutzer lesen |
| `Policy.Read.All` | Conditional Access Policies |
| `RoleManagement.Read.All` | PIM Konfiguration |
| `IdentityRiskyUser.Read.All` | Identity Protection |
| `IdentityRiskEvent.Read.All` | Risk Detections |
| `AuditLog.Read.All` | Audit Logging |
| `User.Read.All` | Benutzerdetails |
| `Group.Read.All` | Gruppenmitgliedschaften |
| `Application.Read.All` | Service Principals |
| `PrivilegedAccess.Read.AzureAD` | PIM Zuweisungen |
| `InformationProtectionPolicy.Read.All` | Sensitivity Labels |

## Authentifizierung

### Interactive (Standard)
```powershell
Connect-EntraAssessment -TenantId "contoso.onmicrosoft.com"
```

### Device Code (Headless)
```powershell
Connect-EntraAssessment -TenantId "xxx-xxx-xxx" -DeviceCode
```

### Service Principal (Automation)
```powershell
$secret = ConvertTo-SecureString "ClientSecret" -AsPlainText -Force
Connect-EntraAssessment -TenantId "xxx-xxx-xxx" -ClientId "app-id" -ClientSecret $secret
```

### Certificate
```powershell
Connect-EntraAssessment -TenantId "xxx-xxx-xxx" -ClientId "app-id" -CertificateThumbprint "ABC123..."
```

### Managed Identity (Azure)
```powershell
Connect-EntraAssessment -TenantId "xxx-xxx-xxx" -ManagedIdentity
```

## Security Checks

### PIM (Privileged Identity Management)

| Check ID | Titel | Risk | Beschreibung |
|----------|-------|------|--------------|
| PIM-001 | Permanente privilegierte Zuweisungen | High | Max. 2 permanente Global Admins |
| PIM-002 | Approval für kritische Rollen | High | Genehmigung bei Aktivierung |
| PIM-003 | Aktivierungsdauer max. 8h | Medium | Zeitlimit für Aktivierung |
| PIM-004 | Justification erforderlich | Medium | Begründung bei Aktivierung |
| PIM-005 | MFA bei Aktivierung | High | MFA für Rollenaktivierung |

### RBAC (Role-Based Access Control)

| Check ID | Titel | Risk | Beschreibung |
|----------|-------|------|--------------|
| RBAC-001 | Global Admins 2-5 | High | Optimale Anzahl Global Admins |
| RBAC-002 | Keine Gäste mit Admin-Rollen | High | Gäste ohne Admin-Rechte |
| RBAC-003 | Keine SP als Global Admin | Medium | Service Principals least-privilege |
| RBAC-004 | Custom Roles dokumentiert | Low | Beschreibungen für Custom Roles |
| RBAC-005 | Privilegierte Benutzer < 5% | Medium | Anteil privilegierter User |

### Conditional Access

| Check ID | Titel | Risk | Beschreibung |
|----------|-------|------|--------------|
| CA-001 | MFA für alle Benutzer | High | MFA Policy vorhanden |
| CA-002 | Legacy Auth blockiert | High | Block Legacy Authentication |
| CA-003 | Admin MFA Policy | High | Dedizierte Admin MFA Policy |
| CA-004 | Risky Sign-In Policy | Medium | Policy für riskante Anmeldungen |

### Identity Protection

| Check ID | Titel | Risk | Beschreibung |
|----------|-------|------|--------------|
| IDP-001 | Keine High Risk Users | High | Keine unbehandelten Risiko-User |
| IDP-002 | Risk Detections monitored | Medium | Überwachung von Risk Detections |

### Copilot (M365)

| Check ID | Titel | Risk | Beschreibung |
|----------|-------|------|--------------|
| COPILOT-001 | Sensitivity Labels | High | Labels konfiguriert |
| COPILOT-002 | DLP Policies | High | DLP vorhanden (Manual Review) |
| COPILOT-003 | Audit Logging | Medium | Audit Logs aktiviert |
| COPILOT-004 | Tenant Isolation | Medium | Gast-Zugriff eingeschränkt |

## Verwendung

### Vollständiges Assessment

```powershell
# Alle Kategorien prüfen
$results = Invoke-EntraSecurityAssessment

# Nur bestimmte Kategorien
$results = Invoke-EntraSecurityAssessment -Categories 'PIM', 'RBAC'
```

### Multi-Tenant Assessment

```powershell
$tenants = @("tenant1.onmicrosoft.com", "tenant2.onmicrosoft.com")
Invoke-MultiTenantAssessment -TenantIds $tenants -OutputPath "./Reports"
```

### Einzelne Kategorien

```powershell
# Nur PIM Checks
$pimResults = Invoke-PIMSecurityCheck

# Nur RBAC Checks
$rbacResults = Invoke-RBACSecurityCheck

# Nur Conditional Access
$caResults = Invoke-ConditionalAccessCheck
```

### Via Pester (Maester-kompatibel)

```powershell
# Alle Tests ausführen
Invoke-Pester ./src/Tests/Custom/*.Tests.ps1 -Output Detailed

# Nur bestimmte Tags
Invoke-Pester ./src/Tests/Custom/*.Tests.ps1 -Tag "PIM", "High"
```

## Reports

### HTML Report (Interaktiv)

```powershell
$results = Invoke-EntraSecurityAssessment
New-AssessmentReport -Results $results -Format HTML
```

Features:
- Security Score mit Progress Ring
- Dashboard mit Pass/Fail/Warning Statistiken
- Aufklappbare Kategorien
- Farbcodierte Risk/Status Badges
- Klickbare Details mit Remediation Links

### JSON Report (Automation)

```powershell
New-AssessmentReport -Results $results -Format JSON -OutputPath "C:\Reports"
```

### Markdown Report (Dokumentation)

```powershell
New-AssessmentReport -Results $results -Format Markdown
```

## Check-Ergebnis Format

```powershell
[PSCustomObject]@{
    CheckId     = 'PIM-001'
    Category    = 'PIM'
    Title       = 'Permanente privilegierte Zuweisungen'
    Risk        = 'High'        # High, Medium, Low, Info
    Status      = 'Failed'      # Passed, Failed, Warning, ManualReview, Error, Skipped
    Description = 'Permanent Global Admins: 5. Maximum recommended: 2'
    Remediation = 'Convert permanent assignments to eligible assignments in PIM.'
    Reference   = 'https://learn.microsoft.com/...'
    Details     = @{ PermanentGlobalAdmins = @('Admin1', 'Admin2') }
    Timestamp   = '2024-01-15T10:30:00Z'
    TenantId    = 'xxx-xxx-xxx'
}
```

## Projektstruktur

```
EntraSecurityAssessment/
├── src/
│   ├── EntraSecurityAssessment.psd1    # Module Manifest
│   ├── EntraSecurityAssessment.psm1    # Hauptmodul
│   ├── Core/
│   │   └── Connect-EntraAssessment.ps1 # Authentication
│   ├── Tests/
│   │   ├── Maester/                    # Standard Maester Tests
│   │   └── Custom/                     # Eigene Pester Tests
│   │       ├── PIM.Tests.ps1
│   │       ├── RBAC.Tests.ps1
│   │       ├── ConditionalAccess.Tests.ps1
│   │       ├── IdentityProtection.Tests.ps1
│   │       └── Copilot.Tests.ps1
│   ├── Reports/
│   │   └── New-AssessmentReport.ps1    # Report Generator
│   └── Config/
│       └── assessment-config.json      # Check Definitionen
├── docs/
├── CLAUDE.md                           # Projekt-Spezifikation
├── CLAUDE_CODE_PROMPTS.md              # Entwicklungs-Prompts
└── README.md
```

## Exportierte Funktionen

| Funktion | Beschreibung |
|----------|--------------|
| `Connect-EntraAssessment` | Verbindung zu Microsoft Graph |
| `Disconnect-EntraAssessment` | Verbindung trennen |
| `Test-EntraAssessmentConnection` | Verbindung prüfen |
| `Get-EntraAssessmentConnection` | Verbindungsinfo abrufen |
| `Invoke-EntraSecurityAssessment` | Vollständiges Assessment |
| `Invoke-MultiTenantAssessment` | Multi-Tenant Assessment |
| `Invoke-PIMSecurityCheck` | PIM Checks ausführen |
| `Invoke-RBACSecurityCheck` | RBAC Checks ausführen |
| `Invoke-ConditionalAccessCheck` | CA Checks ausführen |
| `Invoke-IdentityProtectionCheck` | IDP Checks ausführen |
| `Invoke-CopilotSecurityCheck` | Copilot Checks ausführen |
| `New-AssessmentReport` | Report generieren |

## Aliase

| Alias | Funktion |
|-------|----------|
| `esa` | `Invoke-EntraSecurityAssessment` |
| `cea` | `Connect-EntraAssessment` |

## Lizenzanforderungen

| Feature | Lizenz |
|---------|--------|
| RBAC, Conditional Access Basics | Azure AD Free |
| Conditional Access Policies | Azure AD Premium P1 |
| PIM, Identity Protection | Azure AD Premium P2 |
| Copilot Checks | Microsoft 365 Copilot |

## Risiko-Klassifizierung

| Level | Beschreibung | SLA |
|-------|--------------|-----|
| **High** | Kritische Sicherheitslücke | 24 Stunden |
| **Medium** | Wichtiges Sicherheitsproblem | 7 Tage |
| **Low** | Geringes Risiko | Bei Gelegenheit |
| **Info** | Informativ | Keine Aktion nötig |

## Troubleshooting

### 403 Forbidden Fehler

```powershell
# Fehlende Berechtigungen - erneut mit allen Scopes verbinden
Disconnect-EntraAssessment
Connect-EntraAssessment -TenantId "xxx" -Scopes @(
    'Directory.Read.All',
    'Policy.Read.All',
    'RoleManagement.Read.All'
    # ... weitere Scopes
)
```

### PIM Checks schlagen fehl

PIM erfordert Azure AD Premium P2 Lizenz. Bei fehlender Lizenz werden die Checks als "Error" markiert.

### Identity Protection nicht verfügbar

Identity Protection erfordert Azure AD Premium P2. Prüfen Sie die Lizenzierung.

## Weiterentwicklung

Siehe [CLAUDE_CODE_PROMPTS.md](CLAUDE_CODE_PROMPTS.md) für Prompts zur Erweiterung des Tools.

## Referenzen

- [Microsoft Entra ID Documentation](https://learn.microsoft.com/en-us/entra/)
- [Microsoft Graph API Reference](https://learn.microsoft.com/en-us/graph/api/overview)
- [Maester Framework](https://maester.dev)
- [Pester Testing Framework](https://pester.dev)

## Lizenz

MIT License - siehe LICENSE Datei.
