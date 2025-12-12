# Claude Code Starter Prompts

## 🚀 Initial Project Setup Prompt

Kopiere diesen Prompt in Claude Code um das Projekt zu starten:

---

```
Erstelle ein PowerShell Security Assessment Tool für Microsoft Entra ID und M365.

Das Tool soll:
1. Auf Maester/Pester basieren für Test-Automation
2. Multi-Tenant Support haben (Azure Lighthouse kompatibel)
3. Folgende Security Checks durchführen:
   - PIM: Permanente Zuweisungen, Approval, Aktivierungsdauer
   - RBAC: Global Admin Count, Gäste mit Admin-Rollen
   - Conditional Access: MFA, Legacy Auth Block
   - Identity Protection: Risky Users
   - Copilot: Sensitivity Labels, DLP

Projektstruktur:
- src/EntraSecurityAssessment.psm1 (Hauptmodul)
- src/Core/Connect-EntraAssessment.ps1 (Auth)
- src/Tests/Custom/*.Tests.ps1 (Pester Tests)
- src/Reports/New-AssessmentReport.ps1 (HTML Report)

Nutze Microsoft Graph API für alle Abfragen.
Jeder Check soll ein PSCustomObject zurückgeben mit:
CheckId, Category, Title, Risk (High/Medium/Low), Status (Failed/Passed), Description, Remediation

Starte mit der Projektstruktur und dem Connect-EntraAssessment.ps1
```

---

## 📝 Follow-up Prompts

### Nach dem initialen Setup:

```
Erstelle jetzt die PIM.Tests.ps1 mit folgenden Checks:
- PIM-001: Permanente privilegierte Zuweisungen (prüfe Global Admin, Security Admin, Privileged Role Admin)
- PIM-002: Approval Requirements für kritische Rollen
- PIM-003: Aktivierungsdauer maximal 8 Stunden

Nutze diese Graph API Endpoints:
- GET /v1.0/directoryRoles/{id}/members
- GET /v1.0/policies/roleManagementPolicies
- GET /v1.0/roleManagement/directory/roleEligibilityScheduleInstances

Format als Maester-kompatible Pester Tests mit Describe/Context/It Blöcken.
```

---

```
Erstelle die RBAC.Tests.ps1 mit:
- RBAC-001: Global Admins zwischen 2-5
- RBAC-002: Keine Gast-Benutzer mit Admin-Rollen
- RBAC-003: Keine Service Principals als Global Admin
- RBAC-004: Verhältnis privilegierter Benutzer < 5%

Prüfe diese kritischen Rollen:
- Global Administrator
- Privileged Role Administrator  
- Security Administrator
- Exchange Administrator
- SharePoint Administrator
- User Administrator
```

---

```
Erstelle die Copilot.Tests.ps1 mit:
- COPILOT-001: Sensitivity Labels konfiguriert (GET /v1.0/informationProtection/policy/labels)
- COPILOT-002: DLP Policies Check (Manual Review da S&C API nötig)
- COPILOT-003: Audit Logging aktiviert
- COPILOT-004: Guest User Access eingeschränkt (authorizationPolicy)

Da einige Copilot-Settings nicht über Graph API verfügbar sind, 
nutze Status "ManualReview" für diese Checks.
```

---

```
Erstelle New-AssessmentReport.ps1 der einen interaktiven HTML Report generiert:
- Dashboard mit High/Medium/Low/Passed Statistiken
- Aufklappbare Sections pro Risiko-Level
- Jedes Finding mit CheckId, Titel, Beschreibung, Remediation
- Links zu Microsoft Docs
- Professionelles Design (dunkelblau Header, farbcodierte Risk Badges)
```

---

```
Erstelle das Hauptmodul EntraSecurityAssessment.psm1 das:
- Alle Funktionen aus Core/, Tests/, Reports/ importiert
- Invoke-EntraSecurityAssessment als Hauptfunktion bereitstellt
- Multi-Tenant Support über -TenantIds Parameter hat
- Ergebnisse sammelt und an New-AssessmentReport übergibt

Exportiere diese Funktionen:
- Connect-EntraAssessment
- Invoke-EntraSecurityAssessment  
- Invoke-PIMSecurityCheck
- Invoke-RBACSecurityCheck
- Invoke-ConditionalAccessCheck
- New-AssessmentReport
```

---

## 🔧 Debugging Prompts

```
Der Graph API Call für PIM Policies gibt einen 403 Fehler. 
Welche Scopes brauche ich für /v1.0/policies/roleManagementPolicies?
Und braucht der Tenant eine P2 Lizenz dafür?
```

```
Die Pester Tests laufen nicht mit Maester zusammen.
Wie muss ich die Tests strukturieren damit sie von Invoke-Maester gefunden werden?
```

```
Der HTML Report zeigt die Findings nicht richtig an.
Prüfe die New-AssessmentReport Funktion und fixe das HTML Template.
```

---

## 🎯 MCP Integration Prompt (Optional)

```
Erstelle eine MCP Tool Definition in TypeScript für das Entra Security Assessment.

Das Tool soll:
- entra_security_assessment heißen
- Parameter: tenantId (optional), checks (array), riskLevel (enum)
- Die PowerShell Funktion Invoke-EntraSecurityAssessment aufrufen
- Ergebnisse als JSON zurückgeben

Erstelle auch Helper-Tools:
- get_pim_status
- get_global_admins
- get_risky_users

Diese sollen in meinen Sentinel MCP Server integriert werden.
```

---

## 💡 Tipps für Claude Code

1. **Arbeite inkrementell** - Ein Feature nach dem anderen
2. **Teste nach jedem Schritt** - `Invoke-Pester` für Tests
3. **Nutze einen Test-Tenant** - Nicht in Production testen
4. **Error Handling** - Graph API kann verschiedene Fehler werfen
5. **Maester Docs** - https://maester.dev für Referenz

Viel Erfolg! 🚀
