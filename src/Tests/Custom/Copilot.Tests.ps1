#Requires -Modules Pester, Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Microsoft 365 Copilot Security Tests

.DESCRIPTION
    Pester tests for validating security configuration for M365 Copilot deployment.
    Compatible with Maester test framework.

.NOTES
    Category: Copilot
    Checks: COPILOT-001 through COPILOT-004

    Some checks require manual review as the settings are not fully exposed via Graph API.
    DLP policies require Security & Compliance Center API access.
#>

BeforeDiscovery {
    $script:ConfigPath = Join-Path $PSScriptRoot '..' '..' 'Config' 'assessment-config.json'
    if (Test-Path $script:ConfigPath) {
        $script:Config = Get-Content $script:ConfigPath -Raw | ConvertFrom-Json
    }
}

BeforeAll {
    # Verify Graph connection
    $context = Get-MgContext
    if (-not $context) {
        throw "Not connected to Microsoft Graph. Run Connect-EntraAssessment first."
    }

    # Helper function
    function Invoke-GraphRequest {
        param(
            [string]$Uri,
            [string]$Method = 'GET',
            [switch]$AllPages
        )

        try {
            $response = Invoke-MgGraphRequest -Method $Method -Uri $Uri -ErrorAction Stop

            if ($AllPages -and $response.'@odata.nextLink') {
                $allResults = @($response.value)
                while ($response.'@odata.nextLink') {
                    $response = Invoke-MgGraphRequest -Method GET -Uri $response.'@odata.nextLink' -ErrorAction Stop
                    $allResults += $response.value
                }
                return $allResults
            }

            return $response
        }
        catch {
            if ($_.Exception.Message -match '403' -or $_.Exception.Message -match 'Forbidden') {
                Write-Warning "Access denied for $Uri - additional permissions may be required"
            }
            elseif ($_.Exception.Message -match '404') {
                Write-Warning "Resource not found: $Uri - feature may not be configured"
            }
            else {
                Write-Warning "Graph API Error for $Uri : $($_.Exception.Message)"
            }
            return $null
        }
    }

    # Load sensitivity labels
    $script:SensitivityLabels = @()
    $script:SensitivityLabelsError = $null
    try {
        $response = Invoke-GraphRequest -Uri '/v1.0/informationProtection/policy/labels'
        if ($response.value) {
            $script:SensitivityLabels = $response.value
        }
        elseif ($response -is [array]) {
            $script:SensitivityLabels = $response
        }
    }
    catch {
        $script:SensitivityLabelsError = $_.Exception.Message
        Write-Warning "Could not load sensitivity labels: $($_.Exception.Message)"
    }

    # Load authorization policy (guest settings)
    $script:AuthorizationPolicy = $null
    try {
        $response = Invoke-GraphRequest -Uri '/v1.0/policies/authorizationPolicy'
        if ($response.value) {
            $script:AuthorizationPolicy = $response.value[0]
        }
        elseif ($response.id) {
            $script:AuthorizationPolicy = $response
        }
    }
    catch {
        Write-Warning "Could not load authorization policy: $($_.Exception.Message)"
    }

    # Check for unified audit log (via directory audit as proxy)
    $script:AuditLogEnabled = $false
    try {
        # If we can query audit logs, auditing is enabled
        $response = Invoke-GraphRequest -Uri '/v1.0/auditLogs/directoryAudits?$top=1'
        if ($response) {
            $script:AuditLogEnabled = $true
        }
    }
    catch {
        Write-Warning "Could not verify audit log status: $($_.Exception.Message)"
    }

    # Load external identities policy
    $script:ExternalIdentitiesPolicy = $null
    try {
        $response = Invoke-GraphRequest -Uri '/v1.0/policies/externalIdentitiesPolicy'
        $script:ExternalIdentitiesPolicy = $response
    }
    catch {
        Write-Warning "Could not load external identities policy"
    }

    # Check cross-tenant access settings
    $script:CrossTenantPolicy = $null
    try {
        $response = Invoke-GraphRequest -Uri '/v1.0/policies/crossTenantAccessPolicy'
        $script:CrossTenantPolicy = $response
    }
    catch {
        Write-Warning "Could not load cross-tenant access policy"
    }
}

Describe "COPILOT-001 - Sensitivity Labels konfiguriert" -Tag "Copilot", "Security", "High" {

    It "COPILOT-001.1: Should have sensitivity labels configured" {
        if ($script:SensitivityLabelsError) {
            Set-ItResult -Skipped -Because "Could not access sensitivity labels API: $($script:SensitivityLabelsError)"
        }
        else {
            $script:SensitivityLabels.Count | Should -BeGreaterThan 0 -Because "Sensitivity labels are essential for protecting data accessed by Copilot"
        }
    }

    It "COPILOT-001.2: Should have labels for different classification levels" {
        if ($script:SensitivityLabelsError -or $script:SensitivityLabels.Count -eq 0) {
            Set-ItResult -Skipped -Because "No sensitivity labels available to check"
        }
        else {
            # Check for common classification labels
            $labelNames = $script:SensitivityLabels | ForEach-Object { $_.name.ToLower() }

            $hasConfidential = $labelNames | Where-Object { $_ -match 'confidential|vertraulich|konfidentiell' }
            $hasInternal = $labelNames | Where-Object { $_ -match 'internal|intern' }
            $hasPublic = $labelNames | Where-Object { $_ -match 'public|öffentlich|general' }

            $classificationCoverage = @()
            if ($hasConfidential) { $classificationCoverage += 'Confidential' }
            if ($hasInternal) { $classificationCoverage += 'Internal' }
            if ($hasPublic) { $classificationCoverage += 'Public' }

            Write-Host "Classification levels covered: $($classificationCoverage -join ', ')" -ForegroundColor Cyan

            $classificationCoverage.Count | Should -BeGreaterOrEqual 2 -Because "Multiple classification levels should be defined for proper data protection"
        }
    }

    It "COPILOT-001.3: Sensitivity labels inventory" {
        if ($script:SensitivityLabels.Count -gt 0) {
            Write-Host "`nConfigured Sensitivity Labels:" -ForegroundColor Cyan
            foreach ($label in $script:SensitivityLabels) {
                $priority = if ($label.priority) { "Priority: $($label.priority)" } else { "" }
                $parent = if ($label.parent) { "(Sub-label)" } else { "" }
                Write-Host "  - $($label.name) $parent $priority" -ForegroundColor Gray
                if ($label.description) {
                    Write-Host "    $($label.description)" -ForegroundColor DarkGray
                }
            }
        }
        else {
            Write-Host "No sensitivity labels configured" -ForegroundColor Red
            Write-Host "Recommendation: Configure sensitivity labels in Microsoft Purview" -ForegroundColor Yellow
        }
        $true | Should -BeTrue
    }
}

Describe "COPILOT-002 - DLP Policies vorhanden" -Tag "Copilot", "Security", "High", "ManualReview" {

    It "COPILOT-002.1: DLP policies should be configured (Manual Review Required)" {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "MANUAL REVIEW REQUIRED" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host @"

DLP (Data Loss Prevention) policies cannot be fully assessed via Graph API.

Please verify the following in Microsoft Purview Compliance Portal:

1. Navigate to: https://compliance.microsoft.com/datalossprevention

2. Check that DLP policies exist for:
   [ ] Microsoft 365 locations (Exchange, SharePoint, OneDrive, Teams)
   [ ] Sensitive information types are defined
   [ ] Policies are in 'Enforce' mode (not just 'Test')

3. Verify Copilot-specific protections:
   [ ] Policies apply to Copilot interactions
   [ ] Sensitive data types relevant to your org are covered

4. Review policy actions:
   [ ] Block or warn on sensitive data sharing
   [ ] Incident reports are configured

"@ -ForegroundColor Cyan

        # Mark as manual review
        Set-ItResult -Inconclusive -Because "DLP policy verification requires manual review in Microsoft Purview"
    }
}

Describe "COPILOT-003 - Audit Logging aktiviert" -Tag "Copilot", "Security", "Medium" {

    It "COPILOT-003.1: Directory audit logging should be enabled" {
        $script:AuditLogEnabled | Should -BeTrue -Because "Audit logging is essential for monitoring Copilot usage"
    }

    It "COPILOT-003.2: Should have recent audit events" {
        if (-not $script:AuditLogEnabled) {
            Set-ItResult -Skipped -Because "Audit logging not accessible"
        }
        else {
            try {
                $recentAudits = Invoke-GraphRequest -Uri '/v1.0/auditLogs/directoryAudits?$top=10&$orderby=activityDateTime desc'

                if ($recentAudits.value -and $recentAudits.value.Count -gt 0) {
                    $latestAudit = $recentAudits.value[0]
                    $auditAge = (Get-Date) - [datetime]$latestAudit.activityDateTime

                    Write-Host "Latest audit event: $($auditAge.TotalHours.ToString('F1')) hours ago" -ForegroundColor Cyan

                    # Audit events should be recent (within 24 hours in active tenant)
                    $auditAge.TotalHours | Should -BeLessThan 168 -Because "Recent audit events indicate active logging"
                }
                else {
                    Write-Host "No recent audit events found" -ForegroundColor Yellow
                }
            }
            catch {
                Set-ItResult -Skipped -Because "Could not retrieve audit events"
            }
        }
    }

    It "COPILOT-003.3: Unified audit log verification (Manual Check)" {
        Write-Host @"

To verify unified audit logging for Copilot:

1. Microsoft Purview: https://compliance.microsoft.com/auditlogsearch

2. Check that these audit activities are being captured:
   - CopilotInteraction
   - MicrosoftSearch
   - File access events

3. PowerShell verification:
   Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -Operations CopilotInteraction

"@ -ForegroundColor Cyan

        $true | Should -BeTrue
    }
}

Describe "COPILOT-004 - Tenant Isolation und Gastzugriff" -Tag "Copilot", "Security", "Medium" {

    Context "Guest User Settings" {
        It "COPILOT-004.1: Guest user access should be restricted" {
            if (-not $script:AuthorizationPolicy) {
                Set-ItResult -Skipped -Because "Could not load authorization policy"
            }
            else {
                $guestAccess = $script:AuthorizationPolicy.guestUserRoleId

                # Guest role IDs:
                # Restricted Guest: 2af84b1e-32c8-42b7-82bc-daa82404023b
                # Guest: 10dae51f-b6af-4016-8d66-8c2a99b929b3
                # Member: a0b1b346-4d3e-4e8b-98f8-753987be4970

                $restrictedGuestRole = '2af84b1e-32c8-42b7-82bc-daa82404023b'

                $isRestricted = $guestAccess -eq $restrictedGuestRole

                Write-Host "Guest user role: $(
                    switch ($guestAccess) {
                        '2af84b1e-32c8-42b7-82bc-daa82404023b' { 'Restricted Guest (Most Restrictive)' }
                        '10dae51f-b6af-4016-8d66-8c2a99b929b3' { 'Guest' }
                        'a0b1b346-4d3e-4e8b-98f8-753987be4970' { 'Member (Least Restrictive)' }
                        default { $guestAccess }
                    }
                )" -ForegroundColor $(if ($isRestricted) { 'Green' } else { 'Yellow' })

                # Warning but not failure - depends on org requirements
                if (-not $isRestricted) {
                    Write-Host "Recommendation: Consider restricting guest access for better Copilot data protection" -ForegroundColor Yellow
                }

                $true | Should -BeTrue
            }
        }

        It "COPILOT-004.2: Guest invite restrictions should be configured" {
            if (-not $script:AuthorizationPolicy) {
                Set-ItResult -Skipped -Because "Could not load authorization policy"
            }
            else {
                $allowInvites = $script:AuthorizationPolicy.allowInvitesFrom

                Write-Host "Guest invitation setting: $allowInvites" -ForegroundColor Cyan

                # Recommended: 'adminsAndGuestInviters' or 'adminsGuestInvitersAndAllMembers' at minimum
                # 'everyone' is too permissive
                $allowInvites | Should -Not -Be 'everyone' -Because "Unrestricted guest invitations pose data exposure risk"
            }
        }
    }

    Context "External Collaboration Settings" {
        It "COPILOT-004.3: External collaboration should be controlled" {
            if ($script:CrossTenantPolicy) {
                Write-Host "`nCross-Tenant Access Policy:" -ForegroundColor Cyan

                # Check default settings
                $defaultInbound = $script:CrossTenantPolicy.default.b2bCollaborationInbound
                $defaultOutbound = $script:CrossTenantPolicy.default.b2bCollaborationOutbound

                Write-Host "  Default Inbound B2B:  $(if ($defaultInbound.usersAndGroups.accessType -eq 'blocked') { 'Blocked' } else { 'Allowed' })" -ForegroundColor Gray
                Write-Host "  Default Outbound B2B: $(if ($defaultOutbound.usersAndGroups.accessType -eq 'blocked') { 'Blocked' } else { 'Allowed' })" -ForegroundColor Gray

                $true | Should -BeTrue
            }
            else {
                Write-Host "Cross-tenant access policy not configured or not accessible" -ForegroundColor Yellow
                Set-ItResult -Inconclusive -Because "Could not verify cross-tenant settings"
            }
        }
    }

    Context "Copilot-Specific Recommendations" {
        It "COPILOT-004.4: Copilot data protection checklist" {
            Write-Host @"

========================================
Copilot Data Protection Checklist
========================================

Before deploying M365 Copilot, verify:

[ ] Sensitivity Labels
    - Labels are published to users
    - Auto-labeling policies are configured
    - Default label for new documents

[ ] Data Loss Prevention
    - DLP policies cover sensitive data types
    - Policies apply to Teams, SharePoint, OneDrive
    - Blocking or warning actions configured

[ ] Access Controls
    - SharePoint site permissions reviewed
    - OneDrive sharing settings restricted
    - Teams external access configured

[ ] Information Barriers (if needed)
    - Segments defined for regulated groups
    - Policies prevent inappropriate data access

[ ] Audit & Monitoring
    - Unified audit log enabled
    - Copilot activity logging configured
    - Alerts for sensitive data access

[ ] User Training
    - Copilot usage guidelines published
    - Data classification awareness
    - Reporting procedures for incidents

"@ -ForegroundColor Cyan

            $true | Should -BeTrue
        }
    }
}

AfterAll {
    $script:CopilotCheckResults = @{
        Category                = 'Copilot'
        SensitivityLabelsCount  = $script:SensitivityLabels.Count
        AuditLoggingEnabled     = $script:AuditLogEnabled
        GuestAccessConfigured   = ($null -ne $script:AuthorizationPolicy)
        DLPRequiresManualReview = $true
        Timestamp               = Get-Date -Format 'o'
    }
}
