#Requires -Modules Pester, Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Conditional Access Security Tests

.DESCRIPTION
    Pester tests for validating Conditional Access policy configuration.
    Compatible with Maester test framework.

.NOTES
    Category: ConditionalAccess
    Checks: CA-001 through CA-004
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
            Write-Warning "Graph API Error for $Uri : $($_.Exception.Message)"
            return $null
        }
    }

    # Admin role IDs for policy checks
    $script:AdminRoleIds = @(
        '62e90394-69f5-4237-9190-012177145e10'  # Global Administrator
        'e8611ab8-c189-46e8-94e1-60213ab1f814'  # Privileged Role Administrator
        '194ae4cb-b126-40b2-bd5b-6091b380977d'  # Security Administrator
        'fe930be7-5e62-47db-91af-98c3a49a38b1'  # User Administrator
        '29232cdf-9323-42fd-ade2-1d097af3e4de'  # Exchange Administrator
        'f28a1f50-f6e7-4571-818b-6a12f2af6b6c'  # SharePoint Administrator
    )

    # Load Conditional Access policies
    $script:CAPolicies = @()
    try {
        $response = Invoke-GraphRequest -Uri '/v1.0/identity/conditionalAccess/policies'
        if ($response.value) {
            $script:CAPolicies = $response.value
        }
    }
    catch {
        Write-Warning "Could not load Conditional Access policies: $($_.Exception.Message)"
    }

    # Filter enabled policies
    $script:EnabledPolicies = $script:CAPolicies | Where-Object { $_.state -eq 'enabled' }

    # Helper to check if policy targets all users
    function Test-PolicyTargetsAllUsers {
        param($Policy)

        $conditions = $Policy.conditions
        if (-not $conditions -or -not $conditions.users) { return $false }

        $users = $conditions.users
        return ($users.includeUsers -contains 'All') -or
               ($users.includeGroups -and $users.includeGroups.Count -gt 0 -and -not $users.excludeUsers)
    }

    # Helper to check if policy requires MFA
    function Test-PolicyRequiresMFA {
        param($Policy)

        $grantControls = $Policy.grantControls
        if (-not $grantControls) { return $false }

        return ($grantControls.builtInControls -contains 'mfa') -or
               ($grantControls.authenticationStrength -ne $null)
    }

    # Helper to check if policy blocks legacy auth
    function Test-PolicyBlocksLegacyAuth {
        param($Policy)

        $conditions = $Policy.conditions
        $grantControls = $Policy.grantControls

        # Check if targets legacy clients
        $targetsLegacy = $conditions.clientAppTypes -contains 'exchangeActiveSync' -or
                        $conditions.clientAppTypes -contains 'other'

        # Check if blocks access
        $blocksAccess = $grantControls.builtInControls -contains 'block'

        return $targetsLegacy -and $blocksAccess
    }

    # Helper to check if policy targets admin roles
    function Test-PolicyTargetsAdmins {
        param($Policy)

        $conditions = $Policy.conditions
        if (-not $conditions -or -not $conditions.users) { return $false }

        $users = $conditions.users

        # Check if includes admin roles
        if ($users.includeRoles) {
            foreach ($roleId in $script:AdminRoleIds) {
                if ($users.includeRoles -contains $roleId) {
                    return $true
                }
            }
        }

        return $false
    }

    # Helper to check if policy addresses sign-in risk
    function Test-PolicyAddressesSignInRisk {
        param($Policy)

        $conditions = $Policy.conditions
        if (-not $conditions) { return $false }

        return ($conditions.signInRiskLevels -and $conditions.signInRiskLevels.Count -gt 0)
    }
}

Describe "CA-001 - MFA für alle Benutzer" -Tag "ConditionalAccess", "Security", "High" {

    BeforeAll {
        # Find policies that require MFA for all users
        $script:MFAAllUsersPolicies = $script:EnabledPolicies | Where-Object {
            (Test-PolicyTargetsAllUsers -Policy $_) -and (Test-PolicyRequiresMFA -Policy $_)
        }

        # Also check for policies targeting all cloud apps
        $script:MFAAllAppsPolicies = $script:EnabledPolicies | Where-Object {
            $_.conditions.applications.includeApplications -contains 'All' -and
            (Test-PolicyRequiresMFA -Policy $_)
        }
    }

    It "CA-001.1: Should have an MFA policy targeting all users" {
        $hasMFAPolicy = ($script:MFAAllUsersPolicies.Count -gt 0) -or ($script:MFAAllAppsPolicies.Count -gt 0)
        $hasMFAPolicy | Should -BeTrue -Because "All users should be required to use MFA"
    }

    It "CA-001.2: MFA policy should cover all cloud applications" {
        $allAppsMFA = $script:EnabledPolicies | Where-Object {
            $_.conditions.applications.includeApplications -contains 'All' -and
            (Test-PolicyRequiresMFA -Policy $_) -and
            ($_.conditions.users.includeUsers -contains 'All' -or $_.conditions.users.includeGroups)
        }

        if ($allAppsMFA.Count -gt 0) {
            Write-Host "MFA policies covering all apps: $($allAppsMFA.displayName -join ', ')" -ForegroundColor Green
        }

        $allAppsMFA.Count | Should -BeGreaterThan 0 -Because "MFA should be required for all cloud applications"
    }

    It "CA-001.3: MFA policies inventory" {
        $mfaPolicies = $script:EnabledPolicies | Where-Object { Test-PolicyRequiresMFA -Policy $_ }

        Write-Host "`nMFA-enabled policies ($($mfaPolicies.Count)):" -ForegroundColor Cyan
        foreach ($policy in $mfaPolicies) {
            $targetUsers = if ($policy.conditions.users.includeUsers -contains 'All') { 'All Users' }
                          elseif ($policy.conditions.users.includeGroups) { "$($policy.conditions.users.includeGroups.Count) Groups" }
                          else { 'Specific' }

            $targetApps = if ($policy.conditions.applications.includeApplications -contains 'All') { 'All Apps' }
                         else { "$($policy.conditions.applications.includeApplications.Count) Apps" }

            Write-Host "  - $($policy.displayName): $targetUsers -> $targetApps" -ForegroundColor Gray
        }
        $true | Should -BeTrue
    }
}

Describe "CA-002 - Legacy Authentication blockiert" -Tag "ConditionalAccess", "Security", "High" {

    BeforeAll {
        # Find policies that block legacy authentication
        $script:LegacyAuthBlockPolicies = $script:EnabledPolicies | Where-Object {
            Test-PolicyBlocksLegacyAuth -Policy $_
        }

        # Also check for broader legacy auth blocking
        $script:BroadLegacyBlock = $script:EnabledPolicies | Where-Object {
            $_.conditions.clientAppTypes -contains 'other' -and
            $_.grantControls.builtInControls -contains 'block' -and
            ($_.conditions.users.includeUsers -contains 'All')
        }
    }

    It "CA-002.1: Should have a policy blocking legacy authentication" {
        $hasLegacyBlock = ($script:LegacyAuthBlockPolicies.Count -gt 0) -or ($script:BroadLegacyBlock.Count -gt 0)

        if ($hasLegacyBlock) {
            Write-Host "Legacy auth block policies found" -ForegroundColor Green
        }

        $hasLegacyBlock | Should -BeTrue -Because "Legacy authentication protocols should be blocked"
    }

    It "CA-002.2: Legacy auth block should apply to all users" {
        $allUsersLegacyBlock = $script:EnabledPolicies | Where-Object {
            ($_.conditions.clientAppTypes -contains 'other' -or $_.conditions.clientAppTypes -contains 'exchangeActiveSync') -and
            $_.grantControls.builtInControls -contains 'block' -and
            $_.conditions.users.includeUsers -contains 'All'
        }

        $allUsersLegacyBlock.Count | Should -BeGreaterThan 0 -Because "Legacy auth block should cover all users"
    }

    It "CA-002.3: List legacy authentication policies" {
        $legacyPolicies = $script:EnabledPolicies | Where-Object {
            $_.conditions.clientAppTypes -contains 'other' -or
            $_.conditions.clientAppTypes -contains 'exchangeActiveSync'
        }

        if ($legacyPolicies.Count -gt 0) {
            Write-Host "`nPolicies addressing legacy auth:" -ForegroundColor Cyan
            foreach ($policy in $legacyPolicies) {
                $action = if ($policy.grantControls.builtInControls -contains 'block') { 'BLOCK' } else { 'Allow with controls' }
                Write-Host "  - $($policy.displayName): $action" -ForegroundColor Gray
            }
        }
        else {
            Write-Host "No legacy auth policies found!" -ForegroundColor Red
        }
        $true | Should -BeTrue
    }
}

Describe "CA-003 - Admin MFA Policy vorhanden" -Tag "ConditionalAccess", "Security", "High" {

    BeforeAll {
        # Find policies specifically targeting admin roles with MFA
        $script:AdminMFAPolicies = $script:EnabledPolicies | Where-Object {
            (Test-PolicyTargetsAdmins -Policy $_) -and (Test-PolicyRequiresMFA -Policy $_)
        }

        # Also check if "All Users" MFA policy exists (covers admins)
        $script:AllUsersMFACoversAdmins = $script:EnabledPolicies | Where-Object {
            $_.conditions.users.includeUsers -contains 'All' -and
            (Test-PolicyRequiresMFA -Policy $_) -and
            -not ($_.conditions.users.excludeRoles | Where-Object { $_ -in $script:AdminRoleIds })
        }
    }

    It "CA-003.1: Should have MFA policy for administrative roles" {
        $hasAdminMFA = ($script:AdminMFAPolicies.Count -gt 0) -or ($script:AllUsersMFACoversAdmins.Count -gt 0)

        $hasAdminMFA | Should -BeTrue -Because "Administrative roles must require MFA"
    }

    It "CA-003.2: Admin MFA policy should cover critical roles" {
        $criticalRolesCovered = @{
            'Global Administrator' = $false
            'Privileged Role Administrator' = $false
            'Security Administrator' = $false
        }

        foreach ($policy in $script:AdminMFAPolicies) {
            if ($policy.conditions.users.includeRoles -contains '62e90394-69f5-4237-9190-012177145e10') {
                $criticalRolesCovered['Global Administrator'] = $true
            }
            if ($policy.conditions.users.includeRoles -contains 'e8611ab8-c189-46e8-94e1-60213ab1f814') {
                $criticalRolesCovered['Privileged Role Administrator'] = $true
            }
            if ($policy.conditions.users.includeRoles -contains '194ae4cb-b126-40b2-bd5b-6091b380977d') {
                $criticalRolesCovered['Security Administrator'] = $true
            }
        }

        # If there's an all-users MFA policy, all roles are covered
        if ($script:AllUsersMFACoversAdmins.Count -gt 0) {
            $criticalRolesCovered.Keys | ForEach-Object { $criticalRolesCovered[$_] = $true }
        }

        $uncovered = $criticalRolesCovered.GetEnumerator() | Where-Object { -not $_.Value } | Select-Object -ExpandProperty Key

        if ($uncovered.Count -gt 0) {
            Write-Host "Roles without dedicated MFA policy: $($uncovered -join ', ')" -ForegroundColor Yellow
        }

        $uncovered.Count | Should -Be 0 -Because "All critical admin roles should be covered by MFA policy"
    }

    It "CA-003.3: Admin MFA policies summary" {
        Write-Host "`nAdmin-targeted MFA policies:" -ForegroundColor Cyan

        if ($script:AdminMFAPolicies.Count -gt 0) {
            foreach ($policy in $script:AdminMFAPolicies) {
                Write-Host "  - $($policy.displayName)" -ForegroundColor Gray
            }
        }
        elseif ($script:AllUsersMFACoversAdmins.Count -gt 0) {
            Write-Host "  Admins covered by all-users MFA policy" -ForegroundColor Green
        }
        else {
            Write-Host "  No admin-specific MFA policies found!" -ForegroundColor Red
        }

        $true | Should -BeTrue
    }
}

Describe "CA-004 - Risky Sign-In Policy aktiv" -Tag "ConditionalAccess", "Security", "Medium" {

    BeforeAll {
        # Find policies that address sign-in risk
        $script:RiskPolicies = $script:EnabledPolicies | Where-Object {
            Test-PolicyAddressesSignInRisk -Policy $_
        }

        # Find policies addressing user risk
        $script:UserRiskPolicies = $script:EnabledPolicies | Where-Object {
            $_.conditions.userRiskLevels -and $_.conditions.userRiskLevels.Count -gt 0
        }
    }

    It "CA-004.1: Should have a policy addressing risky sign-ins" {
        $script:RiskPolicies.Count | Should -BeGreaterThan 0 -Because "Risky sign-ins should be addressed by Conditional Access"
    }

    It "CA-004.2: Risky sign-in policy should require MFA or block" {
        $effectiveRiskPolicies = $script:RiskPolicies | Where-Object {
            $_.grantControls.builtInControls -contains 'mfa' -or
            $_.grantControls.builtInControls -contains 'block' -or
            $_.grantControls.builtInControls -contains 'passwordChange'
        }

        if ($script:RiskPolicies.Count -gt 0) {
            $effectiveRiskPolicies.Count | Should -BeGreaterThan 0 -Because "Risky sign-in policy should enforce MFA or block access"
        }
        else {
            Set-ItResult -Skipped -Because "No sign-in risk policies found"
        }
    }

    It "CA-004.3: Should address high-risk sign-ins" {
        $highRiskPolicies = $script:RiskPolicies | Where-Object {
            $_.conditions.signInRiskLevels -contains 'high'
        }

        if ($script:RiskPolicies.Count -gt 0) {
            $highRiskPolicies.Count | Should -BeGreaterThan 0 -Because "High-risk sign-ins must be addressed"
        }
        else {
            Set-ItResult -Skipped -Because "No sign-in risk policies found"
        }
    }

    It "CA-004.4: Risk-based policies summary" {
        Write-Host "`nRisk-based Conditional Access policies:" -ForegroundColor Cyan

        if ($script:RiskPolicies.Count -gt 0) {
            foreach ($policy in $script:RiskPolicies) {
                $riskLevels = $policy.conditions.signInRiskLevels -join ', '
                $action = $policy.grantControls.builtInControls -join ', '
                Write-Host "  - $($policy.displayName): Risk levels [$riskLevels] -> $action" -ForegroundColor Gray
            }
        }
        else {
            Write-Host "  No sign-in risk policies configured" -ForegroundColor Yellow
        }

        if ($script:UserRiskPolicies.Count -gt 0) {
            Write-Host "`nUser risk policies:" -ForegroundColor Cyan
            foreach ($policy in $script:UserRiskPolicies) {
                $riskLevels = $policy.conditions.userRiskLevels -join ', '
                Write-Host "  - $($policy.displayName): Risk levels [$riskLevels]" -ForegroundColor Gray
            }
        }

        $true | Should -BeTrue
    }
}

Describe "CA-SUMMARY - Conditional Access Overview" -Tag "ConditionalAccess", "Info" {

    It "CA-SUMMARY: Policy statistics" {
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "Conditional Access Summary" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "Total policies:   $($script:CAPolicies.Count)" -ForegroundColor White
        Write-Host "Enabled policies: $($script:EnabledPolicies.Count)" -ForegroundColor Green
        Write-Host "Disabled/Report:  $($script:CAPolicies.Count - $script:EnabledPolicies.Count)" -ForegroundColor Gray

        $reportOnlyPolicies = $script:CAPolicies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' }
        if ($reportOnlyPolicies.Count -gt 0) {
            Write-Host "`nReport-only policies ($($reportOnlyPolicies.Count)):" -ForegroundColor Yellow
            $reportOnlyPolicies | ForEach-Object { Write-Host "  - $($_.displayName)" -ForegroundColor Yellow }
        }

        $true | Should -BeTrue
    }
}

AfterAll {
    $script:CACheckResults = @{
        Category           = 'ConditionalAccess'
        TotalPolicies      = $script:CAPolicies.Count
        EnabledPolicies    = $script:EnabledPolicies.Count
        MFAPolicies        = ($script:EnabledPolicies | Where-Object { Test-PolicyRequiresMFA -Policy $_ }).Count
        RiskPolicies       = $script:RiskPolicies.Count
        Timestamp          = Get-Date -Format 'o'
    }
}
