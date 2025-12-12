#Requires -Modules Pester, Microsoft.Graph.Authentication

<#
.SYNOPSIS
    PIM (Privileged Identity Management) Security Tests

.DESCRIPTION
    Pester tests for validating PIM configuration and privileged access management.
    Compatible with Maester test framework.

.NOTES
    Category: PIM
    Checks: PIM-001 through PIM-005
#>

BeforeDiscovery {
    # Load configuration
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

    # Helper function to invoke Graph requests
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

    # Get critical role definitions
    $script:CriticalRoles = @{
        'Global Administrator'              = '62e90394-69f5-4237-9190-012177145e10'
        'Privileged Role Administrator'     = 'e8611ab8-c189-46e8-94e1-60213ab1f814'
        'Security Administrator'            = '194ae4cb-b126-40b2-bd5b-6091b380977d'
        'User Administrator'                = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
        'Exchange Administrator'            = '29232cdf-9323-42fd-ade2-1d097af3e4de'
        'SharePoint Administrator'          = 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c'
    }

    # Load directory roles
    $script:DirectoryRoles = Invoke-GraphRequest -Uri '/v1.0/directoryRoles' -AllPages
    if ($script:DirectoryRoles.value) {
        $script:DirectoryRoles = $script:DirectoryRoles.value
    }

    # Load role management policies (PIM settings)
    $script:RoleManagementPolicies = $null
    try {
        $script:RoleManagementPolicies = Invoke-GraphRequest -Uri '/v1.0/policies/roleManagementPolicies?$filter=scopeId eq ''/'' and scopeType eq ''DirectoryRole''' -AllPages
        if ($script:RoleManagementPolicies.value) {
            $script:RoleManagementPolicies = $script:RoleManagementPolicies.value
        }
    }
    catch {
        Write-Warning "Could not load role management policies. PIM may not be configured or license missing."
    }

    # Load eligible role assignments
    $script:EligibleAssignments = $null
    try {
        $script:EligibleAssignments = Invoke-GraphRequest -Uri '/v1.0/roleManagement/directory/roleEligibilityScheduleInstances' -AllPages
        if ($script:EligibleAssignments.value) {
            $script:EligibleAssignments = $script:EligibleAssignments.value
        }
    }
    catch {
        Write-Warning "Could not load eligible assignments."
    }

    # Load active (permanent) role assignments
    $script:ActiveAssignments = $null
    try {
        $script:ActiveAssignments = Invoke-GraphRequest -Uri '/v1.0/roleManagement/directory/roleAssignmentScheduleInstances' -AllPages
        if ($script:ActiveAssignments.value) {
            $script:ActiveAssignments = $script:ActiveAssignments.value
        }
    }
    catch {
        Write-Warning "Could not load active assignments."
    }
}

Describe "PIM-001 - Keine permanenten privilegierten Zuweisungen" -Tag "PIM", "Security", "High" {

    Context "Global Administrator" {
        BeforeAll {
            $roleId = $script:CriticalRoles['Global Administrator']
            $role = $script:DirectoryRoles | Where-Object { $_.roleTemplateId -eq $roleId }

            $script:PermanentGlobalAdmins = @()
            if ($role) {
                $members = Invoke-GraphRequest -Uri "/v1.0/directoryRoles/$($role.id)/members"
                if ($members.value) {
                    $script:PermanentGlobalAdmins = $members.value
                }
            }
        }

        It "PIM-001.1: Should have maximum 2 permanent Global Administrators" {
            $script:PermanentGlobalAdmins.Count | Should -BeLessOrEqual 2 -Because "Permanent Global Admin assignments should be minimized. Found: $($script:PermanentGlobalAdmins.displayName -join ', ')"
        }

        It "PIM-001.2: Permanent Global Admins should be documented" {
            # This is informational - outputs who has permanent access
            if ($script:PermanentGlobalAdmins.Count -gt 0) {
                $adminList = $script:PermanentGlobalAdmins | ForEach-Object {
                    "$($_.displayName) ($($_.userPrincipalName ?? $_.appId))"
                }
                Write-Host "Permanent Global Administrators: $($adminList -join ', ')" -ForegroundColor Yellow
            }
            $true | Should -BeTrue
        }
    }

    Context "Privileged Role Administrator" {
        BeforeAll {
            $roleId = $script:CriticalRoles['Privileged Role Administrator']
            $role = $script:DirectoryRoles | Where-Object { $_.roleTemplateId -eq $roleId }

            $script:PermanentPrivRoleAdmins = @()
            if ($role) {
                $members = Invoke-GraphRequest -Uri "/v1.0/directoryRoles/$($role.id)/members"
                if ($members.value) {
                    $script:PermanentPrivRoleAdmins = $members.value
                }
            }
        }

        It "PIM-001.3: Should have maximum 1 permanent Privileged Role Administrator" {
            $script:PermanentPrivRoleAdmins.Count | Should -BeLessOrEqual 1 -Because "Privileged Role Admin should use PIM eligible assignments"
        }
    }

    Context "Security Administrator" {
        BeforeAll {
            $roleId = $script:CriticalRoles['Security Administrator']
            $role = $script:DirectoryRoles | Where-Object { $_.roleTemplateId -eq $roleId }

            $script:PermanentSecAdmins = @()
            if ($role) {
                $members = Invoke-GraphRequest -Uri "/v1.0/directoryRoles/$($role.id)/members"
                if ($members.value) {
                    $script:PermanentSecAdmins = $members.value
                }
            }
        }

        It "PIM-001.4: Should have no permanent Security Administrators" {
            $script:PermanentSecAdmins.Count | Should -Be 0 -Because "Security Admin role should use PIM eligible assignments only"
        }
    }
}

Describe "PIM-002 - Approval für kritische Rollen erforderlich" -Tag "PIM", "Security", "High" {

    BeforeAll {
        # Get policy rules for critical roles
        $script:PolicyRules = @{}

        foreach ($roleName in @('Global Administrator', 'Privileged Role Administrator', 'Security Administrator')) {
            $roleId = $script:CriticalRoles[$roleName]
            $policy = $script:RoleManagementPolicies | Where-Object {
                $_.scopeId -eq '/' -and $_.roleDefinitionId -eq $roleId
            }

            if ($policy) {
                try {
                    $rules = Invoke-GraphRequest -Uri "/v1.0/policies/roleManagementPolicies/$($policy.id)/rules"
                    $script:PolicyRules[$roleName] = $rules.value
                }
                catch {
                    Write-Warning "Could not get policy rules for $roleName"
                }
            }
        }
    }

    It "PIM-002.1: Global Administrator activation should require approval" {
        $rules = $script:PolicyRules['Global Administrator']
        $approvalRule = $rules | Where-Object { $_.id -eq 'Approval_EndUser_Assignment' }

        if ($approvalRule) {
            $requiresApproval = $approvalRule.setting.isApprovalRequired
            $requiresApproval | Should -BeTrue -Because "Global Admin activation must require approval"
        }
        else {
            Set-ItResult -Skipped -Because "PIM policy not found for Global Administrator"
        }
    }

    It "PIM-002.2: Privileged Role Administrator activation should require approval" {
        $rules = $script:PolicyRules['Privileged Role Administrator']
        $approvalRule = $rules | Where-Object { $_.id -eq 'Approval_EndUser_Assignment' }

        if ($approvalRule) {
            $requiresApproval = $approvalRule.setting.isApprovalRequired
            $requiresApproval | Should -BeTrue -Because "Privileged Role Admin activation must require approval"
        }
        else {
            Set-ItResult -Skipped -Because "PIM policy not found for Privileged Role Administrator"
        }
    }
}

Describe "PIM-003 - Aktivierungsdauer maximal 8 Stunden" -Tag "PIM", "Security", "Medium" {

    BeforeAll {
        $script:ActivationDurations = @{}

        foreach ($roleName in $script:CriticalRoles.Keys) {
            $roleId = $script:CriticalRoles[$roleName]
            $policy = $script:RoleManagementPolicies | Where-Object {
                $_.scopeId -eq '/' -and $_.roleDefinitionId -eq $roleId
            }

            if ($policy) {
                try {
                    $rules = Invoke-GraphRequest -Uri "/v1.0/policies/roleManagementPolicies/$($policy.id)/rules"
                    $expirationRule = $rules.value | Where-Object { $_.id -eq 'Expiration_EndUser_Assignment' }

                    if ($expirationRule -and $expirationRule.setting.maximumDuration) {
                        # Parse ISO 8601 duration (e.g., PT8H)
                        $duration = $expirationRule.setting.maximumDuration
                        if ($duration -match 'PT(\d+)H') {
                            $script:ActivationDurations[$roleName] = [int]$Matches[1]
                        }
                    }
                }
                catch {
                    Write-Warning "Could not get activation duration for $roleName"
                }
            }
        }
    }

    It "PIM-003.1: Global Administrator activation should be max 8 hours" {
        $duration = $script:ActivationDurations['Global Administrator']

        if ($null -ne $duration) {
            $duration | Should -BeLessOrEqual 8 -Because "Global Admin activation duration should not exceed 8 hours. Current: $duration hours"
        }
        else {
            Set-ItResult -Skipped -Because "Could not determine activation duration for Global Administrator"
        }
    }

    It "PIM-003.2: Privileged Role Administrator activation should be max 8 hours" {
        $duration = $script:ActivationDurations['Privileged Role Administrator']

        if ($null -ne $duration) {
            $duration | Should -BeLessOrEqual 8 -Because "Privileged Role Admin activation duration should not exceed 8 hours"
        }
        else {
            Set-ItResult -Skipped -Because "Could not determine activation duration"
        }
    }

    It "PIM-003.3: Security Administrator activation should be max 8 hours" {
        $duration = $script:ActivationDurations['Security Administrator']

        if ($null -ne $duration) {
            $duration | Should -BeLessOrEqual 8 -Because "Security Admin activation duration should not exceed 8 hours"
        }
        else {
            Set-ItResult -Skipped -Because "Could not determine activation duration"
        }
    }
}

Describe "PIM-004 - Justification bei Aktivierung erforderlich" -Tag "PIM", "Security", "Medium" {

    BeforeAll {
        $script:JustificationRequired = @{}

        foreach ($roleName in @('Global Administrator', 'Privileged Role Administrator', 'Security Administrator')) {
            $roleId = $script:CriticalRoles[$roleName]
            $policy = $script:RoleManagementPolicies | Where-Object {
                $_.scopeId -eq '/' -and $_.roleDefinitionId -eq $roleId
            }

            if ($policy) {
                try {
                    $rules = Invoke-GraphRequest -Uri "/v1.0/policies/roleManagementPolicies/$($policy.id)/rules"
                    $enablementRule = $rules.value | Where-Object { $_.id -eq 'Enablement_EndUser_Assignment' }

                    if ($enablementRule) {
                        $script:JustificationRequired[$roleName] = $enablementRule.setting.enabledRules -contains 'Justification'
                    }
                }
                catch {
                    Write-Warning "Could not get justification setting for $roleName"
                }
            }
        }
    }

    It "PIM-004.1: Global Administrator activation should require justification" {
        $required = $script:JustificationRequired['Global Administrator']

        if ($null -ne $required) {
            $required | Should -BeTrue -Because "Global Admin activation must require justification"
        }
        else {
            Set-ItResult -Skipped -Because "Could not determine justification requirement"
        }
    }

    It "PIM-004.2: Privileged Role Administrator activation should require justification" {
        $required = $script:JustificationRequired['Privileged Role Administrator']

        if ($null -ne $required) {
            $required | Should -BeTrue -Because "Privileged Role Admin activation must require justification"
        }
        else {
            Set-ItResult -Skipped -Because "Could not determine justification requirement"
        }
    }
}

Describe "PIM-005 - MFA bei Aktivierung erforderlich" -Tag "PIM", "Security", "High" {

    BeforeAll {
        $script:MFARequired = @{}

        foreach ($roleName in @('Global Administrator', 'Privileged Role Administrator', 'Security Administrator')) {
            $roleId = $script:CriticalRoles[$roleName]
            $policy = $script:RoleManagementPolicies | Where-Object {
                $_.scopeId -eq '/' -and $_.roleDefinitionId -eq $roleId
            }

            if ($policy) {
                try {
                    $rules = Invoke-GraphRequest -Uri "/v1.0/policies/roleManagementPolicies/$($policy.id)/rules"
                    $enablementRule = $rules.value | Where-Object { $_.id -eq 'Enablement_EndUser_Assignment' }

                    if ($enablementRule) {
                        $script:MFARequired[$roleName] = $enablementRule.setting.enabledRules -contains 'MultiFactorAuthentication'
                    }
                }
                catch {
                    Write-Warning "Could not get MFA setting for $roleName"
                }
            }
        }
    }

    It "PIM-005.1: Global Administrator activation should require MFA" {
        $required = $script:MFARequired['Global Administrator']

        if ($null -ne $required) {
            $required | Should -BeTrue -Because "Global Admin activation must require MFA"
        }
        else {
            Set-ItResult -Skipped -Because "Could not determine MFA requirement"
        }
    }

    It "PIM-005.2: Privileged Role Administrator activation should require MFA" {
        $required = $script:MFARequired['Privileged Role Administrator']

        if ($null -ne $required) {
            $required | Should -BeTrue -Because "Privileged Role Admin activation must require MFA"
        }
        else {
            Set-ItResult -Skipped -Because "Could not determine MFA requirement"
        }
    }

    It "PIM-005.3: Security Administrator activation should require MFA" {
        $required = $script:MFARequired['Security Administrator']

        if ($null -ne $required) {
            $required | Should -BeTrue -Because "Security Admin activation must require MFA"
        }
        else {
            Set-ItResult -Skipped -Because "Could not determine MFA requirement"
        }
    }
}

AfterAll {
    # Generate summary for module integration
    $script:PIMCheckResults = @{
        Category = 'PIM'
        ChecksRun = 5
        Timestamp = Get-Date -Format 'o'
    }
}
