#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Entra Security Assessment PowerShell Module

.DESCRIPTION
    A comprehensive security assessment framework for Microsoft Entra ID and M365.
    Provides automated checks for PIM, RBAC, Conditional Access, Identity Protection, and Copilot.
    Compatible with Maester/Pester test automation framework.

.NOTES
    Version: 1.0.0
    Author: Entra Security Assessment Team
#>

# Module-level variables
$script:ModuleRoot = $PSScriptRoot
$script:ConfigPath = Join-Path $PSScriptRoot 'Config' 'assessment-config.json'
$script:AssessmentConfig = $null

#region Module Initialization

# Load configuration
function Initialize-AssessmentConfig {
    [CmdletBinding()]
    param()

    if (Test-Path $script:ConfigPath) {
        try {
            $script:AssessmentConfig = Get-Content $script:ConfigPath -Raw | ConvertFrom-Json
            Write-Verbose "Configuration loaded from: $script:ConfigPath"
        }
        catch {
            Write-Warning "Failed to load configuration: $($_.Exception.Message)"
            $script:AssessmentConfig = $null
        }
    }
    else {
        Write-Warning "Configuration file not found: $script:ConfigPath"
    }
}

# Import all functions from subdirectories
$FunctionPaths = @(
    (Join-Path $PSScriptRoot 'Core' '*.ps1')
    (Join-Path $PSScriptRoot 'Reports' '*.ps1')
)

foreach ($Path in $FunctionPaths) {
    if (Test-Path $Path) {
        $Functions = Get-ChildItem -Path $Path -ErrorAction SilentlyContinue
        foreach ($Function in $Functions) {
            try {
                . $Function.FullName
                Write-Verbose "Imported: $($Function.Name)"
            }
            catch {
                Write-Error "Failed to import $($Function.FullName): $($_.Exception.Message)"
            }
        }
    }
}

# Initialize configuration on module load
Initialize-AssessmentConfig

#endregion

#region Helper Functions

<#
.SYNOPSIS
    Creates a standardized check result object.
#>
function New-CheckResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CheckId,

        [Parameter(Mandatory)]
        [string]$Category,

        [Parameter(Mandatory)]
        [string]$Title,

        [Parameter(Mandatory)]
        [ValidateSet('High', 'Medium', 'Low', 'Info')]
        [string]$Risk,

        [Parameter(Mandatory)]
        [ValidateSet('Passed', 'Failed', 'Warning', 'ManualReview', 'Error', 'Skipped')]
        [string]$Status,

        [Parameter()]
        [string]$Description,

        [Parameter()]
        [string]$Remediation,

        [Parameter()]
        [string]$Reference,

        [Parameter()]
        [hashtable]$Details = @{}
    )

    [PSCustomObject]@{
        CheckId      = $CheckId
        Category     = $Category
        Title        = $Title
        Risk         = $Risk
        Status       = $Status
        Description  = $Description
        Remediation  = $Remediation
        Reference    = $Reference
        Details      = $Details
        Timestamp    = Get-Date -Format 'o'
        TenantId     = (Get-MgContext)?.TenantId
    }
}

<#
.SYNOPSIS
    Invokes a Microsoft Graph API request with error handling.
#>
function Invoke-GraphRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter()]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string]$Method = 'GET',

        [Parameter()]
        [hashtable]$Body,

        [Parameter()]
        [switch]$AllPages
    )

    try {
        $params = @{
            Method      = $Method
            Uri         = $Uri
            ErrorAction = 'Stop'
        }

        if ($Body) {
            $params['Body'] = $Body | ConvertTo-Json -Depth 10
            $params['ContentType'] = 'application/json'
        }

        $response = Invoke-MgGraphRequest @params

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
        $errorDetails = @{
            Uri        = $Uri
            Method     = $Method
            StatusCode = $_.Exception.Response?.StatusCode
            Message    = $_.Exception.Message
        }

        Write-Error "Graph API Error: $($_.Exception.Message)" -ErrorAction Continue
        return $null
    }
}

<#
.SYNOPSIS
    Gets the assessment configuration.
#>
function Get-AssessmentConfig {
    [CmdletBinding()]
    param()

    if (-not $script:AssessmentConfig) {
        Initialize-AssessmentConfig
    }

    return $script:AssessmentConfig
}

#endregion

#region Main Assessment Functions

<#
.SYNOPSIS
    Runs the full Entra Security Assessment.

.DESCRIPTION
    Executes all enabled security checks across PIM, RBAC, Conditional Access,
    Identity Protection, and Copilot categories.

.PARAMETER Categories
    Specific categories to assess. If not specified, all enabled categories are assessed.

.PARAMETER IncludeManualReview
    Include checks that require manual review.

.PARAMETER OutputPath
    Path to save assessment results.

.EXAMPLE
    Invoke-EntraSecurityAssessment

    Runs all enabled security checks.

.EXAMPLE
    Invoke-EntraSecurityAssessment -Categories 'PIM', 'RBAC'

    Runs only PIM and RBAC checks.

.OUTPUTS
    [PSCustomObject[]] Array of check results.
#>
function Invoke-EntraSecurityAssessment {
    [CmdletBinding()]
    [Alias('esa')]
    param(
        [Parameter()]
        [ValidateSet('PIM', 'RBAC', 'ConditionalAccess', 'IdentityProtection', 'Copilot')]
        [string[]]$Categories,

        [Parameter()]
        [switch]$IncludeManualReview,

        [Parameter()]
        [string]$OutputPath
    )

    begin {
        # Verify connection
        $connectionTest = Test-EntraAssessmentConnection
        if (-not $connectionTest.IsConnected) {
            throw "Not connected to Microsoft Graph. Run Connect-EntraAssessment first."
        }

        $config = Get-AssessmentConfig
        $results = @()

        # Determine categories to run
        if (-not $Categories) {
            $Categories = @('PIM', 'RBAC', 'ConditionalAccess', 'IdentityProtection', 'Copilot')
        }

        Write-Host "`nStarting Entra Security Assessment" -ForegroundColor Cyan
        Write-Host "Categories: $($Categories -join ', ')" -ForegroundColor Gray
        Write-Host "Tenant: $((Get-MgContext).TenantId)`n" -ForegroundColor Gray
    }

    process {
        foreach ($category in $Categories) {
            Write-Host "Assessing: $category" -ForegroundColor Yellow

            try {
                $categoryResults = switch ($category) {
                    'PIM' { Invoke-PIMSecurityCheck }
                    'RBAC' { Invoke-RBACSecurityCheck }
                    'ConditionalAccess' { Invoke-ConditionalAccessCheck }
                    'IdentityProtection' { Invoke-IdentityProtectionCheck }
                    'Copilot' { Invoke-CopilotSecurityCheck }
                }

                if ($categoryResults) {
                    $results += $categoryResults
                }
            }
            catch {
                Write-Warning "Error assessing $category : $($_.Exception.Message)"
                $results += New-CheckResult -CheckId "$category-ERR" -Category $category -Title "Assessment Error" -Risk 'Info' -Status 'Error' -Description $_.Exception.Message
            }
        }
    }

    end {
        # Summary
        $passed = ($results | Where-Object Status -eq 'Passed').Count
        $failed = ($results | Where-Object Status -eq 'Failed').Count
        $warnings = ($results | Where-Object Status -eq 'Warning').Count
        $manual = ($results | Where-Object Status -eq 'ManualReview').Count

        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "Assessment Complete" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "Passed:        $passed" -ForegroundColor Green
        Write-Host "Failed:        $failed" -ForegroundColor Red
        Write-Host "Warnings:      $warnings" -ForegroundColor Yellow
        Write-Host "Manual Review: $manual" -ForegroundColor Gray
        Write-Host "Total Checks:  $($results.Count)" -ForegroundColor White

        # Save results if OutputPath specified
        if ($OutputPath) {
            $outputFile = Join-Path $OutputPath "assessment-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
            $results | ConvertTo-Json -Depth 10 | Out-File $outputFile -Encoding UTF8
            Write-Host "`nResults saved to: $outputFile" -ForegroundColor Gray
        }

        return $results
    }
}

<#
.SYNOPSIS
    Runs assessment across multiple tenants.

.DESCRIPTION
    Executes security assessment across multiple Azure tenants using Azure Lighthouse
    or individual connections.

.PARAMETER TenantIds
    Array of Tenant IDs to assess.

.PARAMETER Categories
    Specific categories to assess.

.PARAMETER OutputPath
    Path to save assessment results.

.PARAMETER ClientId
    Application ID for Service Principal authentication.

.PARAMETER ClientSecret
    Client Secret for Service Principal authentication.

.EXAMPLE
    Invoke-MultiTenantAssessment -TenantIds @('tenant1', 'tenant2', 'tenant3')

    Assesses multiple tenants interactively.
#>
function Invoke-MultiTenantAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$TenantIds,

        [Parameter()]
        [ValidateSet('PIM', 'RBAC', 'ConditionalAccess', 'IdentityProtection', 'Copilot')]
        [string[]]$Categories,

        [Parameter()]
        [string]$OutputPath = './Reports',

        [Parameter()]
        [string]$ClientId,

        [Parameter()]
        [SecureString]$ClientSecret
    )

    begin {
        $allResults = @{}
        $totalTenants = $TenantIds.Count
        $currentTenant = 0

        # Ensure output directory exists
        if (-not (Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }
    }

    process {
        foreach ($tenantId in $TenantIds) {
            $currentTenant++
            Write-Host "`n[$currentTenant/$totalTenants] Processing Tenant: $tenantId" -ForegroundColor Cyan

            try {
                # Connect to tenant
                if ($ClientId -and $ClientSecret) {
                    Connect-EntraAssessment -TenantId $tenantId -ClientId $ClientId -ClientSecret $ClientSecret | Out-Null
                }
                else {
                    Connect-EntraAssessment -TenantId $tenantId | Out-Null
                }

                # Run assessment
                $tenantResults = Invoke-EntraSecurityAssessment -Categories $Categories

                $allResults[$tenantId] = @{
                    TenantId     = $tenantId
                    AssessedAt   = Get-Date
                    Results      = $tenantResults
                    Summary      = @{
                        Total   = $tenantResults.Count
                        Passed  = ($tenantResults | Where-Object Status -eq 'Passed').Count
                        Failed  = ($tenantResults | Where-Object Status -eq 'Failed').Count
                        Warning = ($tenantResults | Where-Object Status -eq 'Warning').Count
                    }
                }

                # Save individual tenant results
                $tenantOutputFile = Join-Path $OutputPath "$tenantId-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
                $allResults[$tenantId] | ConvertTo-Json -Depth 10 | Out-File $tenantOutputFile -Encoding UTF8
            }
            catch {
                Write-Warning "Failed to assess tenant $tenantId : $($_.Exception.Message)"
                $allResults[$tenantId] = @{
                    TenantId = $tenantId
                    Error    = $_.Exception.Message
                }
            }
            finally {
                Disconnect-EntraAssessment -ErrorAction SilentlyContinue
            }
        }
    }

    end {
        # Generate summary report
        $summaryFile = Join-Path $OutputPath "multi-tenant-summary-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        $allResults | ConvertTo-Json -Depth 10 | Out-File $summaryFile -Encoding UTF8

        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "Multi-Tenant Assessment Complete" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "Tenants Assessed: $totalTenants" -ForegroundColor White
        Write-Host "Summary saved to: $summaryFile" -ForegroundColor Gray

        return $allResults
    }
}

#endregion

#region Security Check Functions

# Critical role IDs
$script:CriticalRoleIds = @{
    'Global Administrator'              = '62e90394-69f5-4237-9190-012177145e10'
    'Privileged Role Administrator'     = 'e8611ab8-c189-46e8-94e1-60213ab1f814'
    'Security Administrator'            = '194ae4cb-b126-40b2-bd5b-6091b380977d'
    'User Administrator'                = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
    'Exchange Administrator'            = '29232cdf-9323-42fd-ade2-1d097af3e4de'
    'SharePoint Administrator'          = 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c'
}

<#
.SYNOPSIS
    Runs PIM security checks.
#>
function Invoke-PIMSecurityCheck {
    [CmdletBinding()]
    param()

    Write-Verbose "Running PIM Security Checks..."
    $results = @()
    $config = Get-AssessmentConfig

    # Get directory roles
    $directoryRoles = Invoke-GraphRequest -Uri '/v1.0/directoryRoles'
    if ($directoryRoles.value) { $directoryRoles = $directoryRoles.value }

    # PIM-001: Check permanent privileged assignments
    $globalAdminRole = $directoryRoles | Where-Object { $_.roleTemplateId -eq $script:CriticalRoleIds['Global Administrator'] }
    $permanentGlobalAdmins = @()

    if ($globalAdminRole) {
        $members = Invoke-GraphRequest -Uri "/v1.0/directoryRoles/$($globalAdminRole.id)/members"
        if ($members.value) { $permanentGlobalAdmins = $members.value }
    }

    $pim001Status = if ($permanentGlobalAdmins.Count -le 2) { 'Passed' } else { 'Failed' }
    $results += New-CheckResult -CheckId 'PIM-001' -Category 'PIM' -Title 'Permanente privilegierte Zuweisungen' -Risk 'High' -Status $pim001Status `
        -Description "Permanent Global Admins: $($permanentGlobalAdmins.Count). Maximum recommended: 2" `
        -Remediation 'Convert permanent assignments to eligible assignments in PIM.' `
        -Reference 'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure' `
        -Details @{ PermanentGlobalAdmins = $permanentGlobalAdmins.displayName }

    # PIM-002 to PIM-005: Check role management policies
    try {
        $policies = Invoke-GraphRequest -Uri "/v1.0/policies/roleManagementPolicies?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'"
        if ($policies.value) {
            $globalAdminPolicy = $policies.value | Where-Object { $_.roleDefinitionId -eq $script:CriticalRoleIds['Global Administrator'] }

            if ($globalAdminPolicy) {
                $rules = Invoke-GraphRequest -Uri "/v1.0/policies/roleManagementPolicies/$($globalAdminPolicy.id)/rules"

                # PIM-002: Approval required
                $approvalRule = $rules.value | Where-Object { $_.id -eq 'Approval_EndUser_Assignment' }
                $requiresApproval = $approvalRule.setting.isApprovalRequired -eq $true
                $results += New-CheckResult -CheckId 'PIM-002' -Category 'PIM' -Title 'Approval für kritische Rollen' -Risk 'High' `
                    -Status $(if ($requiresApproval) { 'Passed' } else { 'Failed' }) `
                    -Description "Approval required for Global Admin activation: $requiresApproval" `
                    -Remediation 'Configure approval requirements in PIM role settings.' `
                    -Reference 'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings'

                # PIM-003: Activation duration
                $expirationRule = $rules.value | Where-Object { $_.id -eq 'Expiration_EndUser_Assignment' }
                $maxDuration = 0
                if ($expirationRule.setting.maximumDuration -match 'PT(\d+)H') { $maxDuration = [int]$Matches[1] }
                $results += New-CheckResult -CheckId 'PIM-003' -Category 'PIM' -Title 'Aktivierungsdauer maximal 8 Stunden' -Risk 'Medium' `
                    -Status $(if ($maxDuration -le 8 -and $maxDuration -gt 0) { 'Passed' } elseif ($maxDuration -eq 0) { 'Warning' } else { 'Failed' }) `
                    -Description "Maximum activation duration: $maxDuration hours" `
                    -Remediation 'Reduce maximum activation duration in PIM role settings.' `
                    -Reference 'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings'

                # PIM-004: Justification required
                $enablementRule = $rules.value | Where-Object { $_.id -eq 'Enablement_EndUser_Assignment' }
                $requiresJustification = $enablementRule.setting.enabledRules -contains 'Justification'
                $results += New-CheckResult -CheckId 'PIM-004' -Category 'PIM' -Title 'Justification bei Aktivierung' -Risk 'Medium' `
                    -Status $(if ($requiresJustification) { 'Passed' } else { 'Failed' }) `
                    -Description "Justification required: $requiresJustification" `
                    -Remediation 'Enable "Require justification on activation" in PIM role settings.' `
                    -Reference 'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings'

                # PIM-005: MFA required
                $requiresMFA = $enablementRule.setting.enabledRules -contains 'MultiFactorAuthentication'
                $results += New-CheckResult -CheckId 'PIM-005' -Category 'PIM' -Title 'MFA bei Aktivierung' -Risk 'High' `
                    -Status $(if ($requiresMFA) { 'Passed' } else { 'Failed' }) `
                    -Description "MFA required for activation: $requiresMFA" `
                    -Remediation 'Enable "Require Azure MFA on activation" in PIM role settings.' `
                    -Reference 'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings'
            }
            else {
                $results += New-CheckResult -CheckId 'PIM-002' -Category 'PIM' -Title 'PIM Policy Check' -Risk 'High' -Status 'Warning' -Description 'PIM policy not found for Global Administrator. PIM may not be configured.'
            }
        }
    }
    catch {
        $results += New-CheckResult -CheckId 'PIM-ERR' -Category 'PIM' -Title 'PIM Policy Check Error' -Risk 'Info' -Status 'Error' -Description "Could not check PIM policies: $($_.Exception.Message). Azure AD P2 license may be required."
    }

    return $results
}

<#
.SYNOPSIS
    Runs RBAC security checks.
#>
function Invoke-RBACSecurityCheck {
    [CmdletBinding()]
    param()

    Write-Verbose "Running RBAC Security Checks..."
    $results = @()

    # Get directory roles
    $directoryRoles = Invoke-GraphRequest -Uri '/v1.0/directoryRoles'
    if ($directoryRoles.value) { $directoryRoles = $directoryRoles.value }

    # Get Global Admins
    $globalAdminRole = $directoryRoles | Where-Object { $_.roleTemplateId -eq $script:CriticalRoleIds['Global Administrator'] }
    $globalAdmins = @()
    if ($globalAdminRole) {
        $members = Invoke-GraphRequest -Uri "/v1.0/directoryRoles/$($globalAdminRole.id)/members"
        if ($members.value) { $globalAdmins = $members.value }
    }

    # RBAC-001: Global Admin count
    $rbac001Status = if ($globalAdmins.Count -ge 2 -and $globalAdmins.Count -le 5) { 'Passed' }
                     elseif ($globalAdmins.Count -lt 2) { 'Warning' }
                     else { 'Failed' }
    $results += New-CheckResult -CheckId 'RBAC-001' -Category 'RBAC' -Title 'Global Admins zwischen 2-5' -Risk 'High' -Status $rbac001Status `
        -Description "Global Administrator count: $($globalAdmins.Count). Recommended: 2-5" `
        -Remediation 'Review Global Admin assignments and adjust to recommended count.' `
        -Reference 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices' `
        -Details @{ GlobalAdmins = $globalAdmins.displayName; Count = $globalAdmins.Count }

    # RBAC-002: Guest admins
    $guestAdmins = @()
    foreach ($admin in $globalAdmins | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.user' }) {
        try {
            $user = Invoke-GraphRequest -Uri "/v1.0/users/$($admin.id)?`$select=userType"
            if ($user.userType -eq 'Guest') { $guestAdmins += $admin }
        }
        catch { }
    }
    $results += New-CheckResult -CheckId 'RBAC-002' -Category 'RBAC' -Title 'Keine Gäste mit Admin-Rollen' -Risk 'High' `
        -Status $(if ($guestAdmins.Count -eq 0) { 'Passed' } else { 'Failed' }) `
        -Description "Guest users with Global Admin: $($guestAdmins.Count)" `
        -Remediation 'Remove administrative role assignments from guest users.' `
        -Reference 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices' `
        -Details @{ GuestAdmins = $guestAdmins.displayName }

    # RBAC-003: Service Principal Global Admins
    $spGlobalAdmins = $globalAdmins | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.servicePrincipal' }
    $results += New-CheckResult -CheckId 'RBAC-003' -Category 'RBAC' -Title 'Keine Service Principals als Global Admin' -Risk 'Medium' `
        -Status $(if ($spGlobalAdmins.Count -eq 0) { 'Passed' } else { 'Failed' }) `
        -Description "Service Principals with Global Admin: $($spGlobalAdmins.Count)" `
        -Remediation 'Assign more specific roles to Service Principals instead of Global Admin.' `
        -Reference 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices' `
        -Details @{ SPGlobalAdmins = $spGlobalAdmins.displayName }

    # RBAC-004: Custom roles documented
    try {
        $roleDefinitions = Invoke-GraphRequest -Uri '/v1.0/roleManagement/directory/roleDefinitions'
        $customRoles = $roleDefinitions.value | Where-Object { $_.isBuiltIn -eq $false }
        $undocumented = $customRoles | Where-Object { [string]::IsNullOrWhiteSpace($_.description) }

        $results += New-CheckResult -CheckId 'RBAC-004' -Category 'RBAC' -Title 'Custom Roles dokumentiert' -Risk 'Low' `
            -Status $(if ($undocumented.Count -eq 0) { 'Passed' } else { 'Warning' }) `
            -Description "Custom roles: $($customRoles.Count), Undocumented: $($undocumented.Count)" `
            -Remediation 'Add descriptions to all custom roles.' `
            -Reference 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/custom-overview' `
            -Details @{ CustomRoles = $customRoles.displayName; Undocumented = $undocumented.displayName }
    }
    catch {
        $results += New-CheckResult -CheckId 'RBAC-004' -Category 'RBAC' -Title 'Custom Roles Check' -Risk 'Low' -Status 'Error' -Description "Could not check custom roles: $($_.Exception.Message)"
    }

    # RBAC-005: Privileged user percentage
    try {
        $userCount = 0
        $usersResponse = Invoke-GraphRequest -Uri '/v1.0/users?$count=true&$top=1' -Method GET
        # Try to get count from response
        if ($usersResponse.'@odata.count') {
            $userCount = $usersResponse.'@odata.count'
        }
        else {
            $allUsers = Invoke-GraphRequest -Uri '/v1.0/users?$select=id' -AllPages
            $userCount = $allUsers.Count
        }

        $privilegedCount = $globalAdmins.Count
        $percentage = if ($userCount -gt 0) { [math]::Round(($privilegedCount / $userCount) * 100, 2) } else { 0 }

        $results += New-CheckResult -CheckId 'RBAC-005' -Category 'RBAC' -Title 'Privilegierte Benutzer unter 5%' -Risk 'Medium' `
            -Status $(if ($percentage -lt 5) { 'Passed' } else { 'Failed' }) `
            -Description "Privileged users: $privilegedCount / $userCount = $percentage%" `
            -Remediation 'Review privileged role assignments and reduce where possible.' `
            -Reference 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices' `
            -Details @{ PrivilegedCount = $privilegedCount; TotalUsers = $userCount; Percentage = $percentage }
    }
    catch {
        $results += New-CheckResult -CheckId 'RBAC-005' -Category 'RBAC' -Title 'Privileged User Check' -Risk 'Medium' -Status 'Error' -Description "Could not calculate privileged user percentage: $($_.Exception.Message)"
    }

    return $results
}

<#
.SYNOPSIS
    Runs Conditional Access security checks.
#>
function Invoke-ConditionalAccessCheck {
    [CmdletBinding()]
    param()

    Write-Verbose "Running Conditional Access Checks..."
    $results = @()

    # Get CA policies
    $caPolicies = @()
    try {
        $response = Invoke-GraphRequest -Uri '/v1.0/identity/conditionalAccess/policies'
        if ($response.value) { $caPolicies = $response.value }
    }
    catch {
        return @(New-CheckResult -CheckId 'CA-ERR' -Category 'ConditionalAccess' -Title 'CA Policy Error' -Risk 'Info' -Status 'Error' -Description "Could not load CA policies: $($_.Exception.Message)")
    }

    $enabledPolicies = $caPolicies | Where-Object { $_.state -eq 'enabled' }

    # CA-001: MFA for all users
    $mfaPolicies = $enabledPolicies | Where-Object {
        ($_.conditions.users.includeUsers -contains 'All' -or $_.conditions.users.includeGroups) -and
        ($_.grantControls.builtInControls -contains 'mfa' -or $_.grantControls.authenticationStrength)
    }
    $results += New-CheckResult -CheckId 'CA-001' -Category 'ConditionalAccess' -Title 'MFA für alle Benutzer' -Risk 'High' `
        -Status $(if ($mfaPolicies.Count -gt 0) { 'Passed' } else { 'Failed' }) `
        -Description "MFA policies found: $($mfaPolicies.Count)" `
        -Remediation 'Create a Conditional Access policy requiring MFA for all users.' `
        -Reference 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa' `
        -Details @{ MFAPolicies = $mfaPolicies.displayName }

    # CA-002: Legacy auth blocked
    $legacyBlockPolicies = $enabledPolicies | Where-Object {
        ($_.conditions.clientAppTypes -contains 'other' -or $_.conditions.clientAppTypes -contains 'exchangeActiveSync') -and
        $_.grantControls.builtInControls -contains 'block'
    }
    $results += New-CheckResult -CheckId 'CA-002' -Category 'ConditionalAccess' -Title 'Legacy Authentication blockiert' -Risk 'High' `
        -Status $(if ($legacyBlockPolicies.Count -gt 0) { 'Passed' } else { 'Failed' }) `
        -Description "Legacy auth block policies: $($legacyBlockPolicies.Count)" `
        -Remediation 'Create a Conditional Access policy blocking legacy authentication.' `
        -Reference 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-block-legacy' `
        -Details @{ LegacyBlockPolicies = $legacyBlockPolicies.displayName }

    # CA-003: Admin MFA
    $adminMFAPolicies = $enabledPolicies | Where-Object {
        $_.conditions.users.includeRoles -and
        ($_.grantControls.builtInControls -contains 'mfa' -or $_.grantControls.authenticationStrength)
    }
    $allUsersMFACoversAdmins = $mfaPolicies | Where-Object { $_.conditions.users.includeUsers -contains 'All' }
    $hasAdminMFA = ($adminMFAPolicies.Count -gt 0) -or ($allUsersMFACoversAdmins.Count -gt 0)

    $results += New-CheckResult -CheckId 'CA-003' -Category 'ConditionalAccess' -Title 'Admin MFA Policy' -Risk 'High' `
        -Status $(if ($hasAdminMFA) { 'Passed' } else { 'Failed' }) `
        -Description "Admin MFA policies: $($adminMFAPolicies.Count), All-users MFA covering admins: $($allUsersMFACoversAdmins.Count)" `
        -Remediation 'Create a Conditional Access policy requiring MFA for admin roles.' `
        -Reference 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa' `
        -Details @{ AdminMFAPolicies = $adminMFAPolicies.displayName }

    # CA-004: Risky sign-in policy
    $riskPolicies = $enabledPolicies | Where-Object { $_.conditions.signInRiskLevels -and $_.conditions.signInRiskLevels.Count -gt 0 }
    $results += New-CheckResult -CheckId 'CA-004' -Category 'ConditionalAccess' -Title 'Risky Sign-In Policy' -Risk 'Medium' `
        -Status $(if ($riskPolicies.Count -gt 0) { 'Passed' } else { 'Failed' }) `
        -Description "Sign-in risk policies: $($riskPolicies.Count)" `
        -Remediation 'Create a Conditional Access policy for risky sign-ins.' `
        -Reference 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-risk' `
        -Details @{ RiskPolicies = $riskPolicies.displayName; TotalEnabled = $enabledPolicies.Count }

    return $results
}

<#
.SYNOPSIS
    Runs Identity Protection security checks.
#>
function Invoke-IdentityProtectionCheck {
    [CmdletBinding()]
    param()

    Write-Verbose "Running Identity Protection Checks..."
    $results = @()

    # IDP-001: Risky users
    try {
        $riskyUsers = @()
        $response = Invoke-GraphRequest -Uri '/v1.0/identityProtection/riskyUsers'
        if ($response.value) { $riskyUsers = $response.value }

        $highRiskUsers = $riskyUsers | Where-Object { $_.riskLevel -eq 'high' -and $_.riskState -notin @('remediated', 'dismissed') }
        $mediumRiskUsers = $riskyUsers | Where-Object { $_.riskLevel -eq 'medium' -and $_.riskState -notin @('remediated', 'dismissed') }

        $results += New-CheckResult -CheckId 'IDP-001' -Category 'IdentityProtection' -Title 'Keine High Risk Users' -Risk 'High' `
            -Status $(if ($highRiskUsers.Count -eq 0) { 'Passed' } else { 'Failed' }) `
            -Description "High-risk users: $($highRiskUsers.Count), Medium-risk: $($mediumRiskUsers.Count)" `
            -Remediation 'Investigate and remediate high risk users in Identity Protection.' `
            -Reference 'https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-remediate-unblock' `
            -Details @{ HighRiskUsers = $highRiskUsers.userDisplayName; MediumRiskUsers = $mediumRiskUsers.userDisplayName; TotalRisky = $riskyUsers.Count }
    }
    catch {
        $results += New-CheckResult -CheckId 'IDP-001' -Category 'IdentityProtection' -Title 'Risky Users Check' -Risk 'High' -Status 'Error' -Description "Could not access Identity Protection: $($_.Exception.Message). Azure AD P2 license may be required."
    }

    # IDP-002: Risk detections monitoring
    try {
        $thirtyDaysAgo = (Get-Date).AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $riskDetections = @()
        $response = Invoke-GraphRequest -Uri "/v1.0/identityProtection/riskDetections?`$filter=detectedDateTime ge $thirtyDaysAgo&`$top=100"
        if ($response.value) { $riskDetections = $response.value }

        $highRiskDetections = $riskDetections | Where-Object { $_.riskLevel -eq 'high' -and $_.riskState -eq 'atRisk' }

        $results += New-CheckResult -CheckId 'IDP-002' -Category 'IdentityProtection' -Title 'Risk Detections monitored' -Risk 'Medium' `
            -Status $(if ($highRiskDetections.Count -eq 0) { 'Passed' } else { 'Warning' }) `
            -Description "Risk detections (30d): $($riskDetections.Count), Uninvestigated high-risk: $($highRiskDetections.Count)" `
            -Remediation 'Configure alerts for risk detections and establish review process.' `
            -Reference 'https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-investigate-risk' `
            -Details @{ TotalDetections = $riskDetections.Count; HighRiskDetections = $highRiskDetections.Count }
    }
    catch {
        $results += New-CheckResult -CheckId 'IDP-002' -Category 'IdentityProtection' -Title 'Risk Detections Check' -Risk 'Medium' -Status 'Error' -Description "Could not access risk detections: $($_.Exception.Message)"
    }

    return $results
}

<#
.SYNOPSIS
    Runs Copilot security checks.
#>
function Invoke-CopilotSecurityCheck {
    [CmdletBinding()]
    param()

    Write-Verbose "Running Copilot Security Checks..."
    $results = @()

    # COPILOT-001: Sensitivity labels
    try {
        $labels = @()
        $response = Invoke-GraphRequest -Uri '/v1.0/informationProtection/policy/labels'
        if ($response.value) { $labels = $response.value }

        $results += New-CheckResult -CheckId 'COPILOT-001' -Category 'Copilot' -Title 'Sensitivity Labels konfiguriert' -Risk 'High' `
            -Status $(if ($labels.Count -gt 0) { 'Passed' } else { 'Failed' }) `
            -Description "Sensitivity labels configured: $($labels.Count)" `
            -Remediation 'Configure sensitivity labels in Microsoft Purview.' `
            -Reference 'https://learn.microsoft.com/en-us/purview/sensitivity-labels' `
            -Details @{ Labels = $labels.name; Count = $labels.Count }
    }
    catch {
        $results += New-CheckResult -CheckId 'COPILOT-001' -Category 'Copilot' -Title 'Sensitivity Labels Check' -Risk 'High' -Status 'Error' -Description "Could not check sensitivity labels: $($_.Exception.Message)"
    }

    # COPILOT-002: DLP Policies (Manual Review)
    $results += New-CheckResult -CheckId 'COPILOT-002' -Category 'Copilot' -Title 'DLP Policies vorhanden' -Risk 'High' -Status 'ManualReview' `
        -Description 'DLP policy verification requires manual review in Microsoft Purview Compliance Portal.' `
        -Remediation 'Configure DLP policies in Microsoft Purview.' `
        -Reference 'https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp' `
        -Details @{ ManualReviewRequired = $true; CheckLocation = 'https://compliance.microsoft.com/datalossprevention' }

    # COPILOT-003: Audit logging
    $auditEnabled = $false
    try {
        $response = Invoke-GraphRequest -Uri '/v1.0/auditLogs/directoryAudits?$top=1'
        if ($response) { $auditEnabled = $true }
    }
    catch { }

    $results += New-CheckResult -CheckId 'COPILOT-003' -Category 'Copilot' -Title 'Audit Logging aktiviert' -Risk 'Medium' `
        -Status $(if ($auditEnabled) { 'Passed' } else { 'Warning' }) `
        -Description "Directory audit logging accessible: $auditEnabled" `
        -Remediation 'Enable unified audit logging in Microsoft Purview.' `
        -Reference 'https://learn.microsoft.com/en-us/purview/audit-log-enable-disable'

    # COPILOT-004: Tenant isolation / Guest settings
    try {
        $authPolicy = Invoke-GraphRequest -Uri '/v1.0/policies/authorizationPolicy'
        if ($authPolicy.value) { $authPolicy = $authPolicy.value[0] }

        $guestAccess = $authPolicy.guestUserRoleId
        $restrictedGuestRole = '2af84b1e-32c8-42b7-82bc-daa82404023b'
        $isRestricted = $guestAccess -eq $restrictedGuestRole

        $guestAccessLevel = switch ($guestAccess) {
            '2af84b1e-32c8-42b7-82bc-daa82404023b' { 'Restricted Guest (Recommended)' }
            '10dae51f-b6af-4016-8d66-8c2a99b929b3' { 'Guest' }
            'a0b1b346-4d3e-4e8b-98f8-753987be4970' { 'Member (Not Recommended)' }
            default { $guestAccess }
        }

        $results += New-CheckResult -CheckId 'COPILOT-004' -Category 'Copilot' -Title 'Tenant Isolation' -Risk 'Medium' `
            -Status $(if ($isRestricted) { 'Passed' } else { 'Warning' }) `
            -Description "Guest user access level: $guestAccessLevel" `
            -Remediation 'Review and configure guest access settings in External Identities.' `
            -Reference 'https://learn.microsoft.com/en-us/entra/external-id/external-identities-overview' `
            -Details @{ GuestRoleId = $guestAccess; GuestAccessLevel = $guestAccessLevel; AllowInvitesFrom = $authPolicy.allowInvitesFrom }
    }
    catch {
        $results += New-CheckResult -CheckId 'COPILOT-004' -Category 'Copilot' -Title 'Guest Settings Check' -Risk 'Medium' -Status 'Error' -Description "Could not check guest settings: $($_.Exception.Message)"
    }

    return $results
}

#endregion

#region Aliases

Set-Alias -Name 'esa' -Value 'Invoke-EntraSecurityAssessment'
Set-Alias -Name 'cea' -Value 'Connect-EntraAssessment'

#endregion

# Export functions and aliases
Export-ModuleMember -Function @(
    'Connect-EntraAssessment'
    'Disconnect-EntraAssessment'
    'Test-EntraAssessmentConnection'
    'Get-EntraAssessmentConnection'
    'Invoke-EntraSecurityAssessment'
    'Invoke-MultiTenantAssessment'
    'Invoke-PIMSecurityCheck'
    'Invoke-RBACSecurityCheck'
    'Invoke-ConditionalAccessCheck'
    'Invoke-IdentityProtectionCheck'
    'Invoke-CopilotSecurityCheck'
    'New-CheckResult'
    'Invoke-GraphRequest'
    'Get-AssessmentConfig'
) -Alias @('esa', 'cea')
