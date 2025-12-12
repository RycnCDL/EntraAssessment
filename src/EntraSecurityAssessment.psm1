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

#region Placeholder Check Functions (to be implemented in separate files)

# These are placeholder functions that will be replaced by actual implementations
# in the Tests/Custom/*.Tests.ps1 files

function Invoke-PIMSecurityCheck {
    [CmdletBinding()]
    param()

    Write-Verbose "Running PIM Security Checks..."

    # Placeholder - actual implementation in PIM.Tests.ps1
    @(
        New-CheckResult -CheckId 'PIM-001' -Category 'PIM' -Title 'PIM Check Placeholder' -Risk 'Info' -Status 'Skipped' -Description 'PIM checks not yet implemented'
    )
}

function Invoke-RBACSecurityCheck {
    [CmdletBinding()]
    param()

    Write-Verbose "Running RBAC Security Checks..."

    # Placeholder - actual implementation in RBAC.Tests.ps1
    @(
        New-CheckResult -CheckId 'RBAC-001' -Category 'RBAC' -Title 'RBAC Check Placeholder' -Risk 'Info' -Status 'Skipped' -Description 'RBAC checks not yet implemented'
    )
}

function Invoke-ConditionalAccessCheck {
    [CmdletBinding()]
    param()

    Write-Verbose "Running Conditional Access Checks..."

    # Placeholder - actual implementation in ConditionalAccess.Tests.ps1
    @(
        New-CheckResult -CheckId 'CA-001' -Category 'ConditionalAccess' -Title 'CA Check Placeholder' -Risk 'Info' -Status 'Skipped' -Description 'Conditional Access checks not yet implemented'
    )
}

function Invoke-IdentityProtectionCheck {
    [CmdletBinding()]
    param()

    Write-Verbose "Running Identity Protection Checks..."

    # Placeholder - actual implementation in IdentityProtection.Tests.ps1
    @(
        New-CheckResult -CheckId 'IDP-001' -Category 'IdentityProtection' -Title 'IDP Check Placeholder' -Risk 'Info' -Status 'Skipped' -Description 'Identity Protection checks not yet implemented'
    )
}

function Invoke-CopilotSecurityCheck {
    [CmdletBinding()]
    param()

    Write-Verbose "Running Copilot Security Checks..."

    # Placeholder - actual implementation in Copilot.Tests.ps1
    @(
        New-CheckResult -CheckId 'COPILOT-001' -Category 'Copilot' -Title 'Copilot Check Placeholder' -Risk 'Info' -Status 'Skipped' -Description 'Copilot checks not yet implemented'
    )
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
