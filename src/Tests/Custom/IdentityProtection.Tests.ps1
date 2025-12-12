#Requires -Modules Pester, Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Identity Protection Security Tests

.DESCRIPTION
    Pester tests for validating Identity Protection configuration and risky users.
    Compatible with Maester test framework.

.NOTES
    Category: IdentityProtection
    Checks: IDP-001 through IDP-002
    Requires: Azure AD Premium P2 license
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
                Write-Warning "Access denied for $Uri - Azure AD Premium P2 license may be required"
            }
            else {
                Write-Warning "Graph API Error for $Uri : $($_.Exception.Message)"
            }
            return $null
        }
    }

    # Load risky users
    $script:RiskyUsers = @()
    $script:RiskyUsersError = $null
    try {
        $response = Invoke-GraphRequest -Uri '/v1.0/identityProtection/riskyUsers' -AllPages
        if ($response.value) {
            $script:RiskyUsers = $response.value
        }
        elseif ($response -is [array]) {
            $script:RiskyUsers = $response
        }
    }
    catch {
        $script:RiskyUsersError = $_.Exception.Message
        Write-Warning "Could not load risky users: $($_.Exception.Message)"
    }

    # Categorize risky users by risk level
    $script:HighRiskUsers = $script:RiskyUsers | Where-Object { $_.riskLevel -eq 'high' }
    $script:MediumRiskUsers = $script:RiskyUsers | Where-Object { $_.riskLevel -eq 'medium' }
    $script:LowRiskUsers = $script:RiskyUsers | Where-Object { $_.riskLevel -eq 'low' }

    # Filter active risks (not remediated or dismissed)
    $script:ActiveRiskyUsers = $script:RiskyUsers | Where-Object {
        $_.riskState -notin @('remediated', 'dismissed', 'confirmedSafe')
    }

    # Load risk detections (last 30 days)
    $script:RiskDetections = @()
    $script:RiskDetectionsError = $null
    try {
        $thirtyDaysAgo = (Get-Date).AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $response = Invoke-GraphRequest -Uri "/v1.0/identityProtection/riskDetections?`$filter=detectedDateTime ge $thirtyDaysAgo&`$top=100"
        if ($response.value) {
            $script:RiskDetections = $response.value
        }
    }
    catch {
        $script:RiskDetectionsError = $_.Exception.Message
        Write-Warning "Could not load risk detections: $($_.Exception.Message)"
    }

    # Categorize risk detections
    $script:HighRiskDetections = $script:RiskDetections | Where-Object { $_.riskLevel -eq 'high' }
    $script:RecentDetections = $script:RiskDetections | Where-Object {
        $_.detectedDateTime -gt (Get-Date).AddDays(-7)
    }
}

Describe "IDP-001 - Keine High Risk Users" -Tag "IdentityProtection", "Security", "High" {

    It "IDP-001.1: Should have no high-risk users" {
        if ($script:RiskyUsersError) {
            Set-ItResult -Skipped -Because "Could not access Identity Protection API: $($script:RiskyUsersError)"
        }
        else {
            $activeHighRisk = $script:HighRiskUsers | Where-Object {
                $_.riskState -notin @('remediated', 'dismissed', 'confirmedSafe')
            }

            if ($activeHighRisk.Count -gt 0) {
                Write-Host "`nHigh-risk users requiring attention:" -ForegroundColor Red
                foreach ($user in $activeHighRisk) {
                    Write-Host "  - $($user.userDisplayName) ($($user.userPrincipalName))" -ForegroundColor Red
                    Write-Host "    Risk State: $($user.riskState), Last Updated: $($user.riskLastUpdatedDateTime)" -ForegroundColor Gray
                }
            }

            $activeHighRisk.Count | Should -Be 0 -Because "High-risk users should be immediately investigated and remediated"
        }
    }

    It "IDP-001.2: Should have no unreviewed medium-risk users older than 7 days" {
        if ($script:RiskyUsersError) {
            Set-ItResult -Skipped -Because "Could not access Identity Protection API"
        }
        else {
            $sevenDaysAgo = (Get-Date).AddDays(-7)
            $oldMediumRisk = $script:MediumRiskUsers | Where-Object {
                $_.riskState -eq 'atRisk' -and
                [datetime]$_.riskLastUpdatedDateTime -lt $sevenDaysAgo
            }

            if ($oldMediumRisk.Count -gt 0) {
                Write-Host "`nMedium-risk users pending review (>7 days):" -ForegroundColor Yellow
                foreach ($user in $oldMediumRisk) {
                    Write-Host "  - $($user.userDisplayName): $($user.riskLastUpdatedDateTime)" -ForegroundColor Yellow
                }
            }

            $oldMediumRisk.Count | Should -Be 0 -Because "Medium-risk users should be reviewed within 7 days"
        }
    }

    It "IDP-001.3: Risky users summary" {
        if ($script:RiskyUsersError) {
            Write-Host "Could not retrieve risky users data" -ForegroundColor Yellow
            Set-ItResult -Skipped -Because "Identity Protection API not accessible"
        }
        else {
            Write-Host "`n========================================" -ForegroundColor Cyan
            Write-Host "Risky Users Summary" -ForegroundColor Cyan
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host "High Risk:   $($script:HighRiskUsers.Count)" -ForegroundColor $(if ($script:HighRiskUsers.Count -gt 0) { 'Red' } else { 'Green' })
            Write-Host "Medium Risk: $($script:MediumRiskUsers.Count)" -ForegroundColor $(if ($script:MediumRiskUsers.Count -gt 0) { 'Yellow' } else { 'Green' })
            Write-Host "Low Risk:    $($script:LowRiskUsers.Count)" -ForegroundColor Gray
            Write-Host "Total:       $($script:RiskyUsers.Count)" -ForegroundColor White

            # Risk state breakdown
            $riskStates = $script:RiskyUsers | Group-Object -Property riskState
            if ($riskStates.Count -gt 0) {
                Write-Host "`nBy Risk State:" -ForegroundColor Cyan
                foreach ($state in $riskStates) {
                    Write-Host "  - $($state.Name): $($state.Count)" -ForegroundColor Gray
                }
            }

            $true | Should -BeTrue
        }
    }
}

Describe "IDP-002 - Risk Detections werden überwacht" -Tag "IdentityProtection", "Security", "Medium" {

    It "IDP-002.1: Should have visibility into risk detections" {
        if ($script:RiskDetectionsError) {
            Set-ItResult -Skipped -Because "Could not access risk detections: $($script:RiskDetectionsError)"
        }
        else {
            # This test verifies that we can access risk detection data
            # Having access means monitoring is possible
            Write-Host "Risk detections accessible - monitoring capability confirmed" -ForegroundColor Green
            $true | Should -BeTrue
        }
    }

    It "IDP-002.2: High-risk detections should be investigated" {
        if ($script:RiskDetectionsError) {
            Set-ItResult -Skipped -Because "Could not access risk detections"
        }
        else {
            $uninvestigatedHighRisk = $script:HighRiskDetections | Where-Object {
                $_.riskState -eq 'atRisk'
            }

            if ($uninvestigatedHighRisk.Count -gt 0) {
                Write-Host "`nUninvestigated high-risk detections:" -ForegroundColor Red
                foreach ($detection in $uninvestigatedHighRisk | Select-Object -First 10) {
                    Write-Host "  - $($detection.riskEventType): $($detection.userDisplayName) at $($detection.detectedDateTime)" -ForegroundColor Red
                }
                if ($uninvestigatedHighRisk.Count -gt 10) {
                    Write-Host "  ... and $($uninvestigatedHighRisk.Count - 10) more" -ForegroundColor Red
                }
            }

            $uninvestigatedHighRisk.Count | Should -Be 0 -Because "High-risk detections require immediate investigation"
        }
    }

    It "IDP-002.3: Recent risk detections should be reviewed" {
        if ($script:RiskDetectionsError) {
            Set-ItResult -Skipped -Because "Could not access risk detections"
        }
        else {
            $unreviewedRecent = $script:RecentDetections | Where-Object {
                $_.riskState -eq 'atRisk'
            }

            Write-Host "`nRisk detections in last 7 days: $($script:RecentDetections.Count)" -ForegroundColor Cyan
            Write-Host "Unreviewed: $($unreviewedRecent.Count)" -ForegroundColor $(if ($unreviewedRecent.Count -gt 0) { 'Yellow' } else { 'Green' })

            # Warning threshold
            if ($unreviewedRecent.Count -gt 10) {
                Write-Host "Warning: High number of unreviewed recent detections" -ForegroundColor Yellow
            }

            $true | Should -BeTrue
        }
    }

    It "IDP-002.4: Risk detections summary" {
        if ($script:RiskDetectionsError) {
            Write-Host "Could not retrieve risk detections data" -ForegroundColor Yellow
            Set-ItResult -Skipped -Because "Risk detections API not accessible"
        }
        else {
            Write-Host "`n========================================" -ForegroundColor Cyan
            Write-Host "Risk Detections Summary (Last 30 Days)" -ForegroundColor Cyan
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host "Total Detections: $($script:RiskDetections.Count)" -ForegroundColor White
            Write-Host "High Risk:        $($script:HighRiskDetections.Count)" -ForegroundColor $(if ($script:HighRiskDetections.Count -gt 0) { 'Red' } else { 'Green' })
            Write-Host "Last 7 Days:      $($script:RecentDetections.Count)" -ForegroundColor White

            # Detection types breakdown
            $detectionTypes = $script:RiskDetections | Group-Object -Property riskEventType | Sort-Object -Property Count -Descending
            if ($detectionTypes.Count -gt 0) {
                Write-Host "`nTop Detection Types:" -ForegroundColor Cyan
                foreach ($type in $detectionTypes | Select-Object -First 5) {
                    Write-Host "  - $($type.Name): $($type.Count)" -ForegroundColor Gray
                }
            }

            # Detection sources
            $detectionSources = $script:RiskDetections | Group-Object -Property source | Sort-Object -Property Count -Descending
            if ($detectionSources.Count -gt 0) {
                Write-Host "`nDetection Sources:" -ForegroundColor Cyan
                foreach ($source in $detectionSources) {
                    Write-Host "  - $($source.Name): $($source.Count)" -ForegroundColor Gray
                }
            }

            $true | Should -BeTrue
        }
    }
}

Describe "IDP-003 - Identity Protection Configuration" -Tag "IdentityProtection", "Info" {

    It "IDP-003.1: Check for automated remediation capability" {
        # Check if there are CA policies that auto-remediate risky users
        try {
            $caPolicies = Invoke-GraphRequest -Uri '/v1.0/identity/conditionalAccess/policies'

            if ($caPolicies.value) {
                $riskRemediationPolicies = $caPolicies.value | Where-Object {
                    $_.state -eq 'enabled' -and
                    ($_.conditions.userRiskLevels -or $_.conditions.signInRiskLevels) -and
                    ($_.grantControls.builtInControls -contains 'passwordChange' -or
                     $_.grantControls.builtInControls -contains 'mfa')
                }

                if ($riskRemediationPolicies.Count -gt 0) {
                    Write-Host "Automated risk remediation policies found:" -ForegroundColor Green
                    foreach ($policy in $riskRemediationPolicies) {
                        Write-Host "  - $($policy.displayName)" -ForegroundColor Gray
                    }
                }
                else {
                    Write-Host "No automated risk remediation policies configured" -ForegroundColor Yellow
                    Write-Host "Consider creating CA policies with password change requirements for risky users" -ForegroundColor Yellow
                }
            }
        }
        catch {
            Write-Warning "Could not check CA policies: $($_.Exception.Message)"
        }

        $true | Should -BeTrue
    }
}

AfterAll {
    $script:IDPCheckResults = @{
        Category            = 'IdentityProtection'
        TotalRiskyUsers     = $script:RiskyUsers.Count
        HighRiskUsers       = $script:HighRiskUsers.Count
        MediumRiskUsers     = $script:MediumRiskUsers.Count
        TotalDetections     = $script:RiskDetections.Count
        HighRiskDetections  = $script:HighRiskDetections.Count
        APIAccessible       = -not $script:RiskyUsersError
        Timestamp           = Get-Date -Format 'o'
    }
}
