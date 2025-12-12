<#
.SYNOPSIS
    Generates assessment reports in HTML, JSON, or Markdown format.

.DESCRIPTION
    Creates professional security assessment reports from check results.
    Supports interactive HTML with collapsible sections, JSON for automation,
    and Markdown for documentation.

.PARAMETER Results
    Array of check result objects from Invoke-EntraSecurityAssessment.

.PARAMETER Format
    Output format: HTML, JSON, or Markdown. Default: HTML.

.PARAMETER OutputPath
    Directory to save the report. Default: ./Reports

.PARAMETER ReportName
    Custom report filename (without extension).

.PARAMETER TenantName
    Tenant display name for the report header.

.PARAMETER IncludeRecommendations
    Include detailed remediation recommendations.

.EXAMPLE
    $results = Invoke-EntraSecurityAssessment
    New-AssessmentReport -Results $results -Format HTML

.EXAMPLE
    New-AssessmentReport -Results $results -Format JSON -OutputPath "C:\Reports"

.OUTPUTS
    [string] Path to the generated report file.
#>
function New-AssessmentReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject[]]$Results,

        [Parameter()]
        [ValidateSet('HTML', 'JSON', 'Markdown', 'MD')]
        [string]$Format = 'HTML',

        [Parameter()]
        [string]$OutputPath = './Reports',

        [Parameter()]
        [string]$ReportName,

        [Parameter()]
        [string]$TenantName,

        [Parameter()]
        [switch]$IncludeRecommendations
    )

    begin {
        $allResults = @()

        # Ensure output directory exists
        if (-not (Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }

        # Get tenant info if not provided
        if (-not $TenantName) {
            try {
                $context = Get-MgContext
                if ($context) {
                    $org = Invoke-MgGraphRequest -Method GET -Uri '/v1.0/organization' -ErrorAction SilentlyContinue
                    $TenantName = $org.value[0].displayName ?? $context.TenantId
                }
            }
            catch {
                $TenantName = 'Unknown Tenant'
            }
        }
    }

    process {
        $allResults += $Results
    }

    end {
        # Generate report filename
        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        if (-not $ReportName) {
            $ReportName = "EntraSecurityAssessment-$timestamp"
        }

        # Calculate statistics
        $stats = @{
            Total        = $allResults.Count
            Passed       = ($allResults | Where-Object Status -eq 'Passed').Count
            Failed       = ($allResults | Where-Object Status -eq 'Failed').Count
            Warning      = ($allResults | Where-Object Status -eq 'Warning').Count
            ManualReview = ($allResults | Where-Object Status -eq 'ManualReview').Count
            Error        = ($allResults | Where-Object Status -eq 'Error').Count
            Skipped      = ($allResults | Where-Object Status -eq 'Skipped').Count
            HighRisk     = ($allResults | Where-Object { $_.Risk -eq 'High' -and $_.Status -eq 'Failed' }).Count
            MediumRisk   = ($allResults | Where-Object { $_.Risk -eq 'Medium' -and $_.Status -eq 'Failed' }).Count
            LowRisk      = ($allResults | Where-Object { $_.Risk -eq 'Low' -and $_.Status -eq 'Failed' }).Count
        }

        $reportPath = switch ($Format) {
            'HTML' {
                $path = Join-Path $OutputPath "$ReportName.html"
                New-HTMLReport -Results $allResults -Stats $stats -TenantName $TenantName -OutputFile $path
                $path
            }
            'JSON' {
                $path = Join-Path $OutputPath "$ReportName.json"
                New-JSONReport -Results $allResults -Stats $stats -TenantName $TenantName -OutputFile $path
                $path
            }
            { $_ -in 'Markdown', 'MD' } {
                $path = Join-Path $OutputPath "$ReportName.md"
                New-MarkdownReport -Results $allResults -Stats $stats -TenantName $TenantName -OutputFile $path
                $path
            }
        }

        Write-Host "Report generated: $reportPath" -ForegroundColor Green
        return $reportPath
    }
}

function New-HTMLReport {
    param(
        [PSObject[]]$Results,
        [hashtable]$Stats,
        [string]$TenantName,
        [string]$OutputFile
    )

    $reportDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $scorePercent = if ($Stats.Total -gt 0) { [math]::Round(($Stats.Passed / $Stats.Total) * 100) } else { 0 }

    # Group results by category
    $byCategory = $Results | Group-Object -Property Category

    # Generate category sections
    $categorySections = foreach ($category in $byCategory) {
        $categoryResults = $category.Group
        $categoryPassed = ($categoryResults | Where-Object Status -eq 'Passed').Count
        $categoryTotal = $categoryResults.Count

        $checkRows = foreach ($check in $categoryResults) {
            $statusClass = switch ($check.Status) {
                'Passed' { 'status-passed' }
                'Failed' { 'status-failed' }
                'Warning' { 'status-warning' }
                'ManualReview' { 'status-manual' }
                'Error' { 'status-error' }
                default { 'status-skipped' }
            }

            $riskClass = switch ($check.Risk) {
                'High' { 'risk-high' }
                'Medium' { 'risk-medium' }
                'Low' { 'risk-low' }
                default { 'risk-info' }
            }

            $detailsHtml = ''
            if ($check.Details -and $check.Details.Count -gt 0) {
                $detailItems = foreach ($key in $check.Details.Keys) {
                    $value = $check.Details[$key]
                    if ($value -is [array]) { $value = $value -join ', ' }
                    "<li><strong>$key:</strong> $value</li>"
                }
                $detailsHtml = "<ul class='details-list'>$($detailItems -join '')</ul>"
            }

            @"
            <tr class="check-row" onclick="toggleDetails(this)">
                <td><span class="check-id">$($check.CheckId)</span></td>
                <td>$($check.Title)</td>
                <td><span class="badge $riskClass">$($check.Risk)</span></td>
                <td><span class="badge $statusClass">$($check.Status)</span></td>
            </tr>
            <tr class="details-row" style="display:none;">
                <td colspan="4">
                    <div class="details-content">
                        <p><strong>Description:</strong> $($check.Description)</p>
                        $(if ($check.Remediation) { "<p><strong>Remediation:</strong> $($check.Remediation)</p>" })
                        $(if ($check.Reference) { "<p><strong>Reference:</strong> <a href='$($check.Reference)' target='_blank'>$($check.Reference)</a></p>" })
                        $detailsHtml
                    </div>
                </td>
            </tr>
"@
        }

        @"
        <div class="category-section">
            <div class="category-header" onclick="toggleCategory(this)">
                <h3>
                    <span class="toggle-icon">&#9660;</span>
                    $($category.Name)
                    <span class="category-stats">$categoryPassed / $categoryTotal passed</span>
                </h3>
            </div>
            <div class="category-content">
                <table class="checks-table">
                    <thead>
                        <tr>
                            <th width="100">Check ID</th>
                            <th>Title</th>
                            <th width="80">Risk</th>
                            <th width="100">Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        $($checkRows -join "`n")
                    </tbody>
                </table>
            </div>
        </div>
"@
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Entra Security Assessment - $TenantName</title>
    <style>
        :root {
            --primary: #0078d4;
            --primary-dark: #106ebe;
            --success: #107c10;
            --warning: #ffb900;
            --danger: #d13438;
            --info: #8764b8;
            --gray: #605e5c;
            --light-gray: #f3f2f1;
            --border: #edebe9;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--light-gray);
            color: #323130;
            line-height: 1.5;
        }

        .header {
            background: linear-gradient(135deg, #0078d4 0%, #106ebe 100%);
            color: white;
            padding: 2rem;
            text-align: center;
        }

        .header h1 { font-size: 1.8rem; font-weight: 600; margin-bottom: 0.5rem; }
        .header .tenant { font-size: 1.1rem; opacity: 0.9; }
        .header .date { font-size: 0.9rem; opacity: 0.7; margin-top: 0.5rem; }

        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }

        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: white;
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .stat-card .number { font-size: 2.5rem; font-weight: 700; }
        .stat-card .label { color: var(--gray); font-size: 0.9rem; }
        .stat-card.passed .number { color: var(--success); }
        .stat-card.failed .number { color: var(--danger); }
        .stat-card.warning .number { color: var(--warning); }
        .stat-card.score .number { color: var(--primary); }

        .score-ring {
            width: 120px;
            height: 120px;
            margin: 0 auto 1rem;
            position: relative;
        }

        .score-ring svg { transform: rotate(-90deg); }
        .score-ring circle {
            fill: none;
            stroke-width: 10;
        }
        .score-ring .bg { stroke: var(--border); }
        .score-ring .progress { stroke: var(--primary); stroke-linecap: round; transition: stroke-dashoffset 0.5s; }
        .score-ring .score-text {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 1.8rem;
            font-weight: 700;
            color: var(--primary);
        }

        .category-section {
            background: white;
            border-radius: 8px;
            margin-bottom: 1rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }

        .category-header {
            background: var(--light-gray);
            padding: 1rem 1.5rem;
            cursor: pointer;
            border-bottom: 1px solid var(--border);
        }

        .category-header:hover { background: #e8e8e8; }
        .category-header h3 { display: flex; align-items: center; gap: 0.5rem; font-size: 1.1rem; }
        .category-stats { margin-left: auto; font-size: 0.9rem; color: var(--gray); font-weight: normal; }
        .toggle-icon { font-size: 0.8rem; transition: transform 0.2s; }
        .category-header.collapsed .toggle-icon { transform: rotate(-90deg); }

        .category-content { padding: 0; }
        .category-content.hidden { display: none; }

        .checks-table { width: 100%; border-collapse: collapse; }
        .checks-table th, .checks-table td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }
        .checks-table th { background: #faf9f8; font-weight: 600; color: var(--gray); font-size: 0.85rem; text-transform: uppercase; }
        .checks-table tbody tr:hover { background: #faf9f8; }

        .check-row { cursor: pointer; }
        .check-id { font-family: monospace; color: var(--primary); }

        .badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .status-passed { background: #dff6dd; color: var(--success); }
        .status-failed { background: #fde7e9; color: var(--danger); }
        .status-warning { background: #fff4ce; color: #8a6914; }
        .status-manual { background: #e8daef; color: var(--info); }
        .status-error { background: #f3f2f1; color: var(--gray); }
        .status-skipped { background: #f3f2f1; color: var(--gray); }

        .risk-high { background: #fde7e9; color: var(--danger); }
        .risk-medium { background: #fff4ce; color: #8a6914; }
        .risk-low { background: #deecf9; color: var(--primary); }
        .risk-info { background: #f3f2f1; color: var(--gray); }

        .details-row td { padding: 0 !important; background: #faf9f8; }
        .details-content { padding: 1rem 1.5rem; border-left: 4px solid var(--primary); margin: 0.5rem 1rem; }
        .details-content p { margin-bottom: 0.5rem; }
        .details-content a { color: var(--primary); }
        .details-list { margin-top: 0.5rem; padding-left: 1.5rem; }
        .details-list li { margin-bottom: 0.25rem; }

        .footer {
            text-align: center;
            padding: 2rem;
            color: var(--gray);
            font-size: 0.9rem;
        }

        @media (max-width: 768px) {
            .dashboard { grid-template-columns: repeat(2, 1fr); }
            .container { padding: 1rem; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Entra Security Assessment Report</h1>
        <div class="tenant">$TenantName</div>
        <div class="date">Generated: $reportDate</div>
    </div>

    <div class="container">
        <div class="dashboard">
            <div class="stat-card score">
                <div class="score-ring">
                    <svg width="120" height="120">
                        <circle class="bg" cx="60" cy="60" r="50"/>
                        <circle class="progress" cx="60" cy="60" r="50"
                            stroke-dasharray="314"
                            stroke-dashoffset="$(314 - (314 * $scorePercent / 100))"/>
                    </svg>
                    <div class="score-text">$scorePercent%</div>
                </div>
                <div class="label">Security Score</div>
            </div>
            <div class="stat-card passed">
                <div class="number">$($Stats.Passed)</div>
                <div class="label">Passed</div>
            </div>
            <div class="stat-card failed">
                <div class="number">$($Stats.Failed)</div>
                <div class="label">Failed</div>
            </div>
            <div class="stat-card warning">
                <div class="number">$($Stats.Warning)</div>
                <div class="label">Warnings</div>
            </div>
            <div class="stat-card">
                <div class="number">$($Stats.ManualReview)</div>
                <div class="label">Manual Review</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color: var(--danger);">$($Stats.HighRisk)</div>
                <div class="label">High Risk Issues</div>
            </div>
        </div>

        $($categorySections -join "`n")
    </div>

    <div class="footer">
        <p>Entra Security Assessment Tool | Powered by Microsoft Graph API</p>
    </div>

    <script>
        function toggleCategory(header) {
            header.classList.toggle('collapsed');
            const content = header.nextElementSibling;
            content.classList.toggle('hidden');
        }

        function toggleDetails(row) {
            const detailsRow = row.nextElementSibling;
            if (detailsRow.classList.contains('details-row')) {
                detailsRow.style.display = detailsRow.style.display === 'none' ? 'table-row' : 'none';
            }
        }
    </script>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputFile -Encoding UTF8
}

function New-JSONReport {
    param(
        [PSObject[]]$Results,
        [hashtable]$Stats,
        [string]$TenantName,
        [string]$OutputFile
    )

    $report = @{
        metadata = @{
            reportType    = 'EntraSecurityAssessment'
            version       = '1.0.0'
            generatedAt   = Get-Date -Format 'o'
            tenantName    = $TenantName
            tenantId      = (Get-MgContext)?.TenantId
        }
        summary = $Stats
        results = $Results
    }

    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile -Encoding UTF8
}

function New-MarkdownReport {
    param(
        [PSObject[]]$Results,
        [hashtable]$Stats,
        [string]$TenantName,
        [string]$OutputFile
    )

    $reportDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $scorePercent = if ($Stats.Total -gt 0) { [math]::Round(($Stats.Passed / $Stats.Total) * 100) } else { 0 }

    $md = @"
# Entra Security Assessment Report

**Tenant:** $TenantName
**Generated:** $reportDate
**Security Score:** $scorePercent%

## Summary

| Metric | Count |
|--------|-------|
| Total Checks | $($Stats.Total) |
| Passed | $($Stats.Passed) |
| Failed | $($Stats.Failed) |
| Warnings | $($Stats.Warning) |
| Manual Review | $($Stats.ManualReview) |
| High Risk Issues | $($Stats.HighRisk) |

---

"@

    # Group by category
    $byCategory = $Results | Group-Object -Property Category

    foreach ($category in $byCategory) {
        $md += "## $($category.Name)`n`n"
        $md += "| Check ID | Title | Risk | Status |`n"
        $md += "|----------|-------|------|--------|`n"

        foreach ($check in $category.Group) {
            $statusIcon = switch ($check.Status) {
                'Passed' { ':white_check_mark:' }
                'Failed' { ':x:' }
                'Warning' { ':warning:' }
                'ManualReview' { ':eyes:' }
                default { ':grey_question:' }
            }
            $md += "| $($check.CheckId) | $($check.Title) | $($check.Risk) | $statusIcon $($check.Status) |`n"
        }

        $md += "`n"

        # Add details for failed checks
        $failedChecks = $category.Group | Where-Object { $_.Status -in @('Failed', 'Warning') }
        if ($failedChecks) {
            $md += "### Details`n`n"
            foreach ($check in $failedChecks) {
                $md += "#### $($check.CheckId): $($check.Title)`n`n"
                $md += "- **Status:** $($check.Status)`n"
                $md += "- **Risk:** $($check.Risk)`n"
                $md += "- **Description:** $($check.Description)`n"
                if ($check.Remediation) { $md += "- **Remediation:** $($check.Remediation)`n" }
                if ($check.Reference) { $md += "- **Reference:** [$($check.Reference)]($($check.Reference))`n" }
                $md += "`n"
            }
        }
    }

    $md += @"
---

*Report generated by Entra Security Assessment Tool*
"@

    $md | Out-File -FilePath $OutputFile -Encoding UTF8
}

# Export function
Export-ModuleMember -Function 'New-AssessmentReport'
