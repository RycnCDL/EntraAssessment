#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Connects to Microsoft Graph API for Entra Security Assessment.

.DESCRIPTION
    Establishes a connection to Microsoft Graph API supporting multiple authentication methods:
    - Interactive (Browser-based or Device Code)
    - Service Principal with Client Secret
    - Service Principal with Certificate
    - Managed Identity (for Azure-hosted scenarios)

    Supports Multi-Tenant scenarios via Azure Lighthouse.

.PARAMETER TenantId
    The Tenant ID to connect to. Required for all authentication methods.

.PARAMETER Interactive
    Use interactive browser-based authentication. Default method.

.PARAMETER DeviceCode
    Use device code flow for authentication (useful for headless systems).

.PARAMETER ClientId
    Application (Client) ID for Service Principal authentication.

.PARAMETER ClientSecret
    Client Secret for Service Principal authentication.

.PARAMETER CertificateThumbprint
    Certificate thumbprint for Service Principal authentication.

.PARAMETER ManagedIdentity
    Use Managed Identity authentication (Azure VMs, Azure Functions, etc.).

.PARAMETER Scopes
    Custom scopes to request. If not specified, uses default assessment scopes.

.EXAMPLE
    Connect-EntraAssessment -TenantId "contoso.onmicrosoft.com"

    Connects interactively to the specified tenant.

.EXAMPLE
    Connect-EntraAssessment -TenantId "xxx-xxx-xxx" -DeviceCode

    Connects using device code flow.

.EXAMPLE
    Connect-EntraAssessment -TenantId "xxx-xxx-xxx" -ClientId "app-id" -ClientSecret $secret

    Connects using Service Principal with client secret.

.EXAMPLE
    Connect-EntraAssessment -TenantId "xxx-xxx-xxx" -ClientId "app-id" -CertificateThumbprint "ABC123"

    Connects using Service Principal with certificate.

.OUTPUTS
    [PSCustomObject] Connection status object with tenant information.

.NOTES
    Author: Entra Security Assessment Tool
    Requires: Microsoft.Graph.Authentication module
#>
function Connect-EntraAssessment {
    [CmdletBinding(DefaultParameterSetName = 'Interactive')]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(ParameterSetName = 'Interactive')]
        [switch]$Interactive,

        [Parameter(ParameterSetName = 'DeviceCode')]
        [switch]$DeviceCode,

        [Parameter(ParameterSetName = 'ServicePrincipalSecret', Mandatory = $true)]
        [Parameter(ParameterSetName = 'ServicePrincipalCert', Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ClientId,

        [Parameter(ParameterSetName = 'ServicePrincipalSecret', Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [SecureString]$ClientSecret,

        [Parameter(ParameterSetName = 'ServicePrincipalCert', Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'ManagedIdentity')]
        [switch]$ManagedIdentity,

        [Parameter()]
        [string[]]$Scopes
    )

    begin {
        # Default scopes required for security assessment
        $DefaultScopes = @(
            'Directory.Read.All'
            'Policy.Read.All'
            'RoleManagement.Read.All'
            'IdentityRiskyUser.Read.All'
            'IdentityRiskEvent.Read.All'
            'AuditLog.Read.All'
            'User.Read.All'
            'Group.Read.All'
            'Application.Read.All'
            'PrivilegedAccess.Read.AzureAD'
            'InformationProtectionPolicy.Read.All'
        )

        if (-not $Scopes) {
            $Scopes = $DefaultScopes
        }

        # Store connection info in script scope for reuse
        $script:EntraAssessmentConnection = $null
    }

    process {
        try {
            Write-Verbose "Attempting to connect to tenant: $TenantId"

            # Disconnect existing session if any
            $existingContext = Get-MgContext -ErrorAction SilentlyContinue
            if ($existingContext) {
                Write-Verbose "Disconnecting existing Graph session..."
                Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            }

            # Build connection parameters
            $connectParams = @{
                TenantId    = $TenantId
                ErrorAction = 'Stop'
            }

            switch ($PSCmdlet.ParameterSetName) {
                'Interactive' {
                    Write-Host "Connecting to Microsoft Graph (Interactive)..." -ForegroundColor Cyan
                    $connectParams['Scopes'] = $Scopes
                }

                'DeviceCode' {
                    Write-Host "Connecting to Microsoft Graph (Device Code)..." -ForegroundColor Cyan
                    Write-Host "Please use a web browser to open https://microsoft.com/devicelogin" -ForegroundColor Yellow
                    $connectParams['Scopes'] = $Scopes
                    $connectParams['UseDeviceCode'] = $true
                }

                'ServicePrincipalSecret' {
                    Write-Host "Connecting to Microsoft Graph (Service Principal - Secret)..." -ForegroundColor Cyan
                    $credential = New-Object System.Management.Automation.PSCredential($ClientId, $ClientSecret)
                    $connectParams['ClientSecretCredential'] = $credential
                }

                'ServicePrincipalCert' {
                    Write-Host "Connecting to Microsoft Graph (Service Principal - Certificate)..." -ForegroundColor Cyan
                    $connectParams['ClientId'] = $ClientId
                    $connectParams['CertificateThumbprint'] = $CertificateThumbprint
                }

                'ManagedIdentity' {
                    Write-Host "Connecting to Microsoft Graph (Managed Identity)..." -ForegroundColor Cyan
                    $connectParams['Identity'] = $true
                }
            }

            # Connect to Microsoft Graph
            Connect-MgGraph @connectParams

            # Verify connection and get context
            $context = Get-MgContext
            if (-not $context) {
                throw "Failed to establish connection to Microsoft Graph"
            }

            # Get tenant details
            $tenantDetails = $null
            try {
                $tenantDetails = Invoke-MgGraphRequest -Method GET -Uri "/v1.0/organization" -ErrorAction Stop
            }
            catch {
                Write-Warning "Could not retrieve tenant details: $($_.Exception.Message)"
            }

            # Build connection status object
            $connectionInfo = [PSCustomObject]@{
                Connected       = $true
                TenantId        = $context.TenantId
                TenantName      = $tenantDetails.value[0].displayName ?? 'Unknown'
                AuthType        = $PSCmdlet.ParameterSetName
                Account         = $context.Account
                Scopes          = $context.Scopes
                ConnectedAt     = Get-Date
                Environment     = $context.Environment
                AppName         = $context.AppName
                ContextScope    = $context.ContextScope
            }

            # Store in script scope
            $script:EntraAssessmentConnection = $connectionInfo

            Write-Host "`nSuccessfully connected to Microsoft Graph" -ForegroundColor Green
            Write-Host "  Tenant:  $($connectionInfo.TenantName) ($($connectionInfo.TenantId))" -ForegroundColor Gray
            Write-Host "  Account: $($connectionInfo.Account)" -ForegroundColor Gray
            Write-Host "  Scopes:  $($connectionInfo.Scopes.Count) permissions granted" -ForegroundColor Gray

            return $connectionInfo
        }
        catch {
            $errorMessage = "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
            Write-Error $errorMessage

            return [PSCustomObject]@{
                Connected   = $false
                TenantId    = $TenantId
                Error       = $_.Exception.Message
                AuthType    = $PSCmdlet.ParameterSetName
                ConnectedAt = $null
            }
        }
    }
}

<#
.SYNOPSIS
    Tests the current connection to Microsoft Graph.

.DESCRIPTION
    Validates that the current Graph connection is active and has the required permissions
    for running security assessments.

.PARAMETER RequiredScopes
    Array of scopes to validate. If not specified, checks default assessment scopes.

.EXAMPLE
    Test-EntraAssessmentConnection

    Tests if the connection is active and has required permissions.

.OUTPUTS
    [PSCustomObject] Connection test result with permission details.
#>
function Test-EntraAssessmentConnection {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]]$RequiredScopes
    )

    $DefaultRequiredScopes = @(
        'Directory.Read.All'
        'Policy.Read.All'
        'RoleManagement.Read.All'
    )

    if (-not $RequiredScopes) {
        $RequiredScopes = $DefaultRequiredScopes
    }

    try {
        $context = Get-MgContext

        if (-not $context) {
            return [PSCustomObject]@{
                IsConnected     = $false
                HasPermissions  = $false
                MissingScopes   = $RequiredScopes
                Message         = "Not connected to Microsoft Graph. Run Connect-EntraAssessment first."
            }
        }

        # Check for required scopes
        $grantedScopes = $context.Scopes
        $missingScopes = $RequiredScopes | Where-Object { $_ -notin $grantedScopes }

        $hasAllPermissions = $missingScopes.Count -eq 0

        return [PSCustomObject]@{
            IsConnected     = $true
            HasPermissions  = $hasAllPermissions
            TenantId        = $context.TenantId
            Account         = $context.Account
            GrantedScopes   = $grantedScopes
            MissingScopes   = $missingScopes
            Message         = if ($hasAllPermissions) { "Connection valid with all required permissions." } else { "Missing required scopes: $($missingScopes -join ', ')" }
        }
    }
    catch {
        return [PSCustomObject]@{
            IsConnected     = $false
            HasPermissions  = $false
            Error           = $_.Exception.Message
            Message         = "Error testing connection: $($_.Exception.Message)"
        }
    }
}

<#
.SYNOPSIS
    Disconnects from Microsoft Graph.

.DESCRIPTION
    Terminates the current Microsoft Graph session and clears stored connection info.

.EXAMPLE
    Disconnect-EntraAssessment

    Disconnects from Microsoft Graph.
#>
function Disconnect-EntraAssessment {
    [CmdletBinding()]
    param()

    try {
        $context = Get-MgContext
        if ($context) {
            Disconnect-MgGraph -ErrorAction Stop
            $script:EntraAssessmentConnection = $null
            Write-Host "Disconnected from Microsoft Graph" -ForegroundColor Green
        }
        else {
            Write-Host "No active Microsoft Graph connection" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Error "Error disconnecting: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Gets the current Entra Assessment connection information.

.DESCRIPTION
    Returns details about the current Microsoft Graph connection used for assessments.

.EXAMPLE
    Get-EntraAssessmentConnection

    Returns current connection details.

.OUTPUTS
    [PSCustomObject] Current connection information or null if not connected.
#>
function Get-EntraAssessmentConnection {
    [CmdletBinding()]
    param()

    if ($script:EntraAssessmentConnection) {
        return $script:EntraAssessmentConnection
    }

    $context = Get-MgContext
    if ($context) {
        return [PSCustomObject]@{
            Connected   = $true
            TenantId    = $context.TenantId
            Account     = $context.Account
            Scopes      = $context.Scopes
            Environment = $context.Environment
        }
    }

    return $null
}

# Export functions
Export-ModuleMember -Function @(
    'Connect-EntraAssessment'
    'Test-EntraAssessmentConnection'
    'Disconnect-EntraAssessment'
    'Get-EntraAssessmentConnection'
)
