@{
    # Script module or binary module file associated with this manifest
    RootModule = 'EntraSecurityAssessment.psm1'

    # Version number of this module
    ModuleVersion = '1.0.0'

    # Supported PSEditions
    CompatiblePSEditions = @('Core', 'Desktop')

    # ID used to uniquely identify this module
    GUID = 'a8b3c4d5-e6f7-8901-2345-6789abcdef01'

    # Author of this module
    Author = 'Entra Security Assessment Team'

    # Company or vendor of this module
    CompanyName = 'Security Assessment'

    # Copyright statement for this module
    Copyright = '(c) 2024 Entra Security Assessment. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'PowerShell Security Assessment Framework for Microsoft Entra ID and M365. Provides automated security checks for PIM, RBAC, Conditional Access, Identity Protection, and Copilot configurations.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '7.0'

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @(
        @{
            ModuleName = 'Microsoft.Graph.Authentication'
            ModuleVersion = '2.0.0'
        }
    )

    # Functions to export from this module
    FunctionsToExport = @(
        # Core Functions
        'Connect-EntraAssessment'
        'Disconnect-EntraAssessment'
        'Test-EntraAssessmentConnection'
        'Get-EntraAssessmentConnection'

        # Assessment Functions
        'Invoke-EntraSecurityAssessment'
        'Invoke-MultiTenantAssessment'

        # Category-specific Functions
        'Invoke-PIMSecurityCheck'
        'Invoke-RBACSecurityCheck'
        'Invoke-ConditionalAccessCheck'
        'Invoke-IdentityProtectionCheck'
        'Invoke-CopilotSecurityCheck'

        # Health & Export Functions
        'Get-TenantHealth'
        'Export-AssessmentData'

        # Report Functions
        'New-AssessmentReport'
    )

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @(
        'esa'        # Invoke-EntraSecurityAssessment
        'cea'        # Connect-EntraAssessment
    )

    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            # Tags applied to this module
            Tags = @(
                'Security'
                'Assessment'
                'EntraID'
                'AzureAD'
                'M365'
                'Microsoft365'
                'PIM'
                'RBAC'
                'ConditionalAccess'
                'IdentityProtection'
                'Copilot'
                'Maester'
                'Pester'
            )

            # A URL to the license for this module
            LicenseUri = ''

            # A URL to the main website for this project
            ProjectUri = ''

            # ReleaseNotes of this module
            ReleaseNotes = @'
## Version 1.0.0
- Initial release
- Support for PIM, RBAC, Conditional Access, Identity Protection, and Copilot security checks
- Multi-tenant support via Azure Lighthouse
- Interactive and Service Principal authentication
- HTML, JSON, and Markdown report generation
- Maester/Pester compatible test framework
'@

            # Prerelease string of this module
            # Prerelease = ''

            # Flag to indicate whether the module requires explicit user acceptance for install/update/save
            RequireLicenseAcceptance = $false

            # External dependent modules of this module
            ExternalModuleDependencies = @(
                'Microsoft.Graph.Authentication'
            )
        }
    }

    # HelpInfo URI of this module
    # HelpInfoURI = ''

    # Default prefix for commands exported from this module
    # DefaultCommandPrefix = 'Entra'
}
