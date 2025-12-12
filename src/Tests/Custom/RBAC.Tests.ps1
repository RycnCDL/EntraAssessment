#Requires -Modules Pester, Microsoft.Graph.Authentication

<#
.SYNOPSIS
    RBAC (Role-Based Access Control) Security Tests

.DESCRIPTION
    Pester tests for validating RBAC configuration and role assignments.
    Compatible with Maester test framework.

.NOTES
    Category: RBAC
    Checks: RBAC-001 through RBAC-005
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

    # Critical roles
    $script:CriticalRoles = @{
        'Global Administrator'              = '62e90394-69f5-4237-9190-012177145e10'
        'Privileged Role Administrator'     = 'e8611ab8-c189-46e8-94e1-60213ab1f814'
        'Security Administrator'            = '194ae4cb-b126-40b2-bd5b-6091b380977d'
        'User Administrator'                = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
        'Exchange Administrator'            = '29232cdf-9323-42fd-ade2-1d097af3e4de'
        'SharePoint Administrator'          = 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c'
        'Application Administrator'         = '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'
        'Cloud Application Administrator'   = '158c047a-c907-4556-b7ef-446551a6b5f7'
        'Authentication Administrator'      = 'c4e39bd9-1100-46d3-8c65-fb160da0071f'
        'Privileged Authentication Admin'   = '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'
    }

    # Load directory roles
    $script:DirectoryRoles = Invoke-GraphRequest -Uri '/v1.0/directoryRoles'
    if ($script:DirectoryRoles.value) {
        $script:DirectoryRoles = $script:DirectoryRoles.value
    }

    # Load all role definitions (including custom roles)
    $script:RoleDefinitions = Invoke-GraphRequest -Uri '/v1.0/roleManagement/directory/roleDefinitions' -AllPages
    if ($script:RoleDefinitions.value) {
        $script:RoleDefinitions = $script:RoleDefinitions.value
    }

    # Get total user count
    $script:UserCount = 0
    try {
        $userCountResponse = Invoke-GraphRequest -Uri '/v1.0/users/$count' -Method GET
        $script:UserCount = $userCountResponse
    }
    catch {
        # Fallback: count users manually (limited)
        $users = Invoke-GraphRequest -Uri '/v1.0/users?$top=999&$select=id'
        if ($users.value) {
            $script:UserCount = $users.value.Count
        }
    }

    # Load Global Administrator members
    $globalAdminRole = $script:DirectoryRoles | Where-Object { $_.roleTemplateId -eq $script:CriticalRoles['Global Administrator'] }
    $script:GlobalAdmins = @()
    if ($globalAdminRole) {
        $members = Invoke-GraphRequest -Uri "/v1.0/directoryRoles/$($globalAdminRole.id)/members"
        if ($members.value) {
            $script:GlobalAdmins = $members.value
        }
    }

    # Collect all privileged role members
    $script:AllPrivilegedMembers = @{}
    $script:TotalPrivilegedUsers = @()

    foreach ($roleName in $script:CriticalRoles.Keys) {
        $roleId = $script:CriticalRoles[$roleName]
        $role = $script:DirectoryRoles | Where-Object { $_.roleTemplateId -eq $roleId }

        if ($role) {
            $members = Invoke-GraphRequest -Uri "/v1.0/directoryRoles/$($role.id)/members"
            if ($members.value) {
                $script:AllPrivilegedMembers[$roleName] = $members.value
                $script:TotalPrivilegedUsers += $members.value | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.user' }
            }
        }
    }

    # Deduplicate privileged users
    $script:UniquePrivilegedUsers = $script:TotalPrivilegedUsers | Sort-Object -Property id -Unique
}

Describe "RBAC-001 - Global Admins zwischen 2-5" -Tag "RBAC", "Security", "High" {

    It "RBAC-001.1: Should have at least 2 Global Administrators" {
        $script:GlobalAdmins.Count | Should -BeGreaterOrEqual 2 -Because "At least 2 Global Admins are needed for redundancy"
    }

    It "RBAC-001.2: Should have no more than 5 Global Administrators" {
        $script:GlobalAdmins.Count | Should -BeLessOrEqual 5 -Because "Too many Global Admins increase attack surface. Found: $($script:GlobalAdmins.Count)"
    }

    It "RBAC-001.3: Global Administrator count summary" {
        $adminList = $script:GlobalAdmins | ForEach-Object {
            $type = switch ($_.'@odata.type') {
                '#microsoft.graph.user' { 'User' }
                '#microsoft.graph.servicePrincipal' { 'ServicePrincipal' }
                '#microsoft.graph.group' { 'Group' }
                default { 'Unknown' }
            }
            "$($_.displayName) [$type]"
        }
        Write-Host "Global Administrators ($($script:GlobalAdmins.Count)): $($adminList -join ', ')" -ForegroundColor Cyan
        $true | Should -BeTrue
    }
}

Describe "RBAC-002 - Keine Gäste mit Admin-Rollen" -Tag "RBAC", "Security", "High" {

    BeforeAll {
        $script:GuestAdmins = @()

        foreach ($roleName in $script:CriticalRoles.Keys) {
            $members = $script:AllPrivilegedMembers[$roleName]
            if ($members) {
                foreach ($member in $members) {
                    if ($member.'@odata.type' -eq '#microsoft.graph.user') {
                        # Check if guest
                        try {
                            $user = Invoke-GraphRequest -Uri "/v1.0/users/$($member.id)?`$select=id,displayName,userPrincipalName,userType"
                            if ($user.userType -eq 'Guest') {
                                $script:GuestAdmins += [PSCustomObject]@{
                                    DisplayName       = $user.displayName
                                    UserPrincipalName = $user.userPrincipalName
                                    Role              = $roleName
                                }
                            }
                        }
                        catch {
                            Write-Warning "Could not check user type for $($member.displayName)"
                        }
                    }
                }
            }
        }
    }

    It "RBAC-002.1: Should have no guest users with Global Administrator role" {
        $guestGlobalAdmins = $script:GuestAdmins | Where-Object { $_.Role -eq 'Global Administrator' }
        $guestGlobalAdmins.Count | Should -Be 0 -Because "Guest users should never have Global Admin role"
    }

    It "RBAC-002.2: Should have no guest users with any administrative role" {
        if ($script:GuestAdmins.Count -gt 0) {
            $guestList = $script:GuestAdmins | ForEach-Object { "$($_.DisplayName) - $($_.Role)" }
            Write-Host "Guest users with admin roles: $($guestList -join '; ')" -ForegroundColor Red
        }
        $script:GuestAdmins.Count | Should -Be 0 -Because "Guest users should not have administrative roles"
    }
}

Describe "RBAC-003 - Keine Service Principals als Global Admin" -Tag "RBAC", "Security", "Medium" {

    BeforeAll {
        $script:SPGlobalAdmins = $script:GlobalAdmins | Where-Object {
            $_.'@odata.type' -eq '#microsoft.graph.servicePrincipal'
        }
    }

    It "RBAC-003.1: Should have no Service Principals as Global Administrator" {
        if ($script:SPGlobalAdmins.Count -gt 0) {
            $spList = $script:SPGlobalAdmins | ForEach-Object { "$($_.displayName) ($($_.appId))" }
            Write-Host "Service Principals with Global Admin: $($spList -join ', ')" -ForegroundColor Red
        }
        $script:SPGlobalAdmins.Count | Should -Be 0 -Because "Service Principals should use least-privilege roles, not Global Admin"
    }

    It "RBAC-003.2: Service Principals should use specific roles" {
        # Informational check - list SPs in any admin role
        $spAdmins = @()
        foreach ($roleName in $script:CriticalRoles.Keys) {
            $members = $script:AllPrivilegedMembers[$roleName]
            if ($members) {
                $sps = $members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.servicePrincipal' }
                foreach ($sp in $sps) {
                    $spAdmins += [PSCustomObject]@{
                        DisplayName = $sp.displayName
                        AppId       = $sp.appId
                        Role        = $roleName
                    }
                }
            }
        }

        if ($spAdmins.Count -gt 0) {
            Write-Host "Service Principals with admin roles:" -ForegroundColor Yellow
            $spAdmins | ForEach-Object { Write-Host "  - $($_.DisplayName): $($_.Role)" -ForegroundColor Yellow }
        }

        $true | Should -BeTrue
    }
}

Describe "RBAC-004 - Custom Roles dokumentiert" -Tag "RBAC", "Security", "Low" {

    BeforeAll {
        $script:CustomRoles = $script:RoleDefinitions | Where-Object { $_.isBuiltIn -eq $false }
    }

    It "RBAC-004.1: All custom roles should have descriptions" {
        $rolesWithoutDescription = $script:CustomRoles | Where-Object {
            [string]::IsNullOrWhiteSpace($_.description)
        }

        if ($rolesWithoutDescription.Count -gt 0) {
            $roleList = $rolesWithoutDescription | ForEach-Object { $_.displayName }
            Write-Host "Custom roles without description: $($roleList -join ', ')" -ForegroundColor Yellow
        }

        $rolesWithoutDescription.Count | Should -Be 0 -Because "Custom roles should be documented with descriptions"
    }

    It "RBAC-004.2: Custom roles inventory" {
        if ($script:CustomRoles.Count -gt 0) {
            Write-Host "Custom roles found: $($script:CustomRoles.Count)" -ForegroundColor Cyan
            $script:CustomRoles | ForEach-Object {
                Write-Host "  - $($_.displayName): $($_.description ?? 'No description')" -ForegroundColor Gray
            }
        }
        else {
            Write-Host "No custom roles defined" -ForegroundColor Green
        }
        $true | Should -BeTrue
    }
}

Describe "RBAC-005 - Privilegierte Benutzer unter 5%" -Tag "RBAC", "Security", "Medium" {

    BeforeAll {
        $script:PrivilegedPercentage = 0
        if ($script:UserCount -gt 0 -and $script:UniquePrivilegedUsers.Count -gt 0) {
            $script:PrivilegedPercentage = [math]::Round(($script:UniquePrivilegedUsers.Count / $script:UserCount) * 100, 2)
        }
    }

    It "RBAC-005.1: Privileged users should be less than 5% of total users" {
        Write-Host "Privileged users: $($script:UniquePrivilegedUsers.Count) / $($script:UserCount) = $($script:PrivilegedPercentage)%" -ForegroundColor Cyan

        if ($script:UserCount -eq 0) {
            Set-ItResult -Skipped -Because "Could not determine total user count"
        }
        else {
            $script:PrivilegedPercentage | Should -BeLessThan 5 -Because "High percentage of privileged users increases risk"
        }
    }

    It "RBAC-005.2: Privileged role distribution summary" {
        Write-Host "`nPrivileged role distribution:" -ForegroundColor Cyan
        foreach ($roleName in $script:CriticalRoles.Keys | Sort-Object) {
            $count = ($script:AllPrivilegedMembers[$roleName])?.Count ?? 0
            if ($count -gt 0) {
                Write-Host "  - ${roleName}: $count members" -ForegroundColor Gray
            }
        }
        $true | Should -BeTrue
    }
}

AfterAll {
    $script:RBACCheckResults = @{
        Category            = 'RBAC'
        GlobalAdminCount    = $script:GlobalAdmins.Count
        PrivilegedUserCount = $script:UniquePrivilegedUsers.Count
        TotalUserCount      = $script:UserCount
        CustomRoleCount     = $script:CustomRoles.Count
        GuestAdminCount     = $script:GuestAdmins.Count
        Timestamp           = Get-Date -Format 'o'
    }
}
