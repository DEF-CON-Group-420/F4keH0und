#
# Module manifest for module 'F4keH0und'
#
@{

# Script module or binary module file associated with this manifest.
RootModule = 'F4keH0und.psm1'

# Version number of this module.
ModuleVersion = '2.16.0'

# ID used to uniquely identify this module
GUID = 'd2b0e6f3-8d3c-4e8f-8c6a-1e9f4c3a2b1d'

# Author of this module
Author = 'm3c4n1sm0'

# Company or vendor of this module
CompanyName = 'DCG420'

# Copyright statement for this module
Copyright = '(c) 2025 m3c4n1sm0. All rights reserved.'

# Description of the functionality provided by this module.
Description = 'F4keH0und - Last Generation: A PowerShell framework to analyze BloodHound data, recommend deception opportunities, and manage deceptive elements across AD, Entra ID, and Windows artifact planes.'

# Functions to export from this module, for best performance, do not use wildcards.
FunctionsToExport = @(
    'Find-F4keH0undOpportunity',
    'New-F4keH0undDecoy',
    'Get-F4keH0undElementType',
    'New-F4keH0undElement',
    'New-F4keH0undToken',
    'Register-F4keH0undTokenTrigger',
    'Update-F4keH0undElement',
    'Disable-F4keH0undElement',
    'Enable-F4keH0undElement',
    'Remove-F4keH0undElement',
    'Sync-F4keH0undEntraParity',
    'Update-F4keH0undDecoy',
    'Disable-F4keH0undDecoy',
    'Enable-F4keH0undDecoy',
    'Add-F4keH0undRelationship',
    'Remove-F4keH0undDecoy',
    'Get-F4keH0undInventory',
    'Get-F4keH0undConfig',
    'Test-F4keH0undDrift',
    'Test-F4keH0undCoverage',
    'Test-F4keH0undConfig'
)

# Cmdlets to export from this module
CmdletsToExport = @()

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module
AliasesToExport = @()

# Private data to pass to the module root script.
PrivateData = @{

    PSData = @{
        Tags = @('BloodHound', 'Active Directory', 'Entra ID', 'Deception', 'Cybersecurity', 'PowerShell', 'LastGeneration')
        # LicenseUri = ''
        ProjectUri = 'https://github.com/th3r3d/F4keH0und-LG'
        # IconUri = ''
    }
}

}
