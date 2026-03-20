#
# Module manifest for module 'F4keH0und'
#
@{

# Script module or binary module file associated with this manifest.
RootModule = 'F4keH0und.psm1' # CHANGED

# Version number of this module.
ModuleVersion = '2.5.0'

# ID used to uniquely identify this module
GUID = 'd2b0e6f3-8d3c-4e8f-8c6a-1e9f4c3a2b1d'

# Author of this module
Author = 'm3c4n1sm0'

# Company or vendor of this module
CompanyName = 'DCG420'

# Copyright statement for this module
Copyright = '(c) 2025 m3c4n1sm0. All rights reserved.'

# Description of the functionality provided by this module.
Description = 'A PowerShell framework to analyze BloodHound data, recommend deception opportunities, and deploy decoy objects in AD and Entra ID.'

# Functions to export from this module, for best performance, do not use wildcards.
FunctionsToExport = @(
    'Find-F4keH0undOpportunity',   # CHANGED
    'New-F4keH0undDecoy',          # CHANGED
    'Add-F4keH0undRelationship',   # CHANGED
    'Remove-F4keH0undDecoy'        # CHANGED
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
        Tags = @('BloodHound', 'Active Directory', 'Entra ID', 'Deception', 'Cybersecurity', 'Hacking') # Added a new tag!
        # LicenseUri = ''
        ProjectUri = 'https://github.com/DEF-CON-Group-420/F4keH0und'
        # IconUri = ''
    }
}

}
