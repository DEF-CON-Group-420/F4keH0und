function Get-F4keH0undRank {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject]$Opportunity
    )

    # Use a switch statement to determine the rank based on the DecoyType
    switch ($Opportunity.DecoyType) {
        "StaleAdminUser" {
            # Mimics direct access to Tier 0 assets.
            return "Critical"
        }
        "KerberoastableUser" {
            # Lures an attacker on a known, dangerous attack path.
            return "High"
        }
        # We will add more cases here as we add more decoy types.
        default {
            # Default to Low for any unrecognized type.
            return "Low"
        }
    }
}