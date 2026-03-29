function Get-F4keH0undRank {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject]$Opportunity
    )

    process {
    # Use a switch statement to determine the rank based on the DecoyType
    switch ($Opportunity.DecoyType) {
        "StaleAdminUser" {
            return "Critical"
        }
        "KerberoastableUser" {
            return "High"
        }
        "UnconstrainedDelegationComputer" {
            return "High"
        }
        "DNSAdminUser" {
            return "Critical"
        }
        # NEW CASE
        "ACLAttackPath" {
            return "High"
        }
        "PrivilegedEntraSP" {
            return "Critical"
        }
        default {
            return "Low"
        }
    }
    } # end process
}