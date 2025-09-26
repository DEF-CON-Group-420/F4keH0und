# F4keH0und
*A PowerShell framework for deploying Active Directory & Entra ID deception at scale.*

---

## 📖 Description

**F4keH0und** is a PowerShell module designed for blue teams, red teams, and security researchers. It programmatically analyzes the output from BloodHound data collectors (SharpHound and AzureHound) to identify high-value deception opportunities within an Active Directory or Microsoft Entra ID environment.

Based on its analysis, it suggests decoy users, service principals, and computers that mimic real, high-value targets. Upon user approval, F4keH0und can deploy these decoys, creating a landscape of honey accounts and Kerberoastable lures designed to detect and deceive attackers.

This tool follows a "Suggest -> Approve -> Create" workflow, with safety features like `-WhatIf` and flexible credential handling built-in to ensure you have full control over any changes made to your environment, **even when targeting a different domain from the one your machine is joined to.**

---

## ✨ Features

-   **Data-Driven Analysis**: Parses timestamp-prefixed JSON from SharpHound and single-file JSON from AzureHound.
-   **Hybrid Environment Support**: Analyzes both on-premises Active Directory and Microsoft Entra ID data.
-   **Cross-Domain Operations**: Use the `-Server` parameter to run the module from an administrative bastion host or a machine in a different domain/forest.
-   **Opportunity Ranking**: Intelligently ranks deception opportunities from **Critical** to **Low** to prioritize the most impactful decoys.
-   **Interactive Deployment**: A user-friendly workflow guides you through selecting and confirming which decoys to create.
-   **Decoy Variety**: Creates multiple types of decoys, including:
    -   **Stale Admin Lures (AD)**: Mimics dormant, privileged on-prem accounts.
    -   **Kerberoastable Lures (AD)**: Deploys users with tempting SPNs to detect Kerberoasting attacks.
    -   **Over-privileged Principals (Entra ID)**: Mimics Entra ID Service Principals with high-privilege roles.
-   **Secure & Flexible Authentication**: Use the `-Credential` parameter to run the script from a standard user session and provide privileged credentials on-the-fly.
-   **Safe by Default**: Includes full `-WhatIf` and `-Confirm` support. No changes are made without explicit approval.
-   **Automated Reporting**: Generates a detailed CSV "handover report" of all created decoys for your SecOps team.
-   **Clean Cleanup**: Includes a `Remove-F4keH0undDecoy` function to cleanly remove all decoys and their associated group memberships.

---

## ⚙️ Prerequisites

1.  **PowerShell 7+**: Recommended for the best compatibility.
2.  **Permissions**: The script must be run in a session that can satisfy the necessary permissions. You have two options:
    * **Run As Privileged User**: Run PowerShell as a user who already has permissions in the target domain. This is only possible if your workstation is a member of the target domain.
    * **Use `-Credential` Parameter**: Run as any user and supply the credentials of a privileged account in the target domain. **This is required for cross-domain operations.**
3.  **Required Modules**:
    * For on-prem AD operations, the **Active Directory Module** (part of RSAT) is required.
4.  **Network Connectivity**: If running against a different domain (using the `-Server` parameter), you must have network connectivity to the target Domain Controller (e.g., firewall ports for AD Web Services, TCP 9389).
5.  **BloodHound Data**: You need the JSON output from a recent SharpHound or AzureHound run.

---

## 🚀 Installation

1.  Clone this repository or download the source code as a ZIP file.
2.  Unzip the folder and ensure the directory containing the module is named `F4keH0und`.
3.  Copy the entire `F4keH0und` folder to one of the directories listed in your `$env:PSModulePath`. A common location is `C:\Users\<YourUsername>\Documents\PowerShell\Modules\`.
4.  Open a new PowerShell terminal and verify the installation with `Get-Module -ListAvailable -Name F4keH0und`.

---

##  workflows/Usage

### 1. Import the Module
```powershell
Import-Module F4keH0und -Force
````

### 2\. Run Analysis

This step is always read-only and can be run from any machine.

**For Active Directory:**

```powershell
Find-F4keH0undOpportunity -BloodHoundPath C:\Path\To\AD_Data\
```

**For Entra ID:**

```powershell
Find-F4keH0undOpportunity -AzureHoundPath C:\Path\To\Entra_Data\
```

### 3\. Deploy Decoys

The method you use depends on your environment.

**Scenario A: Your machine IS a member of the target domain.**
You can rely on your existing login session if it has permissions.

```powershell
# Perform a dry run
New-F4keH0undDecoy -BloodHoundPath C:\Path\To\AD_Data\ -Execute -WhatIf

# Perform the live run
New-F4keH0undDecoy -BloodHoundPath C:\Path\To\AD_Data\ -Execute
```

**Scenario B: Your machine IS NOT a member of the target domain (Recommended Secure Method).**
You **must** use the `-Server` and `-Credential` parameters.

```powershell
# Perform a dry run
New-F4keH0undDecoy -BloodHoundPath C:\Path\To\AD_Data\ -Execute -WhatIf -Server "DC01.target.local" -Credential (Get-Credential)

# Perform the live run
New-F4keH0undDecoy -BloodHoundPath C:\Path\To\AD_Data\ -Execute -Server "DC01.target.local" -Credential (Get-Credential)
```

### 4\. Clean Up Decoys

Similarly, use the `-Server` and `-Credential` parameters when cleaning up from a machine in a different domain.

```powershell
# Perform a dry run of the removal
Remove-F4keH0undDecoy -Identity "decoy_svc_mssql_prod" -WhatIf -Server "DC01.target.local" -Credential (Get-Credential)

# Perform the live removal
Remove-F4keH0undDecoy -Identity "decoy_svc_mssql_prod" -Server "DC01.target.local" -Credential (Get-Credential)
```

-----

## 🔧 Extending F4keH0und

The module is designed to be easily extended with new detection types. Follow this 4-step process:

1.  **Define the Logic & Decoy**: Decide what to look for in the BloodHound JSON data and what kind of decoy you'll create.
2.  **Add Analysis Logic**: Edit `Public\Find-F4keH0undOpportunity.ps1` to include a new block that filters for your target and creates a new opportunity object with a unique `DecoyType`.
3.  **Add Ranking Logic**: Edit `Private\Get-F4keH0undRank.ps1` and add a new `case` to the `switch` statement for your new `DecoyType` to assign it a rank.
4.  **Add Deployment Logic**: Edit `Public\New-F4keH0undDecoy.ps1` by adding a new `case` to its `switch` statement. You will likely need to create a new private helper function (e.g., `New-PrivateADDecoyGroup.ps1`) to handle the actual creation.

-----

## ⚠️ Disclaimer

**This is a hobby project for educational and research purposes.** Making unauthorized changes to a production Active Directory environment can cause significant disruption. Use this tool responsibly and only on environments where you have explicit permission. The author is not responsible for any damage caused by the use or misuse of this software. Always test in a lab environment first.

-----

## 📄 License

This project is licensed under the MIT License.

