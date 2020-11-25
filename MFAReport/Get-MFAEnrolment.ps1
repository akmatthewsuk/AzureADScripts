Param (
    [Parameter(Mandatory=$True, HelpMessage="Specify an Azure AD Group Name")]
    [String]
    # Specifies the group used to enable the Combined Security Registration Experience in Azure AD
    $CombinedRegistrationGroup,
    [Parameter(Mandatory=$True, HelpMessage="Specify an Azure AD Group Name")]
    [String]
    # Specifies the prefix for the report file
    $ReportFilePrefix,
    [Parameter(Mandatory=$false, HelpMessage="Specify a path to save the report to")]
    [String]
    # specifies the path to save the report to
    $ReportPath
)
<#
   .NOTES
    ===========================================================================
    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
    EITHER EXPRESSED OR IMPLIED,  INCLUDING BUT NOT LIMITED TO THE IMPLIED
    WARRANTIES OF MERCHANTBILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
    ===========================================================================
    Created by:    Andrew Matthews
    Filename:      Get-MFAEnrolment.ps1
    Documentation: None
    Execution Tested on: Windows 10 with the MSOnline PowerShell module installed
    Requires:      MSOnline PowerShell module
    Versions:
    1.0 - Initial Release 25-Nov-2020
    ===========================================================================

    .SYNOPSIS
    Creates a report of which users have MFA strong authentication measures registered

    .DESCRIPTION
    Queries Azure AD using MS Online PowerShell and compiles a report in CSV format 

    .PARAMETER CombinedRegistrationGroup
    Specifies the group used to enable the Combined Security Registration Experience in Azure AD
    This parameter can also be used to target a group of user accounts without the group being the group that enables the ombined Security Registration Experience

    .PARAMETER ReportFilePrefix
    Specifies the prefix for the report file

    .PARAMETER ReportPath
    Optional - specifies the path to save the report to

    .EXAMPLE
    C:\PS>Get-MFAEnrolment.ps1 -CombinedRegistrationGroup GroupName -ReportFilePrefix MFAReport

    .EXAMPLE
    C:\PS>Get-MFAEnrolment.ps1 -CombinedRegistrationGroup GroupName -ReportFilePrefix MFAReport -ReportPath "C:\Report"

#>


#############################################################################
# Script Setup
#############################################################################

#check whether the MSOnline Module is installed
Write-Host " "
Write-Host "Checking the MSOnline Module is installed"
Try {
    $MsOnlineModuleInstalled = (get-module -name "MSOnline" -ListAvailable).count
} catch {
    $ErrorMessage = $_.Exception.Message
    Write-Host "Failed to check whether MSOnline Powershell module is installed" -ForegroundColor Red
    Write-Host $ErrorMessage -ForegroundColor Red
    Exit
}

If ($MsOnlineModuleInstalled -eq 0) {
    Write-Host "The MSOnline Module is not installed" -ForegroundColor Red
    Write-Host "Install the MSOnline module with Install-Module MSOnline then re-run the script"
    Exit
} else {
    Write-Host "The MSOnline Module is installed"
}

#Check whether there is an existing session to MSOnline PowerShell
Write-Host " "
Write-Host "Checking for an existing MSOnline Session"
Try {
    Get-MsolDomain -ErrorAction Stop > $null
} Catch {
    #If there is no session then attempt to connect
    Write-Host "Connecting to Azure AD using MSOnline Powershell"
    Try {
        Connect-MsolService
    } Catch {
        $ErrorMessage = $_.Exception.Message
        Write-Host "Failed to connect to Azure AD using MSOnline Powershell" -ForegroundColor Red
        Write-Host $ErrorMessage -ForegroundColor Red
        Exit 
    }

    #Retry the MSOnline Check
    Try {
        Get-MsolDomain -ErrorAction Stop > $null
    } Catch {
        Write-Host "MSOnline PowerShell not available" -ForegroundColor Red
        Exit
    }
    
}

Write-Host " "


#############################################################################
# Query MS Online
#############################################################################

#Create the User Output Array
$MFAUsers = New-Object System.Collections.ArrayList

#Query Azure AD for the specified group
Write-Host "Querying Azure AD for the specified group ($($CombinedRegistrationGroup))"
Try {
    $GroupObject = Get-MsolGroup -SearchString $CombinedRegistrationGroup | where-object {$_.Displayname -eq $CombinedRegistrationGroup}
} Catch {
    $ErrorMessage = $_.Exception.Message
    Write-Host "Failed to Query Azure AD for the specified group" -ForegroundColor Red
    Write-Host $ErrorMessage -ForegroundColor Red
    Exit 
}
if ($null -eq $GroupObject) {
    Write-Host "Group $($CombinedRegistrationGroup) not found" -ForegroundColor Red
    Exit 
}

#Query the membership of the Group
Write-Host "Querying Group Membership for $($GroupObject.DisplayName)"
Try {
    $GroupMembers = Get-MsolGroupMember -GroupObjectId $GroupObject.ObjectID | where-object {$_.GroupMemberType -eq "User"}
} catch {
    $ErrorMessage = $_.Exception.Message
    Write-Host "Failed to query group members of the Specified Group ($($GroupObject.DisplayName))" -ForegroundColor Red
    Write-Host $ErrorMessage -ForegroundColor Red
    Exit 
}

#Check that some group members where returned
if($Null -eq $GroupMembers) {
    Write-Host "Group Membership query returned a null result for Specified Group ($($GroupObject.DisplayName))" -ForegroundColor Red
    Exit 
} else {

    If ($GroupMembers.Count -eq 0) {
        Write-Host "Group Membership is empty for Specified Group ($($GroupObject.DisplayName))" -ForegroundColor Red
        Exit 
    } Else {
        Write-Host "Query returned $($GroupMembers.Count) user accounts"
    }
}

##############################################################################
# Query Strong Authentication Methods
##############################################################################

#Parse the group members and query the Strong auth Methods
Write-Host " "
foreach ($GroupMember in $GroupMembers) {
    Write-Host "Querying Strong authentication methods for $($GroupMember.emailAddress)"
    #Query Azure AD for the user account
    $User = Get-MsolUser -ObjectId $GroupMember.ObjectID

    #Reset the StrongAuthmethodFlags
    $Strong_PhoneAppOTP = "No"
    $Strong_PhoneAppNotification = "No"
    $Strong_OneWaySMS = "No"
    $Strong_TwoWayVoiceMobile = "No"
    $Strong_Default = "None"


    #Check the Strong auth Methods
    If ($User.StrongAuthenticationMethods.Count -eq 0) {
        $MFAEnabled = "No"
    } Else {
        $MFAEnabled = "Yes"
        #Query the Methods
        foreach ($StrongAuthenticationMethod in $User.StrongAuthenticationMethods) {
            Switch ($StrongAuthenticationMethod.MethodType) {
                "OneWaySMS" {
                    $Strong_OneWaySMS = "Yes"
                    If ($StrongAuthenticationMethod.IsDefault -eq $True) {
                        $Strong_Default = "Text Message"
                    }
                }
                "TwoWayVoiceMobile" {
                    $Strong_TwoWayVoiceMobile = "Yes"
                    If ($StrongAuthenticationMethod.IsDefault -eq $True) {
                        $Strong_Default = "Voice Call"
                    }
                }
                "PhoneAppOTP" {
                    $Strong_PhoneAppOTP = "Yes"
                    If ($StrongAuthenticationMethod.IsDefault -eq $True) {
                        $Strong_Default = "Authenticator App Code"
                    }
                }
                "PhoneAppNotification" {
                    $Strong_PhoneAppNotification = "Yes"
                    If ($StrongAuthenticationMethod.IsDefault -eq $True) {
                        $Strong_Default = "Authenticator App Notification"
                    }
                }
                default {
                    Write-Host "Strong authentication method type $($StrongAuthenticationMethod.MethodType) unknown"
                }
            } 
        }
    }


    $UserResult = New-Object -TypeName PSObject -Property @{
        'UserPrincipalName' = $User.UserPrincipalName
        'Name' = $User.DisplayName
        'MFAEnabled' = $MFAEnabled
        'Default Method' = $Strong_Default
        'Authenticator App Notification' = $Strong_PhoneAppNotification
        'Authenticator App Code' = $Strong_PhoneAppOTP
        'Voice Call' = $Strong_TwoWayVoiceMobile
        'Text Message' = $Strong_OneWaySMS
    }
    $MFAUsers.Add($UserResult) | Out-Null
}




##############################################################################
# Export the data to CSV
##############################################################################

write-host ""
Write-Host "Exporting the MFA Details for $($MFAUsers.count) Users" -ForegroundColor Yellow
#Create the file name from the prefix
$FileName = $ReportFilePrefix + "-" + (get-date -Format "yyyy-MM-dd-HHmm") + ".csv"

If(($null -eq $ReportPath)-or($ReportPath.length -eq 0)) {
    #Use the current path
    $ReportFile = ".\$($FileName)"
} Else {
    #Use the supplied path
    $ReportFile = join-path -path $ReportPath -childpath $FileName

    #check the path exists
    if (!(Test-Path -Path $ReportPath)) {
        New-Item -path $ReportPath -ItemType "directory" -force
    }
}
Write-Host "Report File: $ReportFile"
#Export to CSV
$MFAUsers | Select-Object 'UserPrincipalName', 'Name', 'MFAEnabled', 'Default Method', 'Authenticator App Notification', 'Authenticator App Code', 'Voice Call', 'Text Message' | Sort-Object 'UserPrincipalName' | Export-Csv -Path $ReportFile -NoTypeInformation

