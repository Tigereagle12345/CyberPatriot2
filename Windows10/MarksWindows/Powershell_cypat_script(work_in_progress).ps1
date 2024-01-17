# Function to update all applications installed via winget
Function Update-WinGetPackages {
    $packages = winget list
    foreach ($package in $packages) {
        $packageName = $package.Split(" ")[0]
        Write-Host "Updating $packageName"
        winget upgrade $packageName
    }
}

# Function to update the Windows OS
Function Update-WindowsOS {
    Write-Host "Checking for Windows Updates..."
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    $searchResult = $updateSearcher.Search("IsInstalled=0")
    
    if ($searchResult.Updates.Count -eq 0) {
        Write-Host "No updates available."
    } else {
        Write-Host "Installing Windows Updates..."
        $updateInstaller = New-Object -ComObject Microsoft.Update.UpdateColl
        $updateInstaller.AddRange($searchResult.Updates)
        $installResult = $updateSession.CreateUpdateInstaller()
        $installResult.Updates = $updateInstaller
        $installResult.Install()
        Write-Host "Windows Updates installed. Please restart your computer to complete the update."
    }
}

# Update applications installed via winget
Update-WinGetPackages

# Update the Windows OS
Update-WindowsOS

# Define the new password
$newPassword = "JewsAreIntersting1245??!!#4"

# Get a list of all local users
$localUsers = Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Local -eq $true }

# Initialize log variables
$successLog = @()
$failureLog = @()

# Define the desired password policy values
$passwordExpiresInDays = 30
$passwordLength = 10
$maxPasswordAge = 365  # 1 year in days

# Check existing password policies
$existingPasswordExpiresInDays = (secedit /export /areas SECURITYPOLICY /cfg NUL | Select-String "PasswordAge").ToString() -replace '\D+'
$existingPasswordLength = (secedit /export /areas SECURITYPOLICY /cfg NUL | Select-String "MinimumPasswordLength").ToString() -replace '\D+'
$existingMaxPasswordAge = (secedit /export /areas SECURITYPOLICY /cfg NUL | Select-String "MaximumPasswordAge").ToString() -replace '\D+'

if ($existingPasswordExpiresInDays -eq $passwordExpiresInDays -and
    $existingPasswordLength -eq $passwordLength -and
    $existingMaxPasswordAge -eq $maxPasswordAge) {
    Write-Host "Password policies are already set to your desired values."
} else {
    # Configure password policy using Windows Run
    Write-Host "Configuring password policies..."

    # Set password expires in days
    $passwordAgeCommand = "secedit /configure /db reset /cfg %windir%\inf\defltbase.inf /areas SECURITYPOLICY /option PasswordAge=$passwordExpiresInDays"
    Start-Process -NoNewWindow -FilePath "cmd.exe" -ArgumentList "/C $passwordAgeCommand"
    Start-Sleep -Seconds 5  # Wait for the command to finish

    # Set minimum password length
    $passwordLengthCommand = "secedit /configure /db reset /cfg %windir%\inf\defltbase.inf /areas SECURITYPOLICY /option MinimumPasswordLength=$passwordLength"
    Start-Process -NoNewWindow -FilePath "cmd.exe" -ArgumentList "/C $passwordLengthCommand"
    Start-Sleep -Seconds 5  # Wait for the command to finish

    # Set maximum password age
    $maxPasswordAgeCommand = "secedit /configure /db reset /cfg %windir%\inf\defltbase.inf /areas SECURITYPOLICY /option MaximumPasswordAge=$maxPasswordAge"
    Start-Process -NoNewWindow -FilePath "cmd.exe" -ArgumentList "/C $maxPasswordAgeCommand"
    Start-Sleep -Seconds 5  # Wait for the command to finish

    Write-Host "Password policies have been updated to your preference."
}

Write-Host "Password Expires In: $passwordExpiresInDays days"
Write-Host "Minimum Password Length: $passwordLength characters"
Write-Host "Maximum Password Age: 1 year"

Write-Host "Please consider enforcing these settings for user accounts."

# Prompt for the username of the user to be removed
$userToRemove = Read-Host -Prompt "Enter the username of the user to be removed"

# Check if the user account exists
$userExists = Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Name -eq $userToRemove }

if ($userExists) {
    # Remove the user account
    net user $userToRemove /delete
    Write-Host "User $userToRemove has been removed from the computer."
} else {
    Write-Host "User $userToRemove not found on the computer."
}



# Loop through each local user and attempt to change the password
foreach ($user in $localUsers) {
    $userName = $user.Name
    Write-Host "Changing password for user: $userName"
    $result = net user $userName $newPassword
    if ($result -like "*successfully*") {
        $successLog += "Password for user $userName changed successfully."
    } else {
        $failureLog += "Failed to change password for user $userName. Result: $result"
    }
}

# Print the results
Write-Host "All local user passwords have been changed to: $newPassword"
Write-Host "Password change summary:"
$successLog | ForEach-Object { Write-Host $_ }
$failureLog | ForEach-Object { Write-Host $_ }

