# Define variables for trusted users and email notification
$trustedUsers = "User1", "User2", "User3"   # Replace with your trusted user names
$sendFrom = "yourEmailAddress@example.com" # Replace with your email address
$sendTo = "recipientEmailAddress@example.com" # Replace with recipient email address
$smtpServer = "smtp.example.com" # Replace with your SMTP server address

# Monitor for security event ID 4624 (Successful logon) in the Windows event log
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4624} -ComputerName "." -ErrorAction SilentlyContinue |
ForEach-Object {
    # Extract relevant event data
    $event = $_.ToXml()
    $xml = [xml]$event
    $subjectUserName = $xml.Event.EventData.SubjectUserName
    $logonType = [int]$xml.Event.EventData.LogonType

    # Check if the subject user is trusted or not
    if ($trustedUsers -notcontains $subjectUserName) {
        # Check if logon type is interactive (i.e., not a service or network logon)
        if ($logonType -eq 2) {
            # Send email notification
            $subject = "Alert: Non-Trusted User Logged In - $subjectUserName"
            $body = "A non-trusted user ($subjectUserName) has logged in to this computer. Please investigate."
            Send-MailMessage -From $sendFrom -To $sendTo -Subject $subject -Body $body -SmtpServer $smtpServer
        }
    }
}
