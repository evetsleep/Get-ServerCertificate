function Get-ServerCertificate {
    [CmdletBinding()]Param(
        [Parameter(Position=0,Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [String[]]
        $ComputerName,

        [Parameter(Position=1,Mandatory,ValueFromPipelineByPropertyName)]
        [Int]
        $Port
    )

    process {
        foreach ($computer in $ComputerName) {
            try {
                $client = New-Object -TypeName System.Net.Sockets.TcpClient -ArgumentList $computer,$Port
                Write-Verbose ('Connected to {0}:{1}' -f $computer,$Port)
            }
            catch {
                Write-Error -ErrorAction STOP -Message ('Failed to connect to {0}:{1}: {2}' -f $computer,$Port,$psitem.exception.message)
            }

            try {
                $stream = $client.GetStream()
            }
            catch {
                Write-Error -ErrorAction STOP -Message ('Failed to get stream from {0}:{1}: {2}' -f $computer,$Port,$psitem.exception.message)
            }
            
            try {
                $certificateStream = New-Object -TypeName System.Net.Security.SslStream($stream,$false)
                $certificateStream.AuthenticateAsClient($computer)
                $certificateObject = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $certificateStream.RemoteCertificate
                $certificateObject | Add-Member -Name ComputerName -Value $computer -MemberType NoteProperty -Force
            }
            catch {
                Write-Error -ErrorAction STOP -Message ('Failed to build certificate object from {0}:{1}: {2}' -f $computer,$Port,$psitem.exception.message)
            }


            Write-Output $certificateObject
        }
    }
}
<#
.SYNOPSIS
Connect to one (or more) servers and retrieve their certificate information.

.DESCRIPTION
Establish a TCP connection to a port that is offering encryption, such as 443 (HTTPS) or 636 (encrypted LDAP) and examine the certificate that is passed to the client from the server.

.PARAMETER ComputerName
The fully qualified host name of one (or more) servers to examine.

.PARAMETER Port
The port to connect on.

.EXAMPLE
Get-ServerCertificate -ComputerName www.microsoft.com -Port 443
Thumbprint                                Subject
----------                                -------
DC2A469C503FA0CF6CD4539CBACCB0B504D6889D  CN=www.microsoft.com, OU=MSCOM, O=Microsoft Corporation, L=Redmond, S=Wash...

Here we simply connect to www.microsoft.com on port 443 and get back a certificate object that we can examine.

.EXAMPLE
'www.google.com','www.yahoo.com' | Get-ServerCertificate -Port 443
Thumbprint                                Subject
----------                                -------
7C72AAAE0743C28E9C73B90BA813E39656258B2D  CN=www.google.com, O=Google Inc, L=Mountain View, S=California, C=US
DC0866CDF51594FD85CCF249D507164552828AD2  CN=*.www.yahoo.com, O=Yahoo! Inc., L=Sunnyvale, S=CA, C=US

Since the -ComputerName parameter accepts pipeline input we can pass in just the host names and get results back.

.EXAMPLE
$list = import-csv C:\temp\serverList.csv

ComputerName   Port
------------   ----
www.cnn.com    443
www.google.com 443
www.yahoo.com  443
www.reddit.com 443

PS C:\> $list | Get-ServerCertificate
Thumbprint                                Subject
----------                                -------
4F734EBD04AC8BB4363F4C733FE56E49346282F3  CN=turner-tls.map.fastly.net, O="Fastly, Inc.", L=San Francisco, S=Califor...
7C72AAAE0743C28E9C73B90BA813E39656258B2D  CN=www.google.com, O=Google Inc, L=Mountain View, S=California, C=US
DC0866CDF51594FD85CCF249D507164552828AD2  CN=*.www.yahoo.com, O=Yahoo! Inc., L=Sunnyvale, S=CA, C=US
F8D1965323111E86E6874AA93CC7C52969FB22BF  CN=*.reddit.com, O=Reddit Inc., L=San Francisco, S=California, C=US

Created a CSV file with both the ComputerName and Port defined and then we pass in values to the Get-ServerCertificate function to get all of the certificates from the listed hosts.

.EXAMPLE
$list = import-csv C:\temp\serverList.csv
PS C:\> $list | Get-ServerCertificate | Select-Object ComputerName,NotAfter 
ComputerName   NotAfter
------------   --------
www.cnn.com    5/5/2018 2:59:28 PM
www.google.com 12/28/2017 7:00:00 PM
www.yahoo.com  3/19/2018 8:00:00 AM
www.reddit.com 8/21/2018 8:00:00 AM

Making use of an import file we generate a report of when the certificates are going to expire for the hosts that we're interested in.

.LINK
https://github.com/evetsleep/Get-ServerCertificate

#>