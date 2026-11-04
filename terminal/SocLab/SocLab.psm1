# Mini SOC Lab: a lab version of Get-WinEvent for PowerShell on Linux.
#
# The real Get-WinEvent exists only in PowerShell on Windows, and this terminal is Linux. This version
# reads the .evtx files in ~/logs with the dashboard's own EVTX reader (soc_lab/evtx.py, through python3)
# and returns objects shaped like the real EventLogRecord, so the commands you practise here are the
# ones you would type on a Windows analyst workstation:
#
#   Get-WinEvent -Path ~/logs/windows_security.evtx
#   Get-WinEvent -FilterHashtable @{ Path = "$HOME/logs/windows_security.evtx"; Id = 4625 }
#   Get-WinEvent -FilterHashtable @{ Path = "$HOME/logs/windows_security.evtx"; TargetUserName = 'j.smith' }
#
# Supported: -Path, -FilterHashtable (Path, Id, StartTime, EndTime, ProviderName, Level, Keywords, Data and
# event data names such as TargetUserName), -MaxEvents and -Oldest. Events come newest first, as in Windows.
# Not supported: live logs (-LogName, -ListLog), -FilterXPath, -FilterXml and remote computers.
# Message is a one-line description followed by the event data, not the full Windows text.

$script:Dumper = '/opt/soc-lab/evtx_dump.py'

$script:LiveLogs = "This lab's Get-WinEvent reads .evtx files only, for example: " +
    "Get-WinEvent -Path ~/logs/windows_security.evtx. Live logs such as 'Security' exist only on Windows."

$script:Descriptions = @{
    4624 = 'An account was successfully logged on.'
    4625 = 'An account failed to log on.'
    4634 = 'An account was logged off.'
    4647 = 'User initiated logoff.'
    4648 = 'A logon was attempted using explicit credentials.'
    4672 = 'Special privileges assigned to new logon.'
    4720 = 'A user account was created.'
    4722 = 'A user account was enabled.'
    4723 = "An attempt was made to change an account's password."
    4724 = "An attempt was made to reset an account's password."
    4725 = 'A user account was disabled.'
    4726 = 'A user account was deleted.'
    4728 = 'A member was added to a security-enabled global group.'
    4732 = 'A member was added to a security-enabled local group.'
    4740 = 'A user account was locked out.'
    4767 = 'A user account was unlocked.'
    4768 = 'A Kerberos authentication ticket (TGT) was requested.'
    4771 = 'Kerberos pre-authentication failed.'
    4776 = 'The computer attempted to validate the credentials for an account.'
}

$script:LevelNames = @{ 0 = 'Information'; 1 = 'Critical'; 2 = 'Error'; 3 = 'Warning'; 4 = 'Information'; 5 = 'Verbose' }

# Keys of -FilterHashtable with a fixed meaning; any other key is the name of an event data field.
$script:KnownKeys = 'Path', 'LogName', 'Id', 'ProviderName', 'Level', 'Keywords', 'StartTime', 'EndTime', 'Data'

Update-TypeData -TypeName 'SocLab.EventLogRecord' -DefaultDisplayPropertySet TimeCreated, Id, LevelDisplayName, Message -Force

function Get-NodeText($Value) {
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Xml.XmlNode]) { return $Value.InnerText }
    return [string]$Value
}

function ConvertTo-LabRecord([System.Xml.XmlElement] $Node) {
    $system = $Node.System
    $id = [int](Get-NodeText $system.EventID)
    $level = [int](Get-NodeText $system.Level)
    $keywordsText = Get-NodeText $system.Keywords
    $keywords = if ($keywordsText -match '^0x([0-9a-fA-F]+)$') {
        [BitConverter]::ToInt64([BitConverter]::GetBytes([Convert]::ToUInt64($Matches[1], 16)), 0)
    } else { [long]0 }

    $data = @()
    if ($Node.EventData) {
        $data = @($Node.EventData.ChildNodes | Where-Object LocalName -eq 'Data')
    }
    $description = $script:Descriptions[$id]
    if (-not $description) { $description = "Event $id." }
    $lines = foreach ($item in $data) { "  $($item.GetAttribute('Name')):`t$($item.InnerText)" }
    $message = (@($description, '') + $lines) -join "`n"

    $record = [pscustomobject]@{
        PSTypeName       = 'SocLab.EventLogRecord'
        Id               = $id
        Version          = [int](Get-NodeText $system.Version)
        Level            = $level
        LevelDisplayName = $script:LevelNames[$level]
        Task             = [int](Get-NodeText $system.Task)
        Keywords         = $keywords
        RecordId         = [long](Get-NodeText $system.EventRecordID)
        ProviderName     = $system.Provider.Name
        LogName          = Get-NodeText $system.Channel
        MachineName      = Get-NodeText $system.Computer
        TimeCreated      = [DateTimeOffset]::Parse($system.TimeCreated.SystemTime,
                                                   [Globalization.CultureInfo]::InvariantCulture).LocalDateTime
        Message          = $message
        Properties       = @(foreach ($item in $data) { [pscustomobject]@{ Value = $item.InnerText } })
    }
    $xml = $Node.OuterXml
    $record | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $xml }.GetNewClosure()
    $record
}

function Get-EventDataValue($Record, [string] $Name) {
    $parsed = ([xml]$Record.ToXml()).Event
    if ($parsed.EventData) {
        foreach ($item in $parsed.EventData.ChildNodes) {
            if ($item.LocalName -eq 'Data' -and $item.GetAttribute('Name') -eq $Name) { $item.InnerText }
        }
    }
}

function Read-LabEvtx([string] $File) {
    if ([IO.Path]::GetExtension($File) -ne '.evtx') {
        throw "Get-WinEvent reads .evtx event log files, and '$File' is not one. " +
              "For an exported XML file use: [xml](Get-Content '$File' -Raw)"
    }
    $output = & python3 -I $script:Dumper $File
    if ($LASTEXITCODE -ne 0) { throw "Get-WinEvent could not read '$File'." }
    $document = [xml]($output -join "`n")
    $records = @(foreach ($node in $document.DocumentElement.ChildNodes) {
        if ($node.LocalName -eq 'Event') { ConvertTo-LabRecord $node }
    })
    [array]::Reverse($records)  # newest first, as Get-WinEvent returns them on Windows
    , $records
}

function Test-LabFilter($Record, [hashtable] $Filter) {
    foreach ($key in $Filter.Keys) {
        $wanted = @($Filter[$key])
        $ok = switch ($key) {
            'Path'         { $true }
            'LogName'      { $Record.LogName -in $wanted }
            'Id'           { $Record.Id -in $wanted }
            'ProviderName' { $Record.ProviderName -in $wanted }
            'Level'        { $Record.Level -in $wanted }
            'Keywords'     { ($Record.Keywords -band [long]$wanted[0]) -ne 0 }
            'StartTime'    { $Record.TimeCreated -ge [datetime]$wanted[0] }
            'EndTime'      { $Record.TimeCreated -le [datetime]$wanted[0] }
            'Data'         { @($Record.Properties.Value | Where-Object { $_ -in $wanted }).Count -gt 0 }
            default {
                @(Get-EventDataValue $Record $key | Where-Object { $_ -in $wanted }).Count -gt 0
            }
        }
        if (-not $ok) { return $false }
    }
    $true
}

function Get-WinEvent {
    <#
    .SYNOPSIS
    Lab version of Get-WinEvent: reads events from .evtx files (newest first).
    .EXAMPLE
    Get-WinEvent -Path ~/logs/windows_security.evtx -MaxEvents 5
    .EXAMPLE
    Get-WinEvent -FilterHashtable @{ Path = "$HOME/logs/windows_security.evtx"; Id = 4625 }
    #>
    [CmdletBinding(DefaultParameterSetName = 'File')]
    param(
        [Parameter(ParameterSetName = 'File', Mandatory, Position = 0)]
        [string[]] $Path,

        [Parameter(ParameterSetName = 'HashQuery', Mandatory)]
        [hashtable[]] $FilterHashtable,

        [Parameter(ParameterSetName = 'LogName')]
        [string[]] $LogName,

        [Parameter(ParameterSetName = 'ListLog')]
        [string[]] $ListLog,

        [long] $MaxEvents = -1,

        [switch] $Oldest
    )

    if ($PSCmdlet.ParameterSetName -in 'LogName', 'ListLog') { throw $script:LiveLogs }
    $queries = if ($PSCmdlet.ParameterSetName -eq 'File') { , @{ Path = $Path } } else { $FilterHashtable }

    $cache = @{}
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $found = [System.Collections.Generic.List[object]]::new()
    foreach ($query in $queries) {
        $paths = $null
        foreach ($key in $query.Keys) { if ($key -eq 'Path') { $paths = $query[$key] } }
        if (-not $paths) { throw $script:LiveLogs }
        foreach ($pattern in @($paths)) {
            foreach ($resolved in Resolve-Path -Path $pattern -ErrorAction Stop) {
                $file = $resolved.ProviderPath
                if (-not $cache.ContainsKey($file)) { $cache[$file] = Read-LabEvtx $file }
                $records = $cache[$file]
                if ($Oldest -and $records.Count -gt 1) { $records = $records[($records.Count - 1)..0] }
                foreach ($record in $records) {
                    if ((Test-LabFilter $record $query) -and $seen.Add("$file|$($record.RecordId)")) {
                        $found.Add($record)
                    }
                }
            }
        }
    }

    if ($found.Count -eq 0) {
        $exception = [System.Exception]::new('No events were found that match the specified selection criteria.')
        $PSCmdlet.WriteError([System.Management.Automation.ErrorRecord]::new(
            $exception, 'NoMatchingEventsFound', 'ObjectNotFound', $null))
        return
    }
    if ($MaxEvents -gt 0 -and $found.Count -gt $MaxEvents) { $found = $found.GetRange(0, $MaxEvents) }
    $found
}

Export-ModuleMember -Function Get-WinEvent
