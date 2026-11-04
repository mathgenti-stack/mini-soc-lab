@{
    # Mini SOC Lab helpers for PowerShell on Linux. Loaded automatically the first time Get-WinEvent is used.
    RootModule        = 'SocLab.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '6d0f8a52-3c4e-4b8e-9a51-2f7b8c1d4e60'
    Author            = 'Mini SOC Lab'
    Description       = 'Lab version of Get-WinEvent: reads .evtx files on Linux with the lab''s EVTX reader.'
    PowerShellVersion = '7.4'
    FunctionsToExport = @('Get-WinEvent')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
