# PowerShell profile of the analyst (Terminal tab, phase 2): prompt and a short welcome in both languages.
function prompt {
    $where = $PWD.Path
    if ($where.StartsWith($HOME)) { $where = '~' + $where.Substring($HOME.Length) }
    "$($PSStyle.Foreground.BrightCyan)PS analyst@soc-lab$($PSStyle.Reset):$($PSStyle.Foreground.BrightBlue)$where$($PSStyle.Reset)> "
}

if (-not $env:SOC_LAB_PS_WELCOMED) {
    $env:SOC_LAB_PS_WELCOMED = '1'
    Write-Host @'
Mini SOC Lab - PowerShell 7
  EN  Your logs are in ~/logs (read-only). Try:  Get-ChildItem logs
      then  Import-Csv logs/sample_auth_logs.csv | Select-Object -First 3
      Get-WinEvent here is a lab version that reads .evtx files (live logs exist only on Windows).
      Each challenge is in the Terminal tab of the dashboard. Type 'exit' to restart the shell.
  PT  Seus logs estão em ~/logs (somente leitura). Tente:  Get-ChildItem logs
      e depois  Import-Csv logs/sample_auth_logs.csv | Select-Object -First 3
      O Get-WinEvent daqui é uma versão do lab que lê arquivos .evtx (logs ao vivo só existem no Windows).
      Os desafios estão na aba Terminal do dashboard. Digite 'exit' para reiniciar o shell.

'@
}
