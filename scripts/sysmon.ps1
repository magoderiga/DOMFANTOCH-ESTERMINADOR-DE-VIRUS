# sysmon.ps1 - estado, instalacao e leitura de eventos do Sysmon (Sysinternals).
# Uso: pwsh -NoProfile -ExecutionPolicy Bypass -File sysmon.ps1 -Acao Status
#      -Acao Eventos [-Horas 24]   (eventos 6,12,13,14,19,20,21: driver, registro, WMI)
#      -Acao Instalar               (BAIXA Sysmon.zip de download.sysinternals.com e instala com sysmon-config.xml;
#                                    so com OK do usuario para o download e a instalacao)
# Codigo de saida: 0 ok; 1 falhou.
[CmdletBinding()]
param(
    [ValidateSet('Status', 'Eventos', 'Instalar')][string]$Acao = 'Status',
    [int]$Horas = 24
)
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\comum.ps1"
$log = Start-LogSkill ('sysmon-' + $Acao)
$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("=== SYSMON: $Acao ===")
[void]$sb.AppendLine("Log: $log")
$codigo = 0
$config = [IO.Path]::Combine($SkillRaiz, 'sysmon-config.xml')

function Get-StatusSysmon {
    $s = @(Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue)
    if ($s.Count -eq 0) { return 'nao instalado (Get-Service Sysmon* vazio)' }
    return (@($s | ForEach-Object { '{0}={1}' -f $_.Name, $_.Status }) -join ', ')
}

try {
    switch ($Acao) {
        'Status' {
            [void]$sb.AppendLine('Servico: ' + (Get-StatusSysmon))
            $lg = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue
            if ($lg) { [void]$sb.AppendLine(('Log Operational: {0} eventos, ativo={1}' -f $lg.RecordCount, $lg.IsEnabled)) } else { [void]$sb.AppendLine('Log Microsoft-Windows-Sysmon/Operational nao existe') }
        }
        'Eventos' {
            foreach ($e in (Get-EventosSysmon -Horas $Horas -Maximo 500)) { [void]$sb.AppendLine($e) }
        }
        'Instalar' {
            if (-not (Test-Administrador)) { throw 'precisa de administrador' }
            if (-not (Test-Path -LiteralPath $config)) { throw "configuracao nao encontrada: $config" }
            $tmp = [IO.Path]::Combine($env:TEMP, ('sysmon-skill-' + (Get-Carimbo)))
            New-Item -ItemType Directory -Path $tmp -Force | Out-Null
            $zip = [IO.Path]::Combine($tmp, 'Sysmon.zip')
            Write-LogSkill "baixando https://download.sysinternals.com/files/Sysmon.zip -> $zip"
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $zip -UseBasicParsing -ErrorAction Stop
            Expand-Archive -LiteralPath $zip -DestinationPath $tmp -Force -ErrorAction Stop
            $bin = [IO.Path]::Combine($tmp, 'Sysmon64.exe')
            if (-not (Test-Path -LiteralPath $bin)) { $bin = [IO.Path]::Combine($tmp, 'Sysmon.exe') }
            $ass = Get-AuthenticodeSignature -LiteralPath $bin
            [void]$sb.AppendLine(('Assinatura de {0}: {1} | {2}' -f $bin, $ass.Status, $ass.SignerCertificate.Subject))
            if ($ass.Status -ne 'Valid' -or $ass.SignerCertificate.Subject -notmatch 'Microsoft Corporation') { throw 'assinatura do Sysmon nao e Microsoft valida: instalacao abortada' }
            $jaTem = @(Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue).Count -gt 0
            if ($jaTem) { $saida = (& $bin -accepteula -c $config 2>&1) -join ' ' } else { $saida = (& $bin -accepteula -i $config 2>&1) -join ' ' }
            $cod = $LASTEXITCODE
            Write-LogSkill "Sysmon codigo $cod : $saida"
            [void]$sb.AppendLine("Sysmon codigo de saida: $cod")
            [void]$sb.AppendLine("Saida: $saida")
            Start-Sleep -Seconds 3
            $st = Get-StatusSysmon
            [void]$sb.AppendLine('Servico depois: ' + $st)
            if ($cod -ne 0 -or $st -notmatch 'Running') { $codigo = 1 }
        }
    }
} catch {
    [void]$sb.AppendLine('ERRO: ' + $_.Exception.Message)
    $codigo = 1
}
Write-LogSkill "fim codigo $codigo"
Write-Output $sb.ToString()  # scroll-ok: resumo unico emitido no fim, lido pelo Claude (produto do programa)
exit $codigo
