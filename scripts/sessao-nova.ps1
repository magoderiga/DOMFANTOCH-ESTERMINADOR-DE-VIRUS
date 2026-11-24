# sessao-nova.ps1 - abre uma sessao NOVA do agente (claude -p) FORA do app desktop, para a prova de que nada volta.
# Por que: processo lancado de dentro do app Claude desktop (empacotado) le e grava uma visao VIRTUAL de HKCU; um hook
# que recria um valor Run grava nessa visao, e a prova "nao voltou" fica cega. Win32_Process.Create (servico WMI) cria o
# processo fora dessa visao, como o mesmo usuario, e os hooks da sessao nova gravam no registro real.
# Uso: pwsh -NoProfile -ExecutionPolicy Bypass -File sessao-nova.ps1 [-Prompt 'responda apenas ok'] [-PrazoSeg 300] [-Pasta DIR]
# Saida: resumo unico; log e saida do claude em logs\. Codigo: 0 = sessao terminou com codigo 0; 1 = claude terminou com
# outro codigo; 2 = prazo estourado (processo encerrado); 3 = falha ao lancar; 4 = CLI claude nao encontrado.
[CmdletBinding()]
param(
    [string]$Prompt = 'responda apenas ok',
    [int]$PrazoSeg = 300,
    [string]$Pasta = ''
)
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\comum.ps1"
$log = Start-LogSkill 'sessao-nova'
if (-not $Pasta) { $Pasta = (Get-Location).Path }
$pastaLogs = Get-PastaSkill 'logs'
$carimbo = Get-Carimbo
$arqSaida = [IO.Path]::Combine($pastaLogs, "sessao-nova-$carimbo.saida.txt")
$arqFim = [IO.Path]::Combine($pastaLogs, "sessao-nova-$carimbo.fim.txt")
$q = { param($t) "'" + ([string]$t).Replace("'", "''") + "'" }
$interno = @(
    '$ErrorActionPreference = ''Continue'''
    '$env:Path = [Environment]::GetEnvironmentVariable(''Path'', ''Machine'') + '';'' + [Environment]::GetEnvironmentVariable(''Path'', ''User'')'
    '$c = 9'
    '$exe = Get-Command -Name claude.cmd, claude.exe, claude -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1'
    ('try { if (-not $exe) { throw ''claude nao encontrado no PATH'' }; & $exe.Source -p ' + (& $q $Prompt) + ' *> ' + (& $q $arqSaida) + '; $c = $LASTEXITCODE } catch { Set-Content -LiteralPath ' + (& $q $arqSaida) + ' -Value $_.Exception.Message; $c = 9 }')
    ('Set-Content -LiteralPath ' + (& $q $arqFim) + ' -Value (''FIM codigo '' + $c)')
) -join "`n"
$b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($interno))
$ps = [IO.Path]::Combine($env:SystemRoot, 'System32\WindowsPowerShell\v1.0\powershell.exe')
$linha = '"' + $ps + '" -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand ' + $b64
$codigo = 0
$detalhe = ''
$pidS = 0
# o CLI tem de existir no PATH de maquina + usuario (o mesmo que o processo lancado fora do app vai usar)
$pathTodo = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
$achouCli = $false
foreach ($dirP in ($pathTodo -split ';')) {
    if (-not $dirP) { continue }
    foreach ($n in 'claude.cmd', 'claude.exe', 'claude.ps1', 'claude') {
        try { if (Test-Path -LiteralPath ([IO.Path]::Combine([Environment]::ExpandEnvironmentVariables($dirP), $n)) -PathType Leaf) { $achouCli = $true } } catch { }
    }
}
if (-not $achouCli) {
    $codigo = 4
    $detalhe = 'CLI claude nao encontrado no PATH de maquina nem de usuario: instale o Claude Code CLI ou abra a sessao nova pelo app e rode varrer.ps1 depois'
} else {
try {
    $r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $linha; CurrentDirectory = $Pasta } -ErrorAction Stop
    if ([int]$r.ReturnValue -ne 0) { throw ('Win32_Process.Create codigo {0}' -f $r.ReturnValue) }
    $pidS = [int]$r.ProcessId
    Write-LogSkill "lancado fora do app: PID $pidS, pasta $Pasta, prazo $PrazoSeg s"
    $inicio = Get-Date
    while (-not (Test-Path -LiteralPath $arqFim) -and ((Get-Date) - $inicio).TotalSeconds -lt $PrazoSeg) { Start-Sleep -Seconds 2 }
    if (Test-Path -LiteralPath $arqFim) {
        $fim = (Get-Content -LiteralPath $arqFim -Raw).Trim()
        $detalhe = $fim
        if ($fim -ne 'FIM codigo 0') { $codigo = 1 }
        if ($fim -eq 'FIM codigo 9') { $codigo = 4 }
    } else {
        $codigo = 2
        $detalhe = "prazo de $PrazoSeg s estourado; arvore do PID $pidS encerrada"
        $null = & taskkill.exe /PID $pidS /T /F 2>&1
    }
} catch {
    $codigo = 3
    $detalhe = 'falha ao lancar fora do app: ' + $_.Exception.Message
}
}
$saida = ''
if (Test-Path -LiteralPath $arqSaida) { $saida = (Get-Content -LiteralPath $arqSaida -Raw) }
Write-LogSkill ("fim codigo {0}: {1}" -f $codigo, $detalhe)
$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('=== SESSAO NOVA DO AGENTE (fora do app, Win32_Process.Create) ===')
[void]$sb.AppendLine("Log: $log")
[void]$sb.AppendLine("PID: $pidS | pasta: $Pasta | resultado: $detalhe")
[void]$sb.AppendLine("Saida do claude ($arqSaida):")
[void]$sb.AppendLine($saida)
Write-Output $sb.ToString()  # scroll-ok: resumo unico emitido no fim, lido pelo Claude (produto do programa)
exit $codigo
