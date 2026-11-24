# defender.ps1 - estado, varredura e endurecimento do Microsoft Defender.
# Uso: pwsh -NoProfile -ExecutionPolicy Bypass -File defender.ps1 -Acao Status
#      -Acao VarreduraRapida | VarreduraCompleta          (MpCmdRun; saida em logs\defender-*.txt)
#      -Acao VarrerArquivo -Alvo C:\caminho\arquivo.exe    (MpCmdRun -ScanType 3)
#      -Acao AplicarProtecao [-Modo Auditoria|Bloqueio]    (PUA + regras ASR; ALTERA configuracao: so com OK do usuario)
#      -Acao Religar                                       (tira as politicas Disable*=1 com backup .reg, atualiza a
#                                                           politica e tenta iniciar o WinDefend; ALTERA: so com OK do usuario)
# Sem Defender ativo, VarrerArquivo ainda devolve SHA256 e assinatura do arquivo (codigo 3).
# Codigo de saida: 0 ok; 1 acao falhou; 3 Defender indisponivel (servico parado / MpCmdRun ausente).
[CmdletBinding()]
param(
    [ValidateSet('Status', 'VarreduraRapida', 'VarreduraCompleta', 'VarrerArquivo', 'AplicarProtecao', 'Religar')][string]$Acao = 'Status',
    [string]$Alvo = '',
    [ValidateSet('Auditoria', 'Bloqueio')][string]$Modo = 'Auditoria'
)
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\comum.ps1"
$log = Start-LogSkill ('defender-' + $Acao)
$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("=== DEFENDER: $Acao ===")
[void]$sb.AppendLine("Log: $log")
$codigo = 0

function Get-MpCmdRun {
    $plat = [IO.Path]::Combine($env:ProgramData, 'Microsoft\Windows Defender\Platform')
    $dir = Get-ChildItem -LiteralPath $plat -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
    if ($dir) {
        $c = [IO.Path]::Combine($dir.FullName, 'MpCmdRun.exe')
        if (Test-Path -LiteralPath $c) { return $c }
    }
    $c = [IO.Path]::Combine($env:ProgramFiles, 'Windows Defender\MpCmdRun.exe')
    if (Test-Path -LiteralPath $c) { return $c }
    return ''
}

function Get-PoliticasDefender {
    $r = New-Object System.Collections.Generic.List[string]
    foreach ($ch in 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender',
                    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection') {
        foreach ($v in (Get-ValoresChave $ch)) { $r.Add(('{0} -> {1} = {2}' -f (ConvertTo-CaminhoReg $ch), $v.Nome, $v.Valor)) }
    }
    if ($r.Count -eq 0) { $r.Add('nenhuma politica de Defender definida em HKLM\SOFTWARE\Policies\Microsoft\Windows Defender') }
    return ,$r
}

# Regras ASR copiadas de configuring-windows-defender-advanced-settings (mukul975/Anthropic-Cybersecurity-Skills)
$asr = [ordered]@{
    'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550' = 'conteudo executavel vindo de e-mail/webmail'
    'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' = 'Office criando processos filhos'
    '3B576869-A4EC-4529-8536-B80A7769E899' = 'Office criando conteudo executavel'
    '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84' = 'Office injetando codigo em outros processos'
    'D3E037E1-3EB8-44C8-A917-57927947596D' = 'JavaScript/VBScript iniciando executavel baixado'
    '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC' = 'scripts possivelmente ofuscados'
    '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B' = 'chamadas Win32 a partir de macros do Office'
    '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2' = 'roubo de credenciais do LSASS'
    'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4' = 'processos nao assinados vindos de USB'
    'E6DB77E5-3DF2-4CF1-B95A-636979351E5B' = 'persistencia por assinatura de evento WMI'
}
# D1E49AAC (PSExec/WMI) ficou de fora de proposito: quebra automacoes que usam WMI.

try {
    switch ($Acao) {
        'Status' {
            $d = Get-EstadoDefesas
            [void]$sb.AppendLine(($d | ConvertTo-Json -Depth 4))
            [void]$sb.AppendLine('Politicas:')
            foreach ($p in (Get-PoliticasDefender)) { [void]$sb.AppendLine('  ' + $p) }
            [void]$sb.AppendLine('MpCmdRun: ' + (Get-MpCmdRun))
        }
        { $_ -in @('VarreduraRapida', 'VarreduraCompleta', 'VarrerArquivo') } {
            $mp = Get-MpCmdRun
            $svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
            if (-not $mp -or -not $svc -or $svc.Status -ne 'Running') {
                $estado = 'ausente'
                if ($svc) { $estado = [string]$svc.Status }
                [void]$sb.AppendLine("Defender indisponivel: WinDefend=$estado | MpCmdRun='$mp'. Varredura nao executada.")
                [void]$sb.AppendLine('Politicas:')
                foreach ($p in (Get-PoliticasDefender)) { [void]$sb.AppendLine('  ' + $p) }
                if ($Acao -eq 'VarrerArquivo' -and (Test-ArquivoExiste $Alvo)) {
                    $h = Get-FileHash -LiteralPath $Alvo -Algorithm SHA256 -ErrorAction SilentlyContinue
                    $ass = Get-InfoAssinatura $Alvo
                    [void]$sb.AppendLine(('Conferencia sem Defender: SHA256={0} | assinatura={1} {2} | tamanho={3} bytes' -f $h.Hash, $ass.Status, $ass.Assinante, (Get-Item -LiteralPath $Alvo -Force).Length))
                    [void]$sb.AppendLine('Proximo passo: defender.ps1 -Acao Religar (com OK do usuario) e repetir VarrerArquivo; o SHA256 pode ser consultado em servico de reputacao (NAO VERIFICADO aqui).')
                } else {
                    [void]$sb.AppendLine('Proximo passo: defender.ps1 -Acao Religar (com OK do usuario) e repetir a varredura.')
                }
                $codigo = 3
                break
            }
            $argumentos = @('-Scan', '-ScanType', '1')
            if ($Acao -eq 'VarreduraCompleta') { $argumentos = @('-Scan', '-ScanType', '2') }
            if ($Acao -eq 'VarrerArquivo') {
                if (-not (Test-Path -LiteralPath $Alvo)) { throw "alvo nao existe: $Alvo" }
                $argumentos = @('-Scan', '-ScanType', '3', '-File', ('"{0}"' -f $Alvo), '-DisableRemediation')
            }
            $pasta = Get-PastaSkill 'logs'
            $carimbo = Get-Carimbo
            $out = [IO.Path]::Combine($pasta, "defender-$carimbo.txt")
            $err = [IO.Path]::Combine($pasta, "defender-$carimbo.err.txt")
            Write-LogSkill ("MpCmdRun {0} -> {1}" -f ($argumentos -join ' '), $out)
            $p = Start-Process -FilePath $mp -ArgumentList $argumentos -NoNewWindow -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
            $p.WaitForExit()
            $texto = ''
            if (Test-Path -LiteralPath $out) { $texto = Get-Content -LiteralPath $out -Raw }
            [void]$sb.AppendLine("MpCmdRun codigo de saida: $($p.ExitCode) (0 = sem ameaca; 2 = ameaca encontrada/acao pendente; NAO VERIFICADO para outros codigos)")
            [void]$sb.AppendLine("Saida completa: $out")
            [void]$sb.AppendLine($texto)
            if ($p.ExitCode -ne 0) { $codigo = 1 }
        }
        'Religar' {
            if (-not (Test-Administrador)) { throw 'Religar precisa de PowerShell como administrador' }
            $carimbo = Get-Carimbo
            $pastaBk = [IO.Path]::Combine((Get-PastaSkill '_backups'), $carimbo)
            New-Item -ItemType Directory -Path $pastaBk -Force | Out-Null
            $tirados = 0
            foreach ($ch in 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender',
                            'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection') {
                $valores = @(Get-ValoresChave ('Registry::' + $ch) | Where-Object { $_.Nome -match '^Disable' -and $_.Valor -eq '1' })
                if ($valores.Count -eq 0) { continue }
                $arqReg = [IO.Path]::Combine($pastaBk, ('politica-defender-{0}.reg' -f ($ch -replace '[^A-Za-z0-9]', '_')))
                $null = & reg.exe export $ch $arqReg /y 2>$null
                if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $arqReg)) { throw "backup da politica falhou (reg export codigo $LASTEXITCODE): $ch" }
                foreach ($v in $valores) {
                    try {
                        Remove-ItemProperty -LiteralPath ('Registry::' + $ch) -Name $v.Nome -ErrorAction Stop
                        $tirados++
                        [void]$sb.AppendLine(('politica tirada: {0} -> {1} = 1 (backup {2})' -f $ch, $v.Nome, $arqReg))
                    } catch { [void]$sb.AppendLine(('politica NAO tirada: {0} -> {1}: {2}' -f $ch, $v.Nome, $_.Exception.Message)); $codigo = 1 }
                }
            }
            if ($tirados -eq 0) { [void]$sb.AppendLine('nenhuma politica Disable*=1 encontrada') }
            $gp = (& gpupdate.exe /target:computer /force 2>&1) -join ' '
            [void]$sb.AppendLine("gpupdate codigo $LASTEXITCODE")
            Write-LogSkill "gpupdate: $gp"
            try { Start-Service -Name WinDefend -ErrorAction Stop; [void]$sb.AppendLine('Start-Service WinDefend: pedido aceito') }
            catch { [void]$sb.AppendLine('Start-Service WinDefend falhou: ' + $_.Exception.Message) }
            $estado = ''
            for ($i = 0; $i -lt 15; $i++) {
                $svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
                if ($svc) { $estado = [string]$svc.Status } else { $estado = 'ausente' }
                if ($estado -eq 'Running') { break }
                Start-Sleep -Seconds 2
            }
            [void]$sb.AppendLine("WinDefend depois: $estado")
            if ($estado -eq 'Running') {
                try {
                    $st = Get-MpComputerStatus -ErrorAction Stop
                    [void]$sb.AppendLine(('Get-MpComputerStatus: AMServiceEnabled={0} | AntivirusEnabled={1} | RealTimeProtectionEnabled={2}' -f $st.AMServiceEnabled, $st.AntivirusEnabled, $st.RealTimeProtectionEnabled))
                } catch { [void]$sb.AppendLine('Get-MpComputerStatus falhou: ' + $_.Exception.Message) }
            } else {
                $codigo = 1
                [void]$sb.AppendLine('Defender continua parado. Causas provaveis (NAO VERIFICADO): outro antivirus registrado no SecurityCenter2, politica que so cai depois de reiniciar, ou servico desativado por ferramenta de terceiros. Proximo passo: reiniciar o PC (so com OK do usuario) e rodar defender.ps1 -Acao Status.')
            }
        }
        'AplicarProtecao' {
            $acaoAsr = 2
            if ($Modo -eq 'Bloqueio') { $acaoAsr = 1 }
            try { Set-MpPreference -PUAProtection Enabled -ErrorAction Stop; [void]$sb.AppendLine('PUAProtection = Enabled: OK') } catch { [void]$sb.AppendLine('PUAProtection falhou: ' + $_.Exception.Message); $codigo = 1 }
            try { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop; [void]$sb.AppendLine('Protecao em tempo real ligada: OK') } catch { [void]$sb.AppendLine('Tempo real falhou: ' + $_.Exception.Message); $codigo = 1 }
            foreach ($k in $asr.Keys) {
                try {
                    Add-MpPreference -AttackSurfaceReductionRules_Ids $k -AttackSurfaceReductionRules_Actions $acaoAsr -ErrorAction Stop
                    [void]$sb.AppendLine(('ASR {0} ({1}) = {2}: OK' -f $k, $asr[$k], $Modo))
                } catch { [void]$sb.AppendLine(('ASR {0} falhou: {1}' -f $k, $_.Exception.Message)); $codigo = 1 }
            }
            try {
                $pref = Get-MpPreference -ErrorAction Stop
                [void]$sb.AppendLine('Conferencia Get-MpPreference: PUAProtection=' + $pref.PUAProtection + ' | ASR ids=' + (@($pref.AttackSurfaceReductionRules_Ids) -join ',') + ' | acoes=' + (@($pref.AttackSurfaceReductionRules_Actions) -join ','))
            } catch { [void]$sb.AppendLine('Conferencia Get-MpPreference falhou: ' + $_.Exception.Message); $codigo = 1 }
        }
    }
} catch {
    [void]$sb.AppendLine('ERRO: ' + $_.Exception.Message)
    $codigo = 1
}
Write-LogSkill "fim codigo $codigo"
Write-Output $sb.ToString()  # scroll-ok: resumo unico emitido no fim, lido pelo Claude (produto do programa)
exit $codigo
