# remover.ps1 - remove itens escolhidos pelo Id do relatorio da varredura, com backup e verificacao.
# Uso: pwsh -NoProfile -ExecutionPolicy Bypass -File remover.ps1 -Id HKA-0003,REG-0003,TAR-0012 [-Relatorio arq.json]
#        [-ApagarArquivo] [-Forcar] [-RemoverPastaSkill] [-SoLinhas HKA-0005]
#   -Id                um ou mais Ids (separados por virgula) do relatorio (logs\ultima-varredura.json por padrao)
#   -SoLinhas          Ids de origem (tambem listados em -Id) cujo script e LEGITIMO do usuario mas foi trojanizado: o hook
#                      fica registrado e o script fica no lugar; so as linhas que criam persistencia viram linha inerte
#                      (backup antes, sintaxe conferida depois; se quebrar, o original volta e o item sai PARCIAL/FALHOU)
#   -ApagarArquivo     tambem move para _backups\<carimbo>\quarentena o executavel E a carga (script/DLL que o
#                      interpretador roda); nunca de C:\Windows nem de Arquivos de Programas, nunca arquivo com assinatura valida
#   -Forcar            permite remover item marcado como PROTEGIDO (padrao generico + protegidos.txt)
#   -RemoverPastaSkill quando a origem e um script dentro de uma skill, move a pasta inteira da skill para a quarentena
# ORIGENS (HookAgente, HookPlugin, McpAgente, CodigoAgente, PluginAgente) sao removidas PRIMEIRO, de todos os arquivos de
# configuracao que as citam, para que nada recrie a persistencia durante a remocao (scripts\origem.py).
# Backup de tudo que for alterado em _backups\<carimbo>\ (na raiz da skill). Resultado em logs\remocao-*.json.
# Codigo de saida: 0 = tudo removido e verificado; 1 = algum item falhou/recusado/parcial; 2 = erro de uso.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string[]]$Id,
    [string]$Relatorio = '',
    [switch]$ApagarArquivo,
    [switch]$Forcar,
    [switch]$RemoverPastaSkill,
    [string[]]$SoLinhas = @()
)
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\comum.ps1"
$log = Start-LogSkill 'remover'

if (-not (Test-Administrador)) {
    Write-LogSkill 'ERRO: sem privilegio de administrador'
    Write-Output 'ERRO: remover.ps1 precisa de PowerShell como administrador.'  # scroll-ok: mensagem unica lida pelo Claude
    exit 2
}
if (-not $Relatorio) { $Relatorio = [IO.Path]::Combine((Get-PastaSkill 'logs'), 'ultima-varredura.json') }
if (-not (Test-Path -LiteralPath $Relatorio)) {
    Write-Output "ERRO: relatorio nao encontrado: $Relatorio (rode varrer.ps1 antes)"  # scroll-ok: mensagem unica lida pelo Claude
    exit 2
}
$rel = Get-Content -LiteralPath $Relatorio -Raw -Encoding UTF8 | ConvertFrom-Json
$itens = @($rel.Itens)
$tiposOrigem = @('HookAgente', 'HookPlugin', 'McpAgente', 'CodigoAgente', 'PluginAgente')

# -Id A,B chega como um texto so quando o script e chamado com -File: separar aqui
$ids = New-Object System.Collections.Generic.List[string]
foreach ($x in $Id) { foreach ($y in ($x -split '[,;\s]+')) { if ($y.Trim() -and -not $ids.Contains($y.Trim().ToUpper())) { $ids.Add($y.Trim().ToUpper()) } } }

$carimbo = Get-Carimbo
$pastaBk = [IO.Path]::Combine((Get-PastaSkill '_backups'), $carimbo)
New-Item -ItemType Directory -Path $pastaBk -Force | Out-Null
$resultados = New-Object System.Collections.Generic.List[object]

function Get-NomeSeguro([string]$t) { return ($t -replace '[^A-Za-z0-9._-]', '_') }

function Save-ChaveReg([string]$Local, [string]$Rotulo) {
    $arq = [IO.Path]::Combine($pastaBk, (Get-NomeSeguro $Rotulo) + '.reg')
    $null = & reg.exe export (ConvertTo-CaminhoReg $Local) $arq /y 2>$null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $arq)) { throw "falha no backup do registro (reg export codigo $LASTEXITCODE): $Local" }
    return $arq
}

function Save-Json($Objeto, [string]$Rotulo) {
    $arq = [IO.Path]::Combine($pastaBk, (Get-NomeSeguro $Rotulo) + '.json')
    Set-Content -LiteralPath $arq -Value ($Objeto | ConvertTo-Json -Depth 6) -Encoding UTF8
    return $arq
}

function Get-PropsCim($inst) {
    $o = [ordered]@{ Classe = $inst.CimClass.CimClassName }
    foreach ($p in $inst.CimInstanceProperties) {
        $v = $p.Value
        if ($v -is [Microsoft.Management.Infrastructure.CimInstance]) { $v = [string]$v.ToString() }
        elseif ($v -is [byte[]]) { $v = [Convert]::ToBase64String($v) }
        $o[$p.Name] = $v
    }
    return [pscustomobject]$o
}

function Move-ParaQuarentena([string]$Arquivo) {
    $q = [IO.Path]::Combine($pastaBk, 'quarentena')
    if (-not (Test-Path -LiteralPath $q)) { New-Item -ItemType Directory -Path $q -Force | Out-Null }
    $destino = [IO.Path]::Combine($q, ([IO.Path]::GetFileName($Arquivo) + '.quarentena'))
    $n = 1
    while (Test-Path -LiteralPath $destino) { $destino = [IO.Path]::Combine($q, ('{0}_{1}.quarentena' -f [IO.Path]::GetFileName($Arquivo), $n)); $n++ }
    Move-Item -LiteralPath $Arquivo -Destination $destino -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $Arquivo) { throw "arquivo continua no lugar: $Arquivo" }
    return $destino
}

function Remove-Registro($it) {
    $bk = Save-ChaveReg $it.Local ($it.Id + '_chave')
    Remove-ItemProperty -LiteralPath $it.Local -Name $it.Nome -Force -ErrorAction Stop
    $k = Get-Item -LiteralPath $it.Local -ErrorAction SilentlyContinue
    if ($k -and (@($k.GetValueNames()) -contains $it.Nome)) { throw "valor $($it.Nome) continua em $($it.Local)" }
    return "valor '$($it.Nome)' apagado de $($it.Local); backup $bk"
}

function Restore-ValorPadrao($it) {
    $bk = Save-ChaveReg $it.Local ($it.Id + '_chave')
    if ($it.Tipo -eq 'Winlogon' -and $it.Local -match '^Registry::HKEY_LOCAL_MACHINE') {
        $padrao = 'explorer.exe'
        if ($it.Nome -eq 'Userinit') { $padrao = [IO.Path]::Combine($env:SystemRoot, 'system32\userinit.exe') + ',' }
        Set-ItemProperty -LiteralPath $it.Local -Name $it.Nome -Value $padrao -ErrorAction Stop
        $atual = (Get-ItemProperty -LiteralPath $it.Local -Name $it.Nome -ErrorAction Stop).($it.Nome)
        if ($atual -ne $padrao) { throw "Winlogon $($it.Nome) nao voltou ao padrao" }
        return "Winlogon $($it.Nome) restaurado para '$padrao'; backup $bk"
    }
    if ($it.Tipo -eq 'AppInit') {
        Set-ItemProperty -LiteralPath $it.Local -Name 'AppInit_DLLs' -Value '' -ErrorAction Stop
        Set-ItemProperty -LiteralPath $it.Local -Name 'LoadAppInit_DLLs' -Value 0 -Type DWord -ErrorAction SilentlyContinue
        return "AppInit_DLLs esvaziado e LoadAppInit_DLLs=0 em $($it.Local); backup $bk"
    }
    $nomeValor = $it.Nome
    if ($it.Tipo -eq 'IFEO') { $nomeValor = 'Debugger' }
    Remove-ItemProperty -LiteralPath $it.Local -Name $nomeValor -Force -ErrorAction Stop
    $k = Get-Item -LiteralPath $it.Local -ErrorAction SilentlyContinue
    if ($k -and (@($k.GetValueNames()) -contains $nomeValor)) { throw "valor $nomeValor continua em $($it.Local)" }
    return "valor '$nomeValor' apagado de $($it.Local); backup $bk"
}

function Remove-Tarefa($it) {
    $t = Get-ScheduledTask -TaskName $it.TaskName -TaskPath $it.TaskPath -ErrorAction Stop
    $arq = [IO.Path]::Combine($pastaBk, (Get-NomeSeguro ($it.Id + '_tarefa')) + '.xml')
    Export-ScheduledTask -TaskName $it.TaskName -TaskPath $it.TaskPath -ErrorAction Stop | Set-Content -LiteralPath $arq -Encoding Unicode
    if ($t.State -eq 'Running') { Stop-ScheduledTask -TaskName $it.TaskName -TaskPath $it.TaskPath -ErrorAction SilentlyContinue }
    Unregister-ScheduledTask -TaskName $it.TaskName -TaskPath $it.TaskPath -Confirm:$false -ErrorAction Stop
    if (Get-ScheduledTask -TaskName $it.TaskName -TaskPath $it.TaskPath -ErrorAction SilentlyContinue) { throw "tarefa continua registrada: $($it.Nome)" }
    return "tarefa '$($it.Nome)' removida; backup XML $arq"
}

# Apaga objetos de root\subscription pelo System.Management (.Delete()). Usado quando o Remove-CimInstance falha com
# NotFound: acontece com vinculo criado por Set-WmiInstance/[wmiclass] (referencias relativas no __RELPATH).
function Remove-WmiSM([string]$Classe, [scriptblock]$Casa) {
    try { Add-Type -AssemblyName System.Management -ErrorAction Stop } catch { }
    $busca = New-Object System.Management.ManagementObjectSearcher('root\subscription', ('SELECT * FROM ' + $Classe))
    $apagados = 0
    foreach ($obj in $busca.Get()) {
        if (& $Casa $obj) { $obj.Delete(); $apagados++ }
    }
    if ($apagados -eq 0) { throw "System.Management nao achou objeto para apagar em $Classe" }
}
function Remove-WmiObjeto($Cim, [string]$Classe, [scriptblock]$Casa) {
    try { Remove-CimInstance -InputObject $Cim -ErrorAction Stop }
    catch {
        $e1 = $_.Exception.Message
        try { Remove-WmiSM $Classe $Casa } catch { throw ("Remove-CimInstance: {0} | System.Management: {1}" -f $e1, $_.Exception.Message) }
        Write-LogSkill ("{0}: Remove-CimInstance falhou ({1}); apagado pelo System.Management" -f $Classe, $e1)
    }
}
function Get-CasaVinculo([string]$Consumidor, [string]$Filtro) {
    $rc = 'Name=\\?"' + [regex]::Escape($Consumidor) + '\\?"'
    $rf = 'Name=\\?"' + [regex]::Escape($Filtro) + '\\?"'
    return { param($o) (([string]$o['Consumer']) -match $rc) -and (([string]$o['Filter']) -match $rf) }.GetNewClosure()
}
function Get-CasaNome([string]$Nome) {
    return { param($o) ([string]$o['Name']) -eq $Nome }.GetNewClosure()
}

function Remove-Wmi($it) {
    $ns = 'root/subscription'
    $vinculos = @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction Stop)
    if ($it.Tipo -eq 'WMI-Filtro') {
        $filtro = @(Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction Stop | Where-Object { $_.Name -eq $it.Nome })
        if ($filtro.Count -eq 0) { throw "filtro WMI nao encontrado: $($it.Nome)" }
        $vf = @($vinculos | Where-Object { $_.Filter -and $_.Filter.Name -eq $it.Nome })
        $bk = Save-Json ([pscustomobject]@{ Filtros = @($filtro | ForEach-Object { Get-PropsCim $_ }); Vinculos = @($vf | ForEach-Object { Get-PropsCim $_ }) }) ($it.Id + '_wmi')
        foreach ($b in $vf) { Remove-WmiObjeto $b '__FilterToConsumerBinding' (Get-CasaVinculo ([string]$b.Consumer.Name) ([string]$b.Filter.Name)) }
        foreach ($f in $filtro) { Remove-WmiObjeto $f '__EventFilter' (Get-CasaNome ([string]$f.Name)) }
        if (@(Get-CimInstance -Namespace $ns -ClassName __EventFilter | Where-Object { $_.Name -eq $it.Nome }).Count -gt 0) { throw "filtro WMI continua: $($it.Nome)" }
        return "filtro WMI '$($it.Nome)' removido; backup $bk"
    }
    $cons = @(Get-CimInstance -Namespace $ns -ClassName __EventConsumer -ErrorAction Stop | Where-Object { $_.Name -eq $it.Nome })
    if ($cons.Count -eq 0) { throw "consumidor WMI nao encontrado: $($it.Nome)" }
    $vc = @($vinculos | Where-Object { $_.Consumer -and $_.Consumer.Name -eq $it.Nome })
    $nomesF = @($vc | ForEach-Object { [string]$_.Filter.Name } | Select-Object -Unique)
    $outros = @($vinculos | Where-Object { -not ($_.Consumer -and $_.Consumer.Name -eq $it.Nome) })
    $filtros = @(Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction Stop | Where-Object { $nomesF -contains $_.Name })
    # filtro so e apagado se nenhum outro consumidor o usa
    $filtrosApagar = @($filtros | Where-Object { $fn = $_.Name; -not ($outros | Where-Object { $_.Filter -and $_.Filter.Name -eq $fn }) })
    $bk = Save-Json ([pscustomobject]@{
        Consumidores = @($cons | ForEach-Object { Get-PropsCim $_ })
        Filtros      = @($filtros | ForEach-Object { Get-PropsCim $_ })
        Vinculos     = @($vc | ForEach-Object { Get-PropsCim $_ })
    }) ($it.Id + '_wmi')
    foreach ($b in $vc) { Remove-WmiObjeto $b '__FilterToConsumerBinding' (Get-CasaVinculo ([string]$b.Consumer.Name) ([string]$b.Filter.Name)) }
    foreach ($c in $cons) { Remove-WmiObjeto $c '__EventConsumer' (Get-CasaNome ([string]$c.Name)) }
    foreach ($f in $filtrosApagar) { Remove-WmiObjeto $f '__EventFilter' (Get-CasaNome ([string]$f.Name)) }
    $sobra = @(Get-CimInstance -Namespace $ns -ClassName __EventConsumer | Where-Object { $_.Name -eq $it.Nome }).Count
    $sobra += @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding | Where-Object { $_.Consumer -and $_.Consumer.Name -eq $it.Nome }).Count
    foreach ($f in $filtrosApagar) { $fn = $f.Name; $sobra += @(Get-CimInstance -Namespace $ns -ClassName __EventFilter | Where-Object { $_.Name -eq $fn }).Count }
    if ($sobra -gt 0) { throw "sobraram $sobra objetos WMI de '$($it.Nome)'" }
    return ("assinatura WMI '{0}' removida: {1} vinculo(s), {2} consumidor(es), {3} filtro(s); backup {4}" -f $it.Nome, $vc.Count, $cons.Count, $filtrosApagar.Count, $bk)
}

function Remove-Servico($it) {
    $nome = [string]$it.Nome
    $chave = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\' + $nome
    if (-not (Test-Path -LiteralPath $chave)) { throw "servico nao existe: $nome" }
    $bk = Save-ChaveReg $chave ($it.Id + '_servico')
    $svc = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f ($nome -replace "'", "\'")) -ErrorAction SilentlyContinue
    if ($svc -and $svc.State -ne 'Stopped') {
        Stop-Service -Name $nome -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $svc = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f ($nome -replace "'", "\'")) -ErrorAction SilentlyContinue
        if ($svc -and $svc.State -ne 'Stopped' -and $svc.ProcessId -gt 0) {
            $outros = @(Get-CimInstance -ClassName Win32_Service -Filter ("ProcessId={0}" -f $svc.ProcessId) -ErrorAction SilentlyContinue)
            if ($outros.Count -le 1) { Stop-Process -Id $svc.ProcessId -Force -ErrorAction SilentlyContinue }
        }
    }
    $saida = (& sc.exe delete $nome) -join ' '
    $codigo = $LASTEXITCODE
    Write-LogSkill "sc.exe delete $nome -> codigo $codigo : $saida"
    if ($codigo -ne 0 -and $codigo -ne 1072) { throw "sc.exe delete falhou (codigo $codigo): $saida" }
    for ($i = 0; $i -lt 10; $i++) {
        if (-not (Test-Path -LiteralPath $chave)) { return "servico '$nome' parado e apagado; backup $bk" }
        Start-Sleep -Seconds 1
    }
    $flag = $null
    try { $flag = (Get-Item -LiteralPath $chave -ErrorAction Stop).GetValue('DeleteFlag', $null) } catch { }
    if ($flag -eq 1) { return "servico '$nome' MARCADO PARA EXCLUSAO (some ao fechar handles/reiniciar); nao inicia mais; backup $bk" }
    throw "servico continua no registro: $nome"
}

function Remove-ArquivoInicializar($it) {
    $arq = [string]$it.ArquivoInicializar
    if (-not (Test-Path -LiteralPath $arq)) { throw "arquivo nao existe: $arq" }
    $dest = Move-ParaQuarentena $arq
    return "arquivo da pasta Inicializar movido para quarentena: $dest"
}

function Stop-Processo($it) {
    $p = Get-Process -Id ([int]$it.PID) -ErrorAction SilentlyContinue
    if (-not $p) { return "processo PID $($it.PID) ja nao existe" }
    Stop-Process -Id ([int]$it.PID) -Force -ErrorAction Stop
    Start-Sleep -Milliseconds 500
    if (Get-Process -Id ([int]$it.PID) -ErrorAction SilentlyContinue) { throw "processo PID $($it.PID) continua vivo" }
    return "processo PID $($it.PID) ($($it.Nome)) encerrado"
}

# Move para a quarentena o executavel e a carga do item (powershell -File x.ps1 -> x.ps1; rundll32 evil.dll -> evil.dll).
function Remove-ArquivoAlvo($it) {
    $msgs = New-Object System.Collections.Generic.List[string]
    $alvos = New-Object System.Collections.Generic.List[string]
    foreach ($c in @([string]$it.Caminho, [string]$it.Carga)) {
        if ($c -and $c -ne '-' -and -not $alvos.Contains($c)) { $alvos.Add($c) }
    }
    foreach ($cam in $alvos) {
        if (-not (Test-ArquivoExiste $cam)) { $msgs.Add("$cam nao existe (nada a mover)"); continue }
        if (Test-CaminhoSistema $cam) { $msgs.Add("$cam fica em pasta do sistema/Arquivos de Programas: NAO movido"); continue }
        $ass = Get-InfoAssinatura $cam
        if ($ass.Status -eq 'Valid') { $msgs.Add("$cam tem assinatura valida ($($ass.Assinante)): NAO movido"); continue }
        foreach ($p in @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue | Where-Object { ($_.ExecutablePath -and $_.ExecutablePath -ieq $cam) -or ($_.CommandLine -and $_.CommandLine.IndexOf($cam, [StringComparison]::OrdinalIgnoreCase) -ge 0) })) {
            if ([int]$p.ProcessId -ne $PID) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
        }
        Start-Sleep -Milliseconds 500
        $dest = Move-ParaQuarentena $cam
        $msgs.Add("$cam movido para quarentena: $dest")
    }
    return ($msgs.ToArray() -join ' | ')
}

# Ordem: origens primeiro (para nada recriar a persistencia no meio da remocao), depois o resto na ordem pedida
$selecionados = New-Object System.Collections.Generic.List[object]
foreach ($idAlvo in $ids) {
    $it = $itens | Where-Object { $_.Id -eq $idAlvo } | Select-Object -First 1
    $selecionados.Add([pscustomobject]@{ Id = $idAlvo; Item = $it })
}
$idsOrigem = New-Object System.Collections.Generic.List[string]
foreach ($s in $selecionados) {
    $it = $s.Item
    $res = [ordered]@{ Id = $s.Id; Tipo = ''; Nome = ''; Status = ''; Detalhe = ''; Arquivo = '' }
    if (-not $it) { $res.Status = 'NAO_ENCONTRADO'; $res.Detalhe = "Id fora do relatorio $Relatorio"; $resultados.Add([pscustomobject]$res); continue }
    if ($it.Tipo -notin $tiposOrigem) { continue }
    $idsOrigem.Add($s.Id)
}
if ($idsOrigem.Count -gt 0) {
    Write-LogSkill ('removendo origens em agentes de IA: ' + ($idsOrigem -join ','))
    $argsPy = New-Object System.Collections.Generic.List[string]
    foreach ($x in @('remover', '--relatorio', $Relatorio, '--ids', ($idsOrigem -join ','), '--backup', $pastaBk, '--ignorar', $SkillRaiz)) { $argsPy.Add($x) }
    foreach ($r in @($rel.RaizesAgente)) { if ($r) { $argsPy.Add('--raiz-extra'); $argsPy.Add([string]$r) } }
    if ($RemoverPastaSkill) { $argsPy.Add('--remover-pasta-skill') }
    $soL = @(foreach ($x in $SoLinhas) { foreach ($y in ($x -split '[,;\s]+')) { if ($y.Trim()) { $y.Trim().ToUpper() } } })
    if ($soL.Count -gt 0) { $argsPy.Add('--so-linhas'); $argsPy.Add(($soL -join ',')) }
    $porIdPy = @{}
    $falhaPy = ''
    try {
        $r = Invoke-Origem -Argumentos $argsPy.ToArray() -ArquivoErro ([IO.Path]::Combine((Get-PastaSkill 'logs'), "origem-remover-$carimbo.err.txt"))
        Write-LogSkill ("origem.py remover codigo {0}: {1} {2}" -f $r.Codigo, $r.Texto, $r.Erro)
        $j = $r.Texto | ConvertFrom-Json -ErrorAction Stop
        foreach ($x in @($j.Resultados)) { $porIdPy[[string]$x.Id] = $x }
        if (@($j.Resultados).Count -eq 0) { $falhaPy = "origem.py nao devolveu resultados: $($r.Texto) $($r.Erro)" }
    } catch { $falhaPy = 'origem.py falhou: ' + $_.Exception.Message }
    foreach ($idO in $idsOrigem) {
        $it = ($selecionados | Where-Object { $_.Id -eq $idO } | Select-Object -First 1).Item
        $res = [ordered]@{ Id = $idO; Tipo = [string]$it.Tipo; Nome = [string]$it.Nome; Status = ''; Detalhe = ''; Arquivo = '' }
        $x = $porIdPy[$idO]
        if ($x) { $res.Status = [string]$x.Status; $res.Detalhe = [string]$x.Detalhe }
        else { $res.Status = 'FALHOU'; $res.Detalhe = $falhaPy }
        Write-LogSkill ("{0} -> {1}: {2}" -f $idO, $res.Status, $res.Detalhe)
        $resultados.Add([pscustomobject]$res)
    }
}

foreach ($s in $selecionados) {
    $it = $s.Item
    if (-not $it -or $it.Tipo -in $tiposOrigem) { continue }
    $idAlvo = $s.Id
    $res = [ordered]@{ Id = $idAlvo; Tipo = [string]$it.Tipo; Nome = [string]$it.Nome; Status = ''; Detalhe = ''; Arquivo = '' }
    if ($it.Protegido -and -not $Forcar) {
        $res.Status = 'RECUSADO_PROTEGIDO'; $res.Detalhe = "item protegido: $($it.MotivoProtecao). Use -Forcar so com evidencia no relatorio de que este item e malicioso."
        $resultados.Add([pscustomobject]$res); Write-LogSkill "$idAlvo recusado (protegido)"; continue
    }
    if (-not $it.Removivel) {
        $res.Status = 'NAO_REMOVIVEL'; $res.Detalhe = "tipo $($it.Tipo) e so de diagnostico (ver SKILL.md, secao Itens so de diagnostico)"
        $resultados.Add([pscustomobject]$res); continue
    }
    try {
        Write-LogSkill "removendo $idAlvo ($($it.Tipo)) $($it.Nome)"
        switch ($it.Tipo) {
            'Registro'    { $res.Detalhe = Remove-Registro $it }
            'Winlogon'    { $res.Detalhe = Restore-ValorPadrao $it }
            'IFEO'        { $res.Detalhe = Restore-ValorPadrao $it }
            'AppInit'     { $res.Detalhe = Restore-ValorPadrao $it }
            'PoliticaDefender' { $res.Detalhe = Restore-ValorPadrao $it }
            'Tarefa'      { $res.Detalhe = Remove-Tarefa $it }
            'WMI'         { $res.Detalhe = Remove-Wmi $it }
            'WMI-Filtro'  { $res.Detalhe = Remove-Wmi $it }
            'Servico'     { $res.Detalhe = Remove-Servico $it }
            'Inicializar' { $res.Detalhe = Remove-ArquivoInicializar $it }
            'Processo'    { $res.Detalhe = Stop-Processo $it }
            default       { throw "tipo sem rotina de remocao: $($it.Tipo)" }
        }
        $res.Status = 'REMOVIDO'
        if ($ApagarArquivo -and $it.Tipo -notin @('Inicializar', 'Processo')) {
            try { $res.Arquivo = Remove-ArquivoAlvo $it } catch { $res.Arquivo = 'falha ao mover arquivo: ' + $_.Exception.Message }
        }
    } catch {
        $res.Status = 'FALHOU'; $res.Detalhe = $_.Exception.Message
    }
    Write-LogSkill ("{0} -> {1}: {2} {3}" -f $idAlvo, $res.Status, $res.Detalhe, $res.Arquivo)
    $resultados.Add([pscustomobject]$res)
}

$arqRes = [IO.Path]::Combine((Get-PastaSkill 'logs'), "remocao-$carimbo.json")
Set-Content -LiteralPath $arqRes -Value (ConvertTo-Json -InputObject @($resultados.ToArray()) -Depth 4) -Encoding UTF8
$falhas = 0
foreach ($r in $resultados) { if ($r.Status -ne 'REMOVIDO') { $falhas++ } }
$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('=== REMOCAO ===')
[void]$sb.AppendLine("Relatorio usado: $Relatorio")
[void]$sb.AppendLine("Backups: $pastaBk")
[void]$sb.AppendLine("Resultado JSON: $arqRes")
[void]$sb.AppendLine("Log: $log")
foreach ($r in $resultados) {
    [void]$sb.AppendLine(('[{0}] {1} | {2} | {3}' -f $r.Id, $r.Status, $r.Tipo, $r.Nome))
    [void]$sb.AppendLine(('    {0}' -f $r.Detalhe))
    if ($r.Arquivo) { [void]$sb.AppendLine(('    arquivo: {0}' -f $r.Arquivo)) }
}
[void]$sb.AppendLine(('Itens pedidos: {0} | removidos: {1} | nao removidos: {2}' -f $resultados.Count, ($resultados.Count - $falhas), $falhas))
Write-Output $sb.ToString()  # scroll-ok: resumo unico emitido no fim, lido pelo Claude (produto do programa)
if ($falhas -gt 0) { exit 1 }
exit 0
