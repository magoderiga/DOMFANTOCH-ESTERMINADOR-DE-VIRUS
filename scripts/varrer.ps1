# varrer.ps1 - varredura SOMENTE LEITURA dos pontos de persistencia, sinais de malware e ORIGEM em agentes de IA.
# Uso: pwsh -NoProfile -ExecutionPolicy Bypass -File varrer.ps1 [-Saida arquivo.json] [-Todos] [-SemAssinatura]
#        [-RaizAgente DIR[,DIR]] [-DiasRecentes 7] [-NovaLinhaDeBase] [-SemLinhaDeBase]
#   -RaizAgente     pasta extra tratada como "perfil" de agente (tem .claude\settings.json, .claude.json ...); usada no teste
#   -DiasRecentes   item criado/alterado nesse prazo entra no resumo mesmo sem sinal suspeito (padrao 7)
#   -NovaLinhaDeBase grava esta varredura como linha de base (itens fora dela saem como Novo=true depois)
#   -SemLinhaDeBase nao le nem grava a linha de base
# Gera: logs\varredura-AAAAMMDD_HHMMSS.json, logs\ultima-varredura.json e logs\varrer-*.log (andamento).
# Nao altera nada no sistema.
[CmdletBinding()]
param(
    [string]$Saida = '',
    [switch]$Todos,
    [switch]$SemAssinatura,
    [string[]]$RaizAgente = @(),
    [int]$DiasRecentes = 7,
    [switch]$NovaLinhaDeBase,
    [switch]$SemLinhaDeBase
)
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\comum.ps1"
$Global:SkillSemAssinatura = [bool]$SemAssinatura
$log = Start-LogSkill 'varrer'
$inicio = Get-Date
$achados = New-Object System.Collections.Generic.List[object]
$erros = New-Object System.Collections.Generic.List[string]
# Leitura de pasta/chave de outro usuario sem permissao nao pode vazar erro cru na saida: estes cmdlets ficam
# silenciosos por padrao (quem passa -ErrorAction explicito continua decidindo) e os acessos negados viram UMA linha
# de limite no fim (contados por categoria do erro, nao pelo texto, que muda com o idioma do Windows).
foreach ($cm in 'Test-Path', 'Get-ChildItem', 'Get-Item', 'Get-ItemProperty', 'Get-Acl', 'Get-Content', 'Resolve-Path') { $PSDefaultParameterValues[($cm + ':ErrorAction')] = 'SilentlyContinue' }
$Error.Clear()
# limites desta execucao (o que ficou de fora e por que), mostrados no resumo em vez de erro
$limites = New-Object System.Collections.Generic.List[string]
if (-not (Test-Administrador)) { $limites.Add('sem administrador: HKLM e servicos sao lidos, mas hives de outros usuarios, tarefas de outros usuarios, eventos do Sysmon/Defender e parte do WMI podem faltar; para remover, abrir o PowerShell como administrador') }
$pastaLogs = Get-PastaSkill 'logs'
$raizes = New-Object System.Collections.Generic.List[string]
foreach ($r in $RaizAgente) { foreach ($x in ([string]$r -split ',')) { if ($x.Trim()) { $raizes.Add($x.Trim()) } } }
if (-not $Global:SkillTempoReg) { Write-LogSkill ('aviso: data de escrita do registro indisponivel: ' + $Global:SkillErroTempoReg) }

function Add-Achado($a) { if ($a) { $achados.Add($a) } }
function Invoke-Etapa([string]$Nome, [scriptblock]$Bloco) {
    Write-LogSkill "etapa: $Nome"
    $antes = $achados.Count
    try { & $Bloco } catch { $erros.Add("$Nome -> $($_.Exception.Message)"); Write-LogSkill "ERRO em ${Nome}: $($_.Exception.Message)" }
    Write-LogSkill ("etapa {0} concluida: {1} itens" -f $Nome, ($achados.Count - $antes))
}

# Hives de usuario carregadas (HKCU de cada usuario logado aparece como HKEY_USERS\<SID>)
$hivesUsuario = @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -notmatch '_Classes$' -and $_.PSChildName -ne '.DEFAULT' } |
    ForEach-Object { 'Registry::HKEY_USERS\' + $_.PSChildName })

# 1. Chaves Run / RunOnce / Policies (T1547.001)
Invoke-Etapa 'chaves Run do registro' {
    $chaves = New-Object System.Collections.Generic.List[string]
    $relMaquina = @(
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
        'SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce',
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    )
    foreach ($r in $relMaquina) { $chaves.Add('Registry::HKEY_LOCAL_MACHINE\' + $r) }
    $relUsuario = @(
        'Software\Microsoft\Windows\CurrentVersion\Run',
        'Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach ($h in $hivesUsuario) { foreach ($r in $relUsuario) { $chaves.Add($h + '\' + $r) } }
    foreach ($ch in $chaves) {
        $vals = Get-ValoresChave $ch
        if ($vals.Count -eq 0) { continue }
        $data = Get-UltimaEscritaReg $ch
        foreach ($v in $vals) {
            Add-Achado (New-Achado -Tipo 'Registro' -Local $ch -Nome $v.Nome -Comando $v.Valor -Token $v.Nome -DataRef $data)
        }
    }
    # valores Load/Run legados em HKU\<SID>\Software\Microsoft\Windows NT\CurrentVersion\Windows
    foreach ($h in $hivesUsuario) {
        $ch = $h + '\Software\Microsoft\Windows NT\CurrentVersion\Windows'
        foreach ($v in (Get-ValoresChave $ch)) {
            if ($v.Nome -in @('Load', 'Run') -and $v.Valor.Trim()) {
                Add-Achado (New-Achado -Tipo 'Registro' -Local $ch -Nome $v.Nome -Comando $v.Valor -PontosExtra 3 -MotivosExtra @('valor legado Load/Run de inicializacao (raro em sistema limpo)') -DataRef (Get-UltimaEscritaReg $ch))
            }
        }
    }
}

# 1b. Visao do registro: este processo x fora dele (StdRegProv). Dentro de app empacotado, HKCU pode ser virtual:
# valor que so existe na visao deste processo NAO e inicializacao real do Windows.
$visaoRegistro = 'nao comparada'
$visaoDifere = $false
Invoke-Etapa 'visao do registro HKCU (processo x fora do processo)' {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $partes = New-Object System.Collections.Generic.List[string]
    foreach ($sub in 'Software\Microsoft\Windows\CurrentVersion\Run', 'Software\Microsoft\Windows\CurrentVersion\RunOnce') {
        $loc = 'Registry::HKEY_USERS\' + $sid + '\' + $sub
        $listaAqui = Get-ValoresChave $loc
        $aqui = @(foreach ($v in $listaAqui) { [string]$v.Nome })
        $fora = @(Get-NomesValoresFora $sub)
        $soAqui = @($aqui | Where-Object { $fora -notcontains $_ })
        $soFora = @($fora | Where-Object { $aqui -notcontains $_ })
        if ($soAqui.Count -gt 0 -or $soFora.Count -gt 0) { $script:visaoDifere = $true }
        $partes.Add(('HKCU\{0}: este processo={1} fora={2} | so na visao deste processo=[{3}] | so fora=[{4}]' -f $sub, $aqui.Count, $fora.Count, ($soAqui -join ', '), ($soFora -join ', ')))
        foreach ($a in $achados) {
            if ($a.Tipo -eq 'Registro' -and $a.Local -eq $loc -and $soAqui -contains [string]$a.Nome) {
                $a | Add-Member -NotePropertyName SoVisaoVirtual -NotePropertyValue $true -Force
                $a.Motivos = (@($a.Motivos, 'SO NA VISAO VIRTUAL deste processo: o registro real do Windows nao tem este valor (nao e inicializacao real)') | Where-Object { $_ }) -join '; '
            }
        }
    }
    $script:visaoRegistro = $partes -join ' || '
}

# 2. Winlogon, IFEO e AppInit_DLLs (T1547.004, T1546.012, T1546.010)
Invoke-Etapa 'Winlogon / IFEO / AppInit' {
    $wl = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    foreach ($v in (Get-ValoresChave $wl)) {
        if ($v.Nome -eq 'Shell' -and $v.Valor.Trim().ToLower() -ne 'explorer.exe') {
            Add-Achado (New-Achado -Tipo 'Winlogon' -Local $wl -Nome 'Shell' -Comando $v.Valor -PontosExtra 4 -MotivosExtra @('Winlogon Shell diferente de explorer.exe'))
        }
        if ($v.Nome -eq 'Userinit') {
            $u = $v.Valor.Trim().TrimEnd(',').ToLower()
            if ($u -notin @('c:\windows\system32\userinit.exe', ($env:SystemRoot.ToLower() + '\system32\userinit.exe'))) {
                Add-Achado (New-Achado -Tipo 'Winlogon' -Local $wl -Nome 'Userinit' -Comando $v.Valor -PontosExtra 4 -MotivosExtra @('Winlogon Userinit com programa extra'))
            }
        }
    }
    foreach ($h in $hivesUsuario) {
        $ch = $h + '\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
        foreach ($v in (Get-ValoresChave $ch)) {
            if ($v.Nome -eq 'Shell' -and $v.Valor.Trim()) {
                Add-Achado (New-Achado -Tipo 'Winlogon' -Local $ch -Nome 'Shell' -Comando $v.Valor -PontosExtra 4 -MotivosExtra @('Shell definido por usuario (substitui o explorer)'))
            }
        }
    }
    foreach ($base in 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
                      'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options') {
        foreach ($k in @(Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue)) {
            $dbg = $k.GetValue('Debugger', $null)
            if ($dbg) {
                $loc = 'Registry::' + $k.Name
                Add-Achado (New-Achado -Tipo 'IFEO' -Local $loc -Nome ($k.PSChildName + ' -> Debugger') -Comando ([string]$dbg) -PontosExtra 3 -MotivosExtra @('Debugger em Image File Execution Options (sequestra a abertura do programa)') -Extra @{ ValorRegistro = 'Debugger' } -DataRef (Get-UltimaEscritaReg $loc))
            }
        }
    }
    foreach ($ch in 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
                    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
        foreach ($v in (Get-ValoresChave $ch)) {
            if ($v.Nome -eq 'AppInit_DLLs' -and $v.Valor.Trim()) {
                Add-Achado (New-Achado -Tipo 'AppInit' -Local $ch -Nome 'AppInit_DLLs' -Comando $v.Valor -PontosExtra 3 -MotivosExtra @('AppInit_DLLs preenchido (DLL injetada em todo processo com user32)'))
            }
        }
    }
}

# 2b. Politicas que desligam o Defender (malware grava para se proteger)
Invoke-Etapa 'politicas do Defender' {
    $pol = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender'
    foreach ($ch in @($pol, ($pol + '\Real-Time Protection'))) {
        foreach ($v in (Get-ValoresChave $ch)) {
            if ($v.Nome -in @('DisableAntiSpyware', 'DisableAntiVirus', 'DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableIOAVProtection', 'DisableOnAccessProtection', 'DisableScanOnRealtimeEnable') -and $v.Valor -eq '1') {
                Add-Achado (New-Achado -Tipo 'PoliticaDefender' -Local $ch -Nome $v.Nome -Comando ('{0}=1' -f $v.Nome) -Caminho '-' -PontosExtra 4 -MotivosExtra @('politica de registro desliga protecao do Defender') -DataRef (Get-UltimaEscritaReg $ch))
            }
        }
    }
}

# 3. Pastas Inicializar (T1547.001)
Invoke-Etapa 'pastas Inicializar' {
    $pastas = New-Object System.Collections.Generic.List[string]
    $pastas.Add([IO.Path]::Combine($env:ProgramData, 'Microsoft\Windows\Start Menu\Programs\StartUp'))
    $perfis = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { -not $_.Special -and $_.LocalPath })
    foreach ($p in $perfis) { $pastas.Add([IO.Path]::Combine($p.LocalPath, 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')) }
    $sh = $null
    try { $sh = New-Object -ComObject WScript.Shell } catch { }
    foreach ($pa in ($pastas | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $pa)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $pa -File -Force -ErrorAction SilentlyContinue)) {
            if ($f.Name -ieq 'desktop.ini') { continue }
            $cmd = $f.FullName
            $cam = $f.FullName
            if ($f.Extension -ieq '.lnk' -and $sh) {
                try {
                    $lnk = $sh.CreateShortcut($f.FullName)
                    $cmd = ('{0} {1}' -f $lnk.TargetPath, $lnk.Arguments).Trim()
                    $cam = [string]$lnk.TargetPath
                    if (-not $cam) { $cam = $f.FullName }
                } catch { }
            }
            $pe = 0; $me = @()
            if ($f.Extension -match '^\.(bat|cmd|vbs|vbe|js|jse|ps1|hta|wsf|scr|pif|exe)$') { $pe = 1; $me = @('arquivo executavel/script direto na pasta Inicializar') }
            $dt = $f.LastWriteTime
            if ($f.CreationTime -gt $dt) { $dt = $f.CreationTime }
            Add-Achado (New-Achado -Tipo 'Inicializar' -Local $pa -Nome $f.Name -Comando $cmd -Caminho $cam -PontosExtra $pe -MotivosExtra $me -Extra @{ ArquivoInicializar = $f.FullName } -Token $f.BaseName -DataRef $dt.ToString('s'))
        }
    }
}

# 4. Tarefas agendadas (T1053.005) + tarefas ocultas no TaskCache (cross-view)
Invoke-Etapa 'tarefas agendadas' {
    $tarefas = @(Get-ScheduledTask -ErrorAction Stop)
    $vistas = @{}
    $dirTarefas = [IO.Path]::Combine($env:SystemRoot, 'System32\Tasks')
    foreach ($t in $tarefas) {
        $full = $t.TaskPath + $t.TaskName
        $vistas[$full.ToLower()] = 1
        $partes = New-Object System.Collections.Generic.List[string]
        $cam = ''
        foreach ($a in @($t.Actions)) {
            if ($a.PSObject.Properties['Execute'] -and $a.Execute) {
                $partes.Add(('{0} {1}' -f $a.Execute, $a.Arguments).Trim())
                if (-not $cam) { $cam = Get-CaminhoExecutavel ([string]$a.Execute) }
            } elseif ($a.PSObject.Properties['ClassId'] -and $a.ClassId) {
                $partes.Add('ComHandler ' + $a.ClassId + ' ' + $a.Data)
            }
        }
        if ($partes.Count -eq 0) { continue }
        if (-not $cam) { $cam = '-' }
        $pe = 0; $me = @()
        try { if ($t.Settings.Hidden) { $pe += 1; $me += 'tarefa marcada como oculta' } } catch { }
        $usr = ''
        try { $usr = [string]$t.Principal.UserId } catch { }
        $data = ''
        try { $data = (Get-Item -LiteralPath ($dirTarefas + $full) -Force -ErrorAction Stop).LastWriteTime.ToString('s') } catch { }
        Add-Achado (New-Achado -Tipo 'Tarefa' -Local $t.TaskPath -Nome $full -Comando ($partes -join ' | ') -Caminho $cam -PontosExtra $pe -MotivosExtra $me -Token $t.TaskName -DataRef $data -Extra @{ TaskPath = $t.TaskPath; TaskName = $t.TaskName; Estado = [string]$t.State; Autor = [string]$t.Author; Usuario = $usr })
    }
    # Cross-view: tarefa presente no registro TaskCache\Tree mas invisivel ao Get-ScheduledTask (tecnica Tarrask)
    $raiz = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree'
    $nraiz = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree'
    foreach ($k in @(Get-ChildItem -LiteralPath $raiz -Recurse -ErrorAction SilentlyContinue)) {
        $id = $k.GetValue('Id', $null)
        if (-not $id) { continue }
        $rel = $k.Name.Substring($nraiz.Length)
        if ($vistas.ContainsKey($rel.ToLower())) { continue }
        # entrada velha (sem TaskCache\Tasks\{Id}) e resto inofensivo de tarefa apagada: ignorar
        if (-not (Test-Path -LiteralPath ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\' + $id))) { continue }
        $temSD = @($k.GetValueNames()) -contains 'SD'
        if (-not $temSD) {
            Add-Achado (New-Achado -Tipo 'TarefaOculta' -Local ('Registry::' + $k.Name) -Nome $rel -Comando ('TaskCache Id=' + $id) -Caminho '-' -PontosExtra 4 -MotivosExtra @('tarefa ativa sem valor SD no TaskCache: escondida do Get-ScheduledTask (tecnica Tarrask)') -Removivel $false)
        } else {
            Add-Achado (New-Achado -Tipo 'TarefaOculta' -Local ('Registry::' + $k.Name) -Nome $rel -Comando ('TaskCache Id=' + $id) -Caminho '-' -PontosExtra 2 -MotivosExtra @('tarefa registrada que o Get-ScheduledTask nao lista (permissao restrita ou ocultacao)') -Removivel $false)
        }
    }
}

# 5. Assinaturas WMI (T1546.003)
Invoke-Etapa 'assinaturas WMI' {
    $filtros = @(Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction Stop)
    $consumidores = @(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -ErrorAction Stop)
    $vinculos = @(Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -ErrorAction Stop)
    $filtrosUsados = @{}
    foreach ($c in $consumidores) {
        $classe = $c.CimClass.CimClassName
        $cam = '-'
        if ($classe -eq 'CommandLineEventConsumer') {
            $cmd = [string]$c.CommandLineTemplate
            if (-not $cmd) { $cmd = [string]$c.ExecutablePath }
            if ($c.ExecutablePath) { $cam = [string]$c.ExecutablePath } else { $cam = Get-CaminhoExecutavel $cmd }
        } elseif ($classe -eq 'ActiveScriptEventConsumer') {
            $cmd = '[' + [string]$c.ScriptingEngine + '] ' + [string]$c.ScriptText
            if ($c.ScriptFileName) { $cmd += ' arquivo=' + $c.ScriptFileName; $cam = [string]$c.ScriptFileName }
        } else {
            $cmd = (@($c.CimInstanceProperties | Where-Object { $null -ne $_.Value -and $_.Name -notin @('CreatorSID', 'MachineName', 'MaximumQueueSize') } | ForEach-Object { '{0}={1}' -f $_.Name, $_.Value }) -join ' ')
        }
        $vs = @($vinculos | Where-Object { $_.Consumer -and $_.Consumer.Name -eq $c.Name })
        $nomesF = @($vs | ForEach-Object { [string]$_.Filter.Name })
        foreach ($nf in $nomesF) { $filtrosUsados[$nf] = 1 }
        $queries = @($filtros | Where-Object { $nomesF -contains $_.Name } | ForEach-Object { [string]$_.Query })
        $pe = 0; $me = @()
        if ($classe -in @('CommandLineEventConsumer', 'ActiveScriptEventConsumer')) { $pe += 3; $me += "consumidor WMI que executa codigo ($classe)" }
        if ($vs.Count -gt 0) { $pe += 1; $me += 'assinatura WMI ativa (filtro + consumidor + vinculo)' }
        Add-Achado (New-Achado -Tipo 'WMI' -Local ('root/subscription ' + $classe) -Nome ([string]$c.Name) -Comando $cmd -Caminho $cam -PontosExtra $pe -MotivosExtra $me -Token ([string]$c.Name) -Extra @{ ClasseConsumidor = $classe; Filtros = ($nomesF -join ' | '); Consultas = ($queries -join ' | ') })
    }
    foreach ($f in $filtros) {
        if (-not $filtrosUsados.ContainsKey([string]$f.Name)) {
            Add-Achado (New-Achado -Tipo 'WMI-Filtro' -Local 'root/subscription __EventFilter' -Nome ([string]$f.Name) -Comando ([string]$f.Query) -Caminho '-' -PontosExtra 1 -MotivosExtra @('filtro WMI sem consumidor ligado (resto de persistencia?)') -Token ([string]$f.Name))
        }
    }
}

# 6. Servicos (T1543.003) + servicos ocultos (registro x SCM) + drivers
$nomesScm = @{}
Invoke-Etapa 'servicos' {
    $svcs = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)
    foreach ($s in $svcs) {
        $nomesScm[([string]$s.Name).ToLower()] = 1
        $cmd = [string]$s.PathName
        $cam = ''
        if ($cmd -match '\\svchost\.exe') {
            $dll = ''
            foreach ($sub in ('\Parameters', '')) {
                if ($dll) { break }
                try {
                    $k = Get-Item -LiteralPath ('Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\' + $s.Name + $sub) -ErrorAction Stop
                    $dll = [string]$k.GetValue('ServiceDll', $null)
                } catch { }
            }
            if ($dll) { $dll = [Environment]::ExpandEnvironmentVariables($dll); $cam = $dll; $cmd = $cmd + ' [ServiceDll=' + $dll + ']' }
        }
        $data = Get-UltimaEscritaReg ('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\' + $s.Name)
        Add-Achado (New-Achado -Tipo 'Servico' -Local 'HKLM\SYSTEM\CurrentControlSet\Services' -Nome ([string]$s.Name) -Comando $cmd -Caminho $cam -Token ([string]$s.Name) -DataRef $data -Extra @{ NomeExibicao = [string]$s.DisplayName; Inicio = [string]$s.StartMode; Estado = [string]$s.State; Conta = [string]$s.StartName; PID = [int]$s.ProcessId })
    }
}
Invoke-Etapa 'drivers' {
    $drv = @(Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop)
    foreach ($d in $drv) {
        $nomesScm[([string]$d.Name).ToLower()] = 1
        if ($d.State -ne 'Running') { continue }
        $cam = Get-CaminhoExecutavel ([string]$d.PathName)
        $pe = 0; $me = @()
        if ($cam -and $cam -notmatch '\\(system32\\drivers|system32\\driverstore|syswow64\\drivers)\\') { $pe += 1; $me += 'driver carregado fora de System32\drivers / DriverStore' }
        $a = New-Achado -Tipo 'Driver' -Local 'Win32_SystemDriver' -Nome ([string]$d.Name) -Comando ([string]$d.PathName) -Caminho $cam -PontosExtra $pe -MotivosExtra $me -Removivel $false -Extra @{ NomeExibicao = [string]$d.DisplayName; Inicio = [string]$d.StartMode }
        if ($a.Pontos -ge 2 -or $Todos) { Add-Achado $a }
    }
}
Invoke-Etapa 'servicos ocultos (registro x SCM)' {
    $base = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services'
    foreach ($k in @(Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue)) {
        $tipo = $k.GetValue('Type', $null)
        $img = $k.GetValue('ImagePath', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($null -eq $tipo -or -not $img) { continue }
        if ([int]$tipo -notin @(1, 2, 16, 32)) { continue }
        if ($k.GetValue('DeleteFlag', $null) -eq 1) { continue }
        if (-not $nomesScm.ContainsKey($k.PSChildName.ToLower())) {
            Add-Achado (New-Achado -Tipo 'ServicoOculto' -Local ('Registry::' + $k.Name) -Nome $k.PSChildName -Comando ([string]$img) -PontosExtra 3 -MotivosExtra @('servico/driver no registro mas ausente do SCM (oculto ou criado direto no registro)') -Removivel $false)
        }
    }
}

# 7. Processos: suspeitos + processos ocultos (cross-view, detecting-rootkit-activity)
Invoke-Etapa 'processos' {
    $gp1 = @(Get-Process | ForEach-Object { $_.Id })
    $wp = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
    $gp2 = @(Get-Process | ForEach-Object { $_.Id })
    $vistosGP = @{}
    foreach ($i in ($gp1 + $gp2)) { $vistosGP[[int]$i] = 1 }
    $vistosCim = @{}
    foreach ($w in $wp) {
        $procId = [int]$w.ProcessId
        $vistosCim[$procId] = 1
        if ($procId -eq $PID) { continue }
        $cmd = [string]$w.CommandLine
        if (-not $cmd) { $cmd = [string]$w.ExecutablePath }
        $cam = [string]$w.ExecutablePath
        if (-not $cam) { $cam = '-' }
        $a = New-Achado -Tipo 'Processo' -Local ('PID ' + $procId) -Nome ([string]$w.Name) -Comando $cmd -Caminho $cam -Extra @{ PID = $procId; PIDPai = [int]$w.ParentProcessId }
        if ($a.Pontos -ge 2 -or $Todos) { Add-Achado $a }
        if (-not $vistosGP.ContainsKey($procId) -and $procId -gt 4) {
            if (-not (Get-Process -Id $procId -ErrorAction SilentlyContinue) -and (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$procId" -ErrorAction SilentlyContinue)) {
                Add-Achado (New-Achado -Tipo 'ProcessoOculto' -Local ('PID ' + $procId) -Nome ([string]$w.Name) -Comando $cmd -Caminho $cam -PontosExtra 3 -MotivosExtra @('processo visivel no WMI e invisivel ao Get-Process') -Removivel $false)
            }
        }
    }
    foreach ($i in $gp1) {
        if ($i -le 4 -or $vistosCim.ContainsKey([int]$i)) { continue }
        $gpx = Get-Process -Id $i -ErrorAction SilentlyContinue
        if ($gpx -and -not (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$i" -ErrorAction SilentlyContinue)) {
            Add-Achado (New-Achado -Tipo 'ProcessoOculto' -Local ('PID ' + $i) -Nome $gpx.ProcessName -Comando ([string]$gpx.Path) -Caminho '-' -PontosExtra 3 -MotivosExtra @('processo visivel ao Get-Process e invisivel no WMI') -Removivel $false)
        }
    }
}

# 8. Notas de resgate (performing-ransomware-response)
Invoke-Etapa 'notas de resgate' {
    $padrao = '(decrypt|ransom|restore[-_ ]?(my|your)?[-_ ]?files|recover[-_ ]?(my|your)?[-_ ]?files|how[-_ ]?to[-_ ]?(decrypt|recover|restore|back)|^_readme\.txt$|^!+.+\.(txt|hta|html)$)'
    $perfis = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { -not $_.Special -and $_.LocalPath })
    foreach ($p in $perfis) {
        foreach ($sub in 'Desktop', 'Documents', 'OneDrive\Desktop', 'OneDrive\Documents') {
            $pa = [IO.Path]::Combine($p.LocalPath, $sub)
            if (-not (Test-Path -LiteralPath $pa)) { continue }
            foreach ($f in @(Get-ChildItem -LiteralPath $pa -File -Force -ErrorAction SilentlyContinue)) {
                if ($f.Name -match $padrao -and $f.Extension -match '^\.(txt|hta|html|htm|url|rtf)$') {
                    Add-Achado (New-Achado -Tipo 'NotaResgate' -Local $pa -Nome $f.Name -Comando $f.FullName -Caminho '-' -PontosExtra 3 -MotivosExtra @('nome tipico de nota de resgate de ransomware') -Removivel $false)
                }
            }
        }
    }
}

# 9. Defesas: Defender, exclusoes, Sysmon, copias de sombra
$defesas = $null
Invoke-Etapa 'defesas (Defender / Sysmon)' {
    $script:defesas = Get-EstadoDefesas
    foreach ($e in @($script:defesas.ExclusoesDefender)) {
        if ($e) { Add-Achado (New-Achado -Tipo 'ExclusaoDefender' -Local 'Windows Defender Exclusions' -Nome $e -Comando $e -Caminho '-' -PontosExtra 2 -MotivosExtra @('exclusao no Defender (malware costuma se excluir da varredura)') -Removivel $false) }
    }
}
$eventosSysmon = Get-EventosSysmon -Horas 24 -Maximo 200

# Itens recentes (criados/alterados dentro de -DiasRecentes)
$limite = (Get-Date).AddDays(-[math]::Abs($DiasRecentes))
foreach ($a in $achados) {
    if ($a.DataRef) {
        try { $a.Recente = ([datetime]::Parse([string]$a.DataRef, [Globalization.CultureInfo]::InvariantCulture) -ge $limite) } catch { }
    }
}

# Ids estaveis dentro do relatorio
$prefixo = @{ Registro = 'REG'; Winlogon = 'WLG'; IFEO = 'IFE'; AppInit = 'API'; Inicializar = 'INI'; Tarefa = 'TAR'; TarefaOculta = 'TOC'; WMI = 'WMI'; 'WMI-Filtro' = 'WMF'; Servico = 'SRV'; ServicoOculto = 'SOC'; Driver = 'DRV'; Processo = 'PRC'; ProcessoOculto = 'POC'; NotaResgate = 'RSG'; ExclusaoDefender = 'EXC'; PoliticaDefender = 'PDF'; HookAgente = 'HKA'; HookPlugin = 'HKP'; McpAgente = 'MCP'; CodigoAgente = 'CAG'; PluginAgente = 'PAG' }
$cont = @{}
function Set-IdAchado($a) {
    $px = $prefixo[$a.Tipo]
    if (-not $px) { $px = 'OUT' }
    if (-not $cont.ContainsKey($px)) { $cont[$px] = 0 }
    $cont[$px]++
    $a.Id = '{0}-{1:D4}' -f $px, $cont[$px]
}
if (-not (Test-Administrador)) {
    $nOcultos = $achados.RemoveAll([Predicate[object]] { param($x) $x.Tipo -in @('ServicoOculto', 'ProcessoOculto', 'TarefaOculta') })
    $limites.Add(('sem administrador: comparacoes de visoes (servico/processo/tarefa oculto) nao foram feitas, porque o SCM, o WMI e o Agendador escondem itens de usuario comum e dariam falso positivo ({0} descartado(s))' -f $nOcultos))
}
foreach ($a in $achados) { Set-IdAchado $a }

# 10. ORIGEM: hooks, plugins, servidores MCP e instrucoes de agentes de IA que (re)criam a persistencia
$tiposOrigem = @('HookAgente', 'HookPlugin', 'McpAgente', 'CodigoAgente', 'PluginAgente')
$origemInfo = $null
Invoke-Etapa 'origem em agentes de IA (hooks, plugins, MCP, instrucoes)' {
    if (-not (Get-Python)) { $limites.Add('Python 3 nao encontrado (python/py no PATH): a parte ORIGEM em agentes de IA foi pulada; o resto da varredura vale'); return }
    $porId = @{}
    foreach ($a in $achados) { $porId[$a.Id] = $a }
    $ligaveis = @($achados | Where-Object {
        ($_.Tipo -in @('Registro', 'WMI', 'WMI-Filtro', 'Inicializar', 'Winlogon', 'IFEO', 'AppInit')) -or
        ($_.Tipo -eq 'Tarefa' -and ((-not ([string]$_.Local).StartsWith('\Microsoft\')) -or $_.Recente)) -or
        ($_.Tipo -eq 'Servico' -and (([string]$_.Assinante -notmatch 'Microsoft') -or $_.Recente))
    } | ForEach-Object { [pscustomobject]@{ Id = $_.Id; Tipo = $_.Tipo; Nome = $_.Nome; Token = $_.Token; Caminho = $_.Caminho; Carga = $_.Carga; Recente = [bool]$_.Recente } })
    $arqItens = [IO.Path]::Combine($pastaLogs, 'origem-itens.json')
    $arqOrigem = [IO.Path]::Combine($pastaLogs, 'origem-resultado.json')
    $arqErro = [IO.Path]::Combine($pastaLogs, 'origem-varrer.err.txt')
    Set-Content -LiteralPath $arqItens -Value (ConvertTo-Json -InputObject @($ligaveis) -Depth 3) -Encoding UTF8
    if (Test-Path -LiteralPath $arqOrigem) { Remove-Item -LiteralPath $arqOrigem -Force }
    $argsPy = New-Object System.Collections.Generic.List[string]
    foreach ($x in @('varrer', '--saida', $arqOrigem, '--itens', $arqItens, '--ignorar', $SkillRaiz)) { $argsPy.Add($x) }
    foreach ($r in $raizes) { $argsPy.Add('--raiz-extra'); $argsPy.Add($r) }
    $res = Invoke-Origem -Argumentos $argsPy.ToArray() -ArquivoErro $arqErro
    if ($res.Codigo -ne 0 -or -not (Test-Path -LiteralPath $arqOrigem)) { throw ('origem.py falhou (codigo {0}): {1} {2}' -f $res.Codigo, $res.Texto, $res.Erro) }
    $j = Get-Content -LiteralPath $arqOrigem -Raw -Encoding UTF8 | ConvertFrom-Json
    $script:origemInfo = [ordered]@{ Python = $res.Python; DuracaoSeg = $j.DuracaoSeg; Projetos = $j.Projetos; Homes = @($j.Homes); ArquivosLidos = @($j.ArquivosLidos); ErrosLeitura = @($j.ErrosLeitura); CopiasDaSkill = @($j.CopiasDaSkill) }
    $origens = New-Object System.Collections.Generic.List[object]
    foreach ($p in @($j.Itens)) {
        $o = [ordered]@{
            Id = ''; Tipo = [string]$p.Tipo; Nivel = (Get-Nivel ([int]$p.Pontos)); Pontos = [int]$p.Pontos
            Nome = [string]$p.Nome; Local = [string]$p.Local; Comando = [string]$p.Comando; Caminho = [string]$p.Caminho
            ArquivoExiste = (Test-ArquivoExiste ([string]$p.Caminho)); Assinatura = '-'; Assinante = ''
            Carga = ''; CargaExiste = $false; CargaAssinatura = ''; Motivos = [string]$p.Motivos
            Protegido = $false; MotivoProtecao = ''; Removivel = [bool]$p.Removivel; Token = ''; DataRef = ''
            Recente = $false; Novo = $null; OrigemProvavel = ''; Reinjetor = ''; NoResumo = $true
        }
        foreach ($pr in $p.PSObject.Properties) { if (-not $o.Contains($pr.Name)) { $o[$pr.Name] = $pr.Value } }
        if ($o.ArquivoExiste) {
            try {
                $dt = (Get-Item -LiteralPath $o.Caminho -Force -ErrorAction Stop).LastWriteTime
                $o.DataRef = $dt.ToString('s')
                $o.Recente = ($dt -ge $limite)
            } catch { }
        }
        $obj = [pscustomobject]$o
        Set-IdAchado $obj
        $origens.Add($obj)
    }
    # liga persistencia -> origem (a origem recria o artefato); a protecao do item cai porque a evidencia aponta para ataque
    $reforcados = @{}
    foreach ($o in $origens) {
        foreach ($lid in @($o.LigadoA)) {
            $alvo = $porId[[string]$lid]
            if (-not $alvo) { continue }
            if ($alvo.OrigemProvavel) { $alvo.OrigemProvavel = $alvo.OrigemProvavel + ', ' + $o.Id } else { $alvo.OrigemProvavel = $o.Id }
            if (-not $reforcados.ContainsKey($alvo.Id)) {
                $reforcados[$alvo.Id] = 1
                $alvo.Pontos = [int]$alvo.Pontos + 4
                $alvo.Motivos = (@($alvo.Motivos, ('recriado por origem em agente de IA: ' + $o.Id + ' (' + $o.Local + ')')) | Where-Object { $_ }) -join '; '
            }
            if ($alvo.Protegido) { $alvo.Protegido = $false; $alvo.MotivoProtecao = 'protecao retirada: ligado a origem em agente de IA ' + $o.Id }
        }
    }
    if ($j.Reinjetores) {
        foreach ($pr in $j.Reinjetores.PSObject.Properties) {
            $alvo = $porId[[string]$pr.Name]
            if (-not $alvo) { continue }
            $alvo.Reinjetor = (@($pr.Value) -join ' || ')
            $alvo.Pontos = [int]$alvo.Pontos + 3
            $alvo.Motivos = (@($alvo.Motivos, 'o script deste item mexe em configuracao de agente de IA (pode reinjetar hook/MCP)') | Where-Object { $_ }) -join '; '
        }
    }
    foreach ($o in $origens) { $achados.Add($o) }
}

# Nivel final, linha de base (itens novos) e o que entra no resumo
$tiposSempre = @('Registro', 'Inicializar', 'WMI', 'WMI-Filtro', 'Winlogon', 'IFEO', 'AppInit') + $tiposOrigem
$arqBase = [IO.Path]::Combine($pastaLogs, 'linha-de-base.json')
$base = $null
if (-not $SemLinhaDeBase -and (Test-Path -LiteralPath $arqBase)) {
    try {
        $base = @{}
        foreach ($k in @(Get-Content -LiteralPath $arqBase -Raw -Encoding UTF8 | ConvertFrom-Json)) { $base[[string]$k] = 1 }
    } catch { $base = $null; $erros.Add('linha de base ilegivel: ' + $_.Exception.Message) }
}
$chavesAgora = New-Object System.Collections.Generic.List[string]
foreach ($a in $achados) {
    $a.Nivel = Get-Nivel ([int]$a.Pontos)
    if ($a.Tipo -notin @('Processo', 'ProcessoOculto')) {
        $k = '{0}|{1}|{2}|{3}' -f $a.Tipo, $a.Local, $a.Nome, $a.Comando
        $chavesAgora.Add($k)
        if ($null -ne $base) { $a.Novo = -not $base.ContainsKey($k) }
    }
    $a.NoResumo = [bool]($Todos -or $a.Nivel -ne 'baixo' -or $a.Tipo -in $tiposSempre -or $a.Recente -or ($a.Novo -eq $true) -or $a.OrigemProvavel -or $a.Reinjetor)
}
if (-not $SemLinhaDeBase -and ($NovaLinhaDeBase -or $null -eq $base)) {
    Set-Content -LiteralPath $arqBase -Value (ConvertTo-Json -InputObject @($chavesAgora.ToArray()) -Depth 2) -Encoding UTF8
    Write-LogSkill "linha de base gravada: $arqBase ($($chavesAgora.Count) itens)"
}

$fim = Get-Date
$negados = @($Error | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] -and ($_.CategoryInfo.Category -eq 'PermissionDenied' -or $_.Exception -is [System.UnauthorizedAccessException] -or $_.Exception -is [System.Security.SecurityException]) } | ForEach-Object { [string]$_.TargetObject } | Where-Object { $_ } | Select-Object -Unique)
if ($negados.Count -gt 0) { $limites.Add(('acesso negado a {0} pasta(s)/chave(s) (perfis ou chaves de outros usuarios; com administrador sao lidos): {1}' -f $negados.Count, ($negados -join ' | '))) }
$relatorio = [ordered]@{
    Gerado        = $fim.ToString('s')
    Computador    = $env:COMPUTERNAME
    Usuario       = [Environment]::UserName
    Administrador = (Test-Administrador)
    PowerShell    = [string]$PSVersionTable.PSVersion
    DuracaoSeg    = [math]::Round(($fim - $inicio).TotalSeconds, 1)
    DiasRecentes  = $DiasRecentes
    LinhaDeBase   = $(if ($null -ne $base) { $arqBase } else { 'nenhuma (esta varredura virou a linha de base, ou -SemLinhaDeBase)' })
    RaizesAgente  = $raizes.ToArray()
    Limites       = $limites.ToArray()
    Origem        = $origemInfo
    Defesas       = $defesas
    VisaoRegistro = [ordered]@{ Difere = $visaoDifere; Detalhe = $visaoRegistro }
    EventosSysmon = @($eventosSysmon)
    Erros         = $erros.ToArray()
    Itens         = $achados.ToArray()
}
$json = $relatorio | ConvertTo-Json -Depth 6
$arq = [IO.Path]::Combine($pastaLogs, ('varredura-{0}.json' -f $fim.ToString('yyyyMMdd_HHmmss')))
Set-Content -LiteralPath $arq -Value $json -Encoding UTF8
Set-Content -LiteralPath ([IO.Path]::Combine($pastaLogs, 'ultima-varredura.json')) -Value $json -Encoding UTF8
if ($Saida) { Set-Content -LiteralPath $Saida -Value $json -Encoding UTF8 }
Write-LogSkill ("fim: {0} itens, relatorio {1}" -f $achados.Count, $arq)

# Resumo para o Claude ler (texto montado inteiro e emitido uma vez so)
$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('=== VARREDURA DE PERSISTENCIA, MALWARE E ORIGEM EM AGENTES DE IA (somente leitura) ===')
[void]$sb.AppendLine(('Relatorio JSON: {0}' -f $arq))
[void]$sb.AppendLine(('Log: {0}' -f $log))
[void]$sb.AppendLine(('Administrador: {0} | PowerShell {1} | duracao {2} s | itens: {3}' -f $relatorio.Administrador, $relatorio.PowerShell, $relatorio.DuracaoSeg, $achados.Count))
$grupos = $achados | Group-Object Tipo | Sort-Object Name
[void]$sb.AppendLine('Por tipo: ' + (($grupos | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }) -join ', '))
$nAlto = @($achados | Where-Object { $_.Nivel -eq 'alto' }).Count
$nMedio = @($achados | Where-Object { $_.Nivel -eq 'medio' }).Count
[void]$sb.AppendLine(('Nivel alto: {0} | medio: {1} | recentes (<= {2} dias): {3} | linha de base: {4}' -f $nAlto, $nMedio, $DiasRecentes, @($achados | Where-Object { $_.Recente }).Count, $relatorio.LinhaDeBase))
if ($defesas) {
    [void]$sb.AppendLine(('Defender: WinDefend={0} | MpComputerStatus={1}' -f $defesas.WinDefend, (($defesas.MpComputerStatus | ConvertTo-Json -Compress -Depth 3))))
    [void]$sb.AppendLine(('SecurityCenter2: {0}' -f (@($defesas.SecurityCenter2) -join ' || ')))
    [void]$sb.AppendLine(('Sysmon: {0} | Copias de sombra: {1}' -f (@($defesas.Sysmon) -join ', '), $defesas.CopiasSombra))
}
if ($origemInfo) {
    [void]$sb.AppendLine(('Origem (agentes de IA): {0} arquivos de configuracao lidos, {1} projetos, Python {2}' -f @($origemInfo.ArquivosLidos).Count, $origemInfo.Projetos, $origemInfo.Python))
    [void]$sb.AppendLine('    lidos: ' + (@($origemInfo.ArquivosLidos) -join ' | '))
    if (@($origemInfo.ErrosLeitura).Count -gt 0) { [void]$sb.AppendLine('    nao lidos: ' + (@($origemInfo.ErrosLeitura) -join ' || ')) }
    foreach ($cp in @($origemInfo.CopiasDaSkill)) { if ($cp) { [void]$sb.AppendLine('    copia desta skill em ' + $cp + ' (arquivos com SHA256 identico aos desta skill: nao pontuados)') } }
}
[void]$sb.AppendLine('Visao do registro HKCU (este processo x fora, StdRegProv): ' + $visaoRegistro)
if ($visaoDifere) { [void]$sb.AppendLine('ATENCAO: as visoes do registro diferem. Este processo roda dentro de uma visao virtual (app empacotado). Valores marcados SO NA VISAO VIRTUAL nao existem no Windows real; para varredura e prova reais, rodar fora do app (scripts\sessao-nova.ps1 / Win32_Process.Create).') }
if ($limites.Count -gt 0) { [void]$sb.AppendLine('LIMITES DESTA VARREDURA: ' + ($limites -join ' || ')) }
if ($erros.Count -gt 0) { [void]$sb.AppendLine('ERROS DE ETAPA: ' + ($erros -join ' || ')) }

$ordem = @{ Expression = 'Pontos'; Descending = $true }
$origensResumo = @($achados | Where-Object { $_.Tipo -in $tiposOrigem } | Sort-Object $ordem, Id)
[void]$sb.AppendLine(('--- ORIGEM: hooks, plugins, servidores MCP e codigo de agentes de IA ({0}) ---' -f $origensResumo.Count))
foreach ($a in $origensResumo) {
    [void]$sb.AppendLine(('[{0}] {1} {2}pts {3} | {4} | {5} | {6}' -f $a.Id, $a.Nivel.ToUpper(), $a.Pontos, $a.Tipo, $a.Agente, $a.Nome, $a.Local))
    [void]$sb.AppendLine(('    comando: {0}' -f $a.Comando))
    if (@($a.Scripts).Count -gt 0) { [void]$sb.AppendLine(('    scripts: {0}' -f (@($a.Scripts) -join ' | '))) }
    if (@($a.ScriptsAninhados).Count -gt 0) { [void]$sb.AppendLine(('    chamados por eles: {0}' -f (@($a.ScriptsAninhados) -join ' | '))) }
    if ($a.Motivos) { [void]$sb.AppendLine(('    motivos: {0}' -f $a.Motivos)) }
    if (@($a.LigadoA).Count -gt 0) { [void]$sb.AppendLine(('    CRIA ESTES ITENS DE PERSISTENCIA: {0}' -f (@($a.LigadoA) -join ', '))) }
    if (@($a.Reinjetores).Count -gt 0) { [void]$sb.AppendLine(('    reinjetado por: {0}' -f (@($a.Reinjetores) -join ' || '))) }
    if (@($a.Trechos).Count -gt 0) { [void]$sb.AppendLine(('    trechos: {0}' -f (@($a.Trechos) -join ' || '))) }
}
$mostrar = @($achados | Where-Object { $_.NoResumo -and $_.Tipo -notin $tiposOrigem } | Sort-Object $ordem, Id)
[void]$sb.AppendLine(('--- PERSISTENCIA E SINAIS NO WINDOWS ({0} de {1}: medio/alto, tipos sempre listados, recentes, novos, ligados a origem) ---' -f $mostrar.Count, @($achados | Where-Object { $_.Tipo -notin $tiposOrigem }).Count))
foreach ($a in $mostrar) {
    $marcas = @()
    if ($a.Recente) { $marcas += ('RECENTE ' + $a.DataRef) }
    if ($a.Novo -eq $true) { $marcas += 'NOVO (fora da linha de base)' }
    if ($a.OrigemProvavel) { $marcas += ('ORIGEM=' + $a.OrigemProvavel) }
    if ($a.PSObject.Properties['SoVisaoVirtual']) { $marcas += 'SO NA VISAO VIRTUAL (nao existe no Windows real)' }
    $txtMarcas = ''
    if ($marcas.Count -gt 0) { $txtMarcas = ' | ' + ($marcas -join ' | ') }
    [void]$sb.AppendLine(('[{0}] {1} {2}pts {3} | {4} | {5}{6}' -f $a.Id, $a.Nivel.ToUpper(), $a.Pontos, $a.Tipo, $a.Nome, $a.Local, $txtMarcas))
    [void]$sb.AppendLine(('    comando: {0}' -f $a.Comando))
    [void]$sb.AppendLine(('    arquivo: {0} | existe={1} | assinatura={2} {3}' -f $a.Caminho, $a.ArquivoExiste, $a.Assinatura, $a.Assinante))
    if ($a.Carga) { [void]$sb.AppendLine(('    carga: {0} | existe={1} | assinatura={2}' -f $a.Carga, $a.CargaExiste, $a.CargaAssinatura)) }
    if ($a.Motivos) { [void]$sb.AppendLine(('    motivos: {0}' -f $a.Motivos)) }
    if ($a.Reinjetor) { [void]$sb.AppendLine(('    REINJETA AGENTE: {0}' -f $a.Reinjetor)) }
    if ($a.Protegido) { [void]$sb.AppendLine(('    PROTEGIDO: {0} (so remove com -Forcar)' -f $a.MotivoProtecao)) }
}
Write-Output $sb.ToString()  # scroll-ok: resumo unico emitido no fim, lido pelo Claude (produto do programa)
exit 0
