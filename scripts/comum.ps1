# comum.ps1 - funcoes compartilhadas da skill domfantoch-esterminador-de-virus.
# Carregado com:  . "$PSScriptRoot\comum.ps1"
# Arquivo em ASCII puro de proposito: o Windows PowerShell 5.1 le .ps1 sem BOM como ANSI.
# Compativel com Windows PowerShell 5.1 e PowerShell 7.x.

$SkillRaiz = Split-Path -Parent $PSScriptRoot
$Global:SkillSemAssinatura = $false
$Global:SkillCacheAssinatura = @{}
$Global:SkillLog = $null

function Get-PastaSkill([string]$Nome) {
    $p = [IO.Path]::Combine($SkillRaiz, $Nome)
    if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
    return $p
}

function Get-Carimbo { return (Get-Date -Format 'yyyyMMdd_HHmmss') }

function Start-LogSkill([string]$Nome) {
    $pasta = Get-PastaSkill 'logs'
    # rotacao: guarda os 80 arquivos mais novos (fora ultima-varredura.json e linha-de-base.json)
    try {
        Get-ChildItem -LiteralPath $pasta -File -ErrorAction Stop |
            Where-Object { $_.Name -notin @('ultima-varredura.json', 'linha-de-base.json') } |
            Sort-Object LastWriteTime -Descending | Select-Object -Skip 80 |
            Remove-Item -Force -ErrorAction SilentlyContinue
    } catch { }
    $Global:SkillLog = [IO.Path]::Combine($pasta, ('{0}-{1}.log' -f $Nome, (Get-Carimbo)))
    Write-LogSkill ('inicio: {0} | PowerShell {1} | usuario {2}' -f $Nome, $PSVersionTable.PSVersion, [Environment]::UserName)
    return $Global:SkillLog
}

function Write-LogSkill([string]$Mensagem) {
    if (-not $Global:SkillLog) { return }
    $linha = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Mensagem
    try { Add-Content -LiteralPath $Global:SkillLog -Value $linha -Encoding UTF8 } catch { }
}

function Test-Administrador {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-CaminhoReg([string]$Caminho) {
    $c = $Caminho -replace '^Registry::', ''
    $c = $c -replace '^HKEY_LOCAL_MACHINE', 'HKLM'
    $c = $c -replace '^HKEY_USERS', 'HKU'
    $c = $c -replace '^HKEY_CURRENT_USER', 'HKCU'
    return $c
}

function Get-ValoresChave([string]$Caminho) {
    $r = New-Object System.Collections.Generic.List[object]
    $k = $null
    try { $k = Get-Item -LiteralPath $Caminho -ErrorAction Stop } catch { return ,$r }
    foreach ($n in $k.GetValueNames()) {
        if ([string]::IsNullOrEmpty($n)) { continue }
        $v = $k.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($v -is [array]) { $v = ($v -join ' ') }
        $r.Add([pscustomobject]@{ Nome = $n; Valor = [string]$v })
    }
    return ,$r
}

# Data da ultima escrita de uma chave do registro (RegQueryInfoKey). Usada para achar item NOVO mesmo sem
# nenhum sinal suspeito no comando (ex.: valor Run apontando para notepad.exe criado ha 5 minutos).
$Global:SkillTempoReg = $false
$Global:SkillErroTempoReg = ''
try {
    if (-not ('SkillRegTempo' -as [type])) {
        Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SkillRegTempo {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "RegOpenKeyExW")]
    private static extern int RegOpenKeyEx(UIntPtr hKey, string subKey, int options, int samDesired, out IntPtr result);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "RegQueryInfoKeyW")]
    private static extern int RegQueryInfoKey(IntPtr hKey, IntPtr lpClass, IntPtr lpcClass, IntPtr lpReserved, IntPtr lpcSubKeys, IntPtr lpcMaxSubKeyLen, IntPtr lpcMaxClassLen, IntPtr lpcValues, IntPtr lpcMaxValueNameLen, IntPtr lpcMaxValueLen, IntPtr lpcbSecurityDescriptor, out long lpftLastWriteTime);
    [DllImport("advapi32.dll")]
    private static extern int RegCloseKey(IntPtr hKey);
    public static string Ultima(string raiz, string sub) {
        UIntPtr h;
        if (raiz == "HKLM") { h = new UIntPtr(0x80000002u); }
        else if (raiz == "HKU") { h = new UIntPtr(0x80000003u); }
        else if (raiz == "HKCU") { h = new UIntPtr(0x80000001u); }
        else { return ""; }
        IntPtr k;
        if (RegOpenKeyEx(h, sub, 0, 0x20119, out k) != 0) { return ""; }
        long ft = 0;
        int r = RegQueryInfoKey(k, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out ft);
        RegCloseKey(k);
        if (r != 0 || ft <= 0) { return ""; }
        return DateTime.FromFileTime(ft).ToString("s");
    }
}
'@
    }
    $Global:SkillTempoReg = $true
} catch {
    $Global:SkillErroTempoReg = $_.Exception.Message
}

function Get-UltimaEscritaReg([string]$Local) {
    if (-not $Global:SkillTempoReg) { return '' }
    $c = ConvertTo-CaminhoReg $Local
    $i = $c.IndexOf('\')
    if ($i -lt 1) { return '' }
    try { return [string]([SkillRegTempo]::Ultima($c.Substring(0, $i), $c.Substring($i + 1))) } catch { return '' }
}

# Nomes dos valores de uma subchave de HKCU vistos de FORA deste processo (WMI StdRegProv, roda no servico WMI).
# Processo lancado de dentro de app empacotado (ex.: app Claude desktop) pode ver/gravar uma visao virtual de HKCU.
function Get-NomesValoresFora([string]$SubChave) {
    $r = Invoke-CimMethod -Namespace 'root/default' -ClassName StdRegProv -MethodName EnumValues -Arguments @{ hDefKey = [uint32]2147483649; sSubKeyName = $SubChave } -ErrorAction Stop
    if ([int]$r.ReturnValue -eq 2) { return }
    if ([int]$r.ReturnValue -ne 0) { throw ('StdRegProv.EnumValues codigo {0} em HKCU\{1}' -f $r.ReturnValue, $SubChave) }
    foreach ($n in @($r.sNames)) { if ($n) { [string]$n } }
}

function Test-ArquivoExiste([string]$Caminho) {
    if ([string]::IsNullOrWhiteSpace($Caminho) -or $Caminho -eq '-') { return $false }
    try { return [bool](Test-Path -LiteralPath $Caminho -PathType Leaf -ErrorAction Stop) } catch { return $false }
}

function Get-CaminhoExecutavel([string]$Comando) {
    if ([string]::IsNullOrWhiteSpace($Comando)) { return '' }
    $c = [Environment]::ExpandEnvironmentVariables($Comando.Trim())
    $ehImagem = $false
    if ($c.StartsWith('\??\')) { $c = $c.Substring(4); $ehImagem = $true }
    if ($c -match '^\\SystemRoot\\') { $c = $env:SystemRoot + $c.Substring(11); $ehImagem = $true }
    if ($c -match '^(system32|syswow64)\\') { $c = [IO.Path]::Combine($env:SystemRoot, $c) }
    if ($c.StartsWith('"')) {
        $fim = $c.IndexOf('"', 1)
        if ($fim -gt 1) { return $c.Substring(1, $fim - 1) }
        return $c.Trim('"')
    }
    # ImagePath de driver/servico (\??\ ou \SystemRoot\): a linha inteira e o caminho quando existe como arquivo
    if ($ehImagem -and (Test-ArquivoExiste $c)) { return $c }
    # caminho sem aspas com espaco: regra do CreateProcess, testa prefixos cada vez mais longos (C:\Program, C:\Program Files\x, ...)
    if ($c -match '^[A-Za-z]:\\' -and $c.Contains(' ')) {
        $partes = $c -split ' '
        for ($i = 1; $i -le $partes.Count; $i++) {
            $cand = ($partes[0..($i - 1)] -join ' ')
            if (Test-ArquivoExiste $cand) { return $cand }
            if (Test-ArquivoExiste ($cand + '.exe')) { return ($cand + '.exe') }
        }
    }
    $m = [regex]::Match($c, '^(.+?\.(exe|com|bat|cmd|vbs|vbe|js|jse|hta|ps1|dll|scr|pif|sys|lnk|wsf|msc|cpl))(\s|,|$)', 'IgnoreCase')
    if ($m.Success) { $p = $m.Groups[1].Value } else { $p = ($c -split '\s+')[0] }
    if ($p -notmatch '\\') {
        $cmdInfo = Get-Command -Name $p -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmdInfo) { return [string]$cmdInfo.Path }
    }
    return $p
}

# Carga: o script/DLL que o interpretador executa (powershell -File x.ps1, wscript a.vbs, rundll32 evil.dll,Start).
# A assinatura e a quarentena tem de valer para a carga, nao so para o interpretador da Microsoft.
$Global:SkillReCarga = '(?i)(?<![A-Za-z0-9])(?:[A-Za-z]:[\\/]|\\\\)[^"''<>|*?\r\n]*?\.(?:ps1|psm1|vbs|vbe|js|jse|hta|wsf|bat|cmd|dll|exe|py|pyw|jar|scr|cpl|ocx|sct)(?=$|[\s"'',;)])'
function Get-Carga([string]$Comando, [string]$Caminho) {
    if ([string]::IsNullOrWhiteSpace($Comando)) { return '' }
    $c = [Environment]::ExpandEnvironmentVariables($Comando)
    $cam = ''
    if ($Caminho) { $cam = $Caminho.ToLower() }
    $primeiro = ''
    foreach ($m in [regex]::Matches($c, $Global:SkillReCarga)) {
        $p = (($m.Value -split '\s(?=[A-Za-z]:[\\/])')[-1]).Replace('/', '\')
        if ($p.ToLower() -eq $cam) { continue }
        if (Test-ArquivoExiste $p) { return $p }
        if (-not $primeiro) { $primeiro = $p }
    }
    return $primeiro
}

function Test-CaminhoSistema([string]$Caminho) {
    if (-not $Caminho) { return $false }
    $l = $Caminho.ToLower()
    foreach ($b in @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($b -and $l.StartsWith($b.ToLower().TrimEnd('\') + '\')) { return $true }
    }
    return $false
}

function Get-InfoAssinatura([string]$Caminho) {
    if (-not (Test-ArquivoExiste $Caminho)) { return [pscustomobject]@{ Status = 'ArquivoAusente'; Assinante = '' } }
    if ($Global:SkillCacheAssinatura.ContainsKey($Caminho)) { return $Global:SkillCacheAssinatura[$Caminho] }
    try {
        $s = Get-AuthenticodeSignature -LiteralPath $Caminho -ErrorAction Stop
        $assinante = ''
        if ($s.SignerCertificate) { $assinante = [string]$s.SignerCertificate.Subject }
        $r = [pscustomobject]@{ Status = [string]$s.Status; Assinante = $assinante }
    } catch {
        $r = [pscustomobject]@{ Status = 'ErroAoVerificar'; Assinante = [string]$_.Exception.Message }
    }
    $Global:SkillCacheAssinatura[$Caminho] = $r
    return $r
}

# Regras de pontuacao. Fontes: hunting-for-registry-run-key-persistence (temp, base64, LOLBins),
# hunting-for-scheduled-task-persistence, performing-ransomware-response (shadow copies),
# eradicating-malware-from-infected-systems (mapa de persistencia) - mukul975/Anthropic-Cybersecurity-Skills.
$Global:SkillRegras = @(
    @('(-e|-ec|-en|-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{16,}', 3, 'comando PowerShell codificado em base64'),
    @('frombase64string', 3, 'decodifica base64 dentro do comando'),
    @('-w(indowstyle)?\s+h(idden)?\b', 2, 'janela oculta (-WindowStyle Hidden)'),
    @('(downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|net\.webclient|start-bitstransfer|bitsadmin|certutil(\.exe)?\s.*-urlcache)', 3, 'baixa conteudo da internet'),
    @('\b(iex|invoke-expression)\b', 2, 'executa texto como codigo (Invoke-Expression)'),
    @('https?://', 2, 'URL dentro do comando'),
    @('\b(mshta|wscript|cscript|regsvr32|msbuild|installutil|regasm|regsvcs|cmstp|odbcconf|forfiles|pcalua)(\.exe)?\b', 2, 'binario do Windows usado para executar codigo (LOLBin)'),
    @('\brundll32(\.exe)?\b.*(javascript:|http|\\appdata\\|\\temp\\|\\users\\public\\|\\programdata\\)', 3, 'rundll32 carregando script/URL/arquivo de pasta gravavel'),
    @('\b(powershell|pwsh|cmd)(\.exe)?\b', 1, 'interpretador de comandos na inicializacao'),
    @('\bcmd(\.exe)?"?\s+/(c|k)\b', 2, 'cmd /c executando comando solto'),
    @('\.(vbs|vbe|js|jse|hta|wsf|ps1|bat|cmd|scr|pif)\b', 1, 'script na inicializacao'),
    @('(\b(vssadmin|wbadmin)\b.*\bdelete\b|bcdedit.*recoveryenabled\s+no|shadowcopy\s+delete|wbadmin.*catalog)', 4, 'apaga copias de sombra/recuperacao (tipico de ransomware)'),
    @('\\(appdata\\local\\temp|windows\\temp|users\\public|\$recycle\.bin|downloads|perflogs)\\', 2, 'executa a partir de pasta temporaria/gravavel'),
    @('^[a-z]:\\programdata\\[^\\]+\.(exe|dll|scr|bat|cmd|vbs|js|ps1)', 2, 'executavel solto na raiz de ProgramData'),
    @('\\appdata\\roaming\\[^\\]+\.(exe|dll|scr)$', 1, 'executavel solto na raiz de AppData\Roaming')
)

function Measure-Suspeita([string]$Comando, [string]$Caminho, $Assinatura) {
    $pts = 0
    $mot = New-Object System.Collections.Generic.List[string]
    $texto = '{0} {1}' -f $Comando, $Caminho
    foreach ($r in $Global:SkillRegras) {
        if ([regex]::IsMatch($texto, $r[0], 'IgnoreCase')) { $pts += $r[1]; $mot.Add($r[2]) }
    }
    if ($Caminho -match '^[a-zA-Z]:\\' -and $Assinatura) {
        switch ($Assinatura.Status) {
            'ArquivoAusente' { $pts += 1; $mot.Add('arquivo do comando nao existe no disco') }
            'NotSigned'      { if ($Caminho -notmatch '(?i)\.(bat|cmd|vbs|js|ps1|txt|py)$') { $pts += 1; $mot.Add('executavel sem assinatura digital') } }
            'HashMismatch'   { $pts += 3; $mot.Add('assinatura digital quebrada (arquivo alterado)') }
            'NotTrusted'     { $pts += 2; $mot.Add('assinatura digital nao confiavel') }
            'UnknownError'   { $pts += 1; $mot.Add('assinatura digital com erro') }
        }
    }
    return [pscustomobject]@{ Pontos = $pts; Motivos = $mot.ToArray() }
}

function Get-Nivel([int]$Pontos) {
    if ($Pontos -ge 4) { return 'alto' }
    if ($Pontos -ge 2) { return 'medio' }
    return 'baixo'
}

# Padrao generico de ferramentas comuns de desenvolvimento que costumam criar servicos/tarefas/valores Run legitimos:
# o remover.ps1 recusa sem -Forcar. Nada depende de elas existirem. Cada usuario acrescenta as proprias automacoes no
# arquivo protegidos.txt (raiz da skill, uma expressao regular por linha). Pastas de agente de IA (.claude,
# .config\opencode) NAO entram aqui de proposito: e justamente onde um hook/skill malicioso se instala. A protecao cai
# sozinha quando a varredura liga o item a uma origem (campo OrigemProvavel).
$Global:SkillProtegidos = @(
    @('\\Servy\\|servy-cli|\\nssm(\.exe)?\b', 'gerenciador de servicos (Servy/NSSM)'),
    @('ollama', 'Ollama'),
    @('ngrok', 'ngrok'),
    @('\\Docker\\|Docker Desktop|com\.docker', 'Docker'),
    @('burp', 'Burp Suite'),
    @('__claudeCodeScript|CLAUDE_CODE_SHELL', 'shell aberto pelo proprio Claude Code')
)
$arqProt = [IO.Path]::Combine($SkillRaiz, 'protegidos.txt')
if (Test-Path -LiteralPath $arqProt) {
    foreach ($l in (Get-Content -LiteralPath $arqProt -Encoding UTF8)) {
        $l = $l.Trim()
        if ($l -and -not $l.StartsWith('#')) { $Global:SkillProtegidos += ,@($l, "protegidos.txt: $l") }
    }
}

function Test-Protegido([string]$Texto) {
    foreach ($p in $Global:SkillProtegidos) {
        try { if ([regex]::IsMatch($Texto, $p[0], 'IgnoreCase')) { return [string]$p[1] } } catch { }
    }
    return ''
}

function New-Achado {
    param(
        [string]$Tipo, [string]$Local, [string]$Nome, [string]$Comando,
        [hashtable]$Extra = @{}, [int]$PontosExtra = 0, [string[]]$MotivosExtra = @(),
        [bool]$Removivel = $true, [string]$Caminho = '', [string]$Token = '', [string]$DataRef = ''
    )
    if (-not $Caminho) { $Caminho = Get-CaminhoExecutavel $Comando }
    $ass = [pscustomobject]@{ Status = 'NaoVerificada'; Assinante = '' }
    if ($Caminho -and $Caminho -ne '-' -and -not $Global:SkillSemAssinatura) { $ass = Get-InfoAssinatura $Caminho }
    $s = Measure-Suspeita -Comando $Comando -Caminho $Caminho -Assinatura $ass
    $pts = [int]$s.Pontos + $PontosExtra
    $mot = New-Object System.Collections.Generic.List[string]
    foreach ($x in @($s.Motivos) + @($MotivosExtra)) { if ($x) { $mot.Add([string]$x) } }
    $carga = ''
    if ($Caminho -ne '-') { $carga = Get-Carga $Comando $Caminho }
    $cargaExiste = Test-ArquivoExiste $carga
    $cargaAss = ''
    if ($carga) {
        if (-not $cargaExiste) { $pts += 1; $mot.Add('arquivo carregado pelo comando nao existe: ' + $carga) }
        elseif (-not $Global:SkillSemAssinatura) {
            $ca = Get-InfoAssinatura $carga
            $cargaAss = [string]$ca.Status
            if ($carga -match '(?i)\.(exe|dll|scr|ocx|cpl)$' -and $ca.Status -eq 'NotSigned') { $pts += 1; $mot.Add('carga sem assinatura digital: ' + $carga) }
        }
    }
    $prot = Test-Protegido ('{0} {1} {2} {3}' -f $Nome, $Comando, $Caminho, $Local)
    $o = [ordered]@{
        Id             = ''
        Tipo           = $Tipo
        Nivel          = (Get-Nivel $pts)
        Pontos         = $pts
        Nome           = $Nome
        Local          = $Local
        Comando        = $Comando
        Caminho        = $Caminho
        ArquivoExiste  = (Test-ArquivoExiste $Caminho)
        Assinatura     = [string]$ass.Status
        Assinante      = [string]$ass.Assinante
        Carga          = $carga
        CargaExiste    = $cargaExiste
        CargaAssinatura = $cargaAss
        Motivos        = ($mot.ToArray() -join '; ')
        Protegido      = [bool]($prot -ne '')
        MotivoProtecao = $prot
        Removivel      = $Removivel
        Token          = $Token
        DataRef        = $DataRef
        Recente        = $false
        Novo           = $null
        OrigemProvavel = ''
        Reinjetor      = ''
        NoResumo       = $false
    }
    foreach ($k in $Extra.Keys) { $o[$k] = $Extra[$k] }
    return [pscustomobject]$o
}

function Get-Python {
    foreach ($n in 'python', 'py') {
        $c = Get-Command -Name $n -CommandType Application -ErrorAction SilentlyContinue |
            Where-Object { $_.Path -notmatch '\\WindowsApps\\' } | Select-Object -First 1
        if ($c) {
            $a = @()
            if ($n -eq 'py') { $a = @('-3') }
            return [pscustomobject]@{ Exe = [string]$c.Path; Args = $a }
        }
    }
    return $null
}

# Roda scripts\origem.py (origem da infeccao em agentes de IA). stdout volta como texto; stderr vai para $ArquivoErro.
function Invoke-Origem([string[]]$Argumentos, [string]$ArquivoErro) {
    $py = Get-Python
    if (-not $py) { throw 'Python 3 nao encontrado no PATH (python/py): a parte de ORIGEM em agentes de IA nao rodou' }
    $script = [IO.Path]::Combine($PSScriptRoot, 'origem.py')
    $pyArgs = @($py.Args) + @('-X', 'utf8', '-I', $script) + @($Argumentos)
    $encAntes = $null
    try { $encAntes = [Console]::OutputEncoding; [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { $encAntes = $null }
    try {
        $saida = & $py.Exe @pyArgs 2> $ArquivoErro
        $codigo = $LASTEXITCODE
    } finally {
        if ($encAntes) { try { [Console]::OutputEncoding = $encAntes } catch { } }
    }
    $texto = (@($saida) | ForEach-Object { [string]$_ }) -join "`n"
    $erro = ''
    if (Test-Path -LiteralPath $ArquivoErro) { $erro = (Get-Content -LiteralPath $ArquivoErro -Raw -ErrorAction SilentlyContinue) }
    return [pscustomobject]@{ Codigo = $codigo; Texto = $texto; Erro = [string]$erro; Python = $py.Exe }
}

function Get-EstadoDefesas {
    $d = [ordered]@{}
    try { $d.WinDefend = [string](Get-Service -Name WinDefend -ErrorAction Stop).Status } catch { $d.WinDefend = 'servico ausente: ' + $_.Exception.Message }
    try {
        $m = Get-MpComputerStatus -ErrorAction Stop
        $d.MpComputerStatus = [ordered]@{
            AMServiceEnabled = $m.AMServiceEnabled; AntivirusEnabled = $m.AntivirusEnabled
            RealTimeProtectionEnabled = $m.RealTimeProtectionEnabled; IsTamperProtected = $m.IsTamperProtected
            AntivirusSignatureLastUpdated = [string]$m.AntivirusSignatureLastUpdated
        }
    } catch { $d.MpComputerStatus = 'Get-MpComputerStatus falhou: ' + $_.Exception.Message }
    try {
        $av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop)
        $d.SecurityCenter2 = @($av | ForEach-Object {
            $hex = '{0:X6}' -f [int]$_.productState
            $ativo = $hex.Substring(2, 2) -in @('10', '11')
            $atual = $hex.Substring(4, 2) -eq '00'
            '{0} | productState={1} (0x{2}) | ativo={3} | assinaturas_em_dia={4} (decodificacao pelo padrao publico do productState, NAO VERIFICADO na documentacao oficial)' -f $_.displayName, $_.productState, $hex, $ativo, $atual
        })
    } catch { $d.SecurityCenter2 = 'falhou: ' + $_.Exception.Message }
    $exc = New-Object System.Collections.Generic.List[string]
    $fonteExc = ''
    try {
        $p = Get-MpPreference -ErrorAction Stop
        foreach ($x in @($p.ExclusionPath)) { if ($x) { $exc.Add("Caminho: $x") } }
        foreach ($x in @($p.ExclusionProcess)) { if ($x) { $exc.Add("Processo: $x") } }
        foreach ($x in @($p.ExclusionExtension)) { if ($x) { $exc.Add("Extensao: $x") } }
        $fonteExc = 'Get-MpPreference'
    } catch {
        $fonteExc = 'registro (Get-MpPreference falhou: ' + $_.Exception.Message + ')'
        foreach ($sub in 'Paths', 'Processes', 'Extensions') {
            $vals = Get-ValoresChave "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\$sub"
            foreach ($v in $vals) { $exc.Add("${sub}: $($v.Nome)") }
        }
    }
    $d.ExclusoesDefender = $exc.ToArray()
    $d.FonteExclusoes = $fonteExc
    try {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1116, 1117; StartTime = (Get-Date).AddDays(-30) } -MaxEvents 50 -ErrorAction Stop)
        $d.DeteccoesDefender30d = @($ev | ForEach-Object { '{0} id={1} {2}' -f $_.TimeCreated.ToString('s'), $_.Id, ($_.Message -replace '\s+', ' ') })
    } catch { $d.DeteccoesDefender30d = 'nenhum evento 1116/1117 em 30 dias ou log indisponivel: ' + $_.Exception.Message }
    $sm = @(Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue)
    if ($sm.Count -gt 0) { $d.Sysmon = @($sm | ForEach-Object { '{0} {1}' -f $_.Name, $_.Status }) } else { $d.Sysmon = 'nao instalado (Get-Service Sysmon* vazio)' }
    try { $d.CopiasSombra = @(Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction Stop).Count } catch { $d.CopiasSombra = 'falhou: ' + $_.Exception.Message }
    return [pscustomobject]$d
}

function Get-EventosSysmon([int]$Horas = 24, [int]$Maximo = 200) {
    $sm = @(Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue)
    if ($sm.Count -eq 0) { return @('Sysmon nao instalado (Get-Service Sysmon* vazio)') }
    try {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 6, 12, 13, 14, 19, 20, 21; StartTime = (Get-Date).AddHours(-$Horas) } -MaxEvents $Maximo -ErrorAction Stop)
        return @($ev | ForEach-Object { '{0} id={1} {2}' -f $_.TimeCreated.ToString('s'), $_.Id, ($_.Message -replace '\s+', ' ') })
    } catch { return @('sem eventos Sysmon 6/12/13/14/19/20/21 nas ultimas ' + $Horas + ' h ou log indisponivel: ' + $_.Exception.Message) }
}
