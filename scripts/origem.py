# -*- coding: utf-8 -*-
"""
origem.py - parte da skill domfantoch-esterminador-de-virus.

Acha a ORIGEM de uma infeccao que se reinstala sozinha a partir de agentes de IA:
hooks e comandos automaticos (Claude Code, Cursor, Gemini CLI, Codex), plugins do Claude Code,
servidores MCP (Claude Code, Claude Desktop, Cursor, OpenCode, VS Code, Codex, Windsurf),
plugins do OpenCode, hooks declarados no frontmatter de SKILL.md / agents/*.md / commands/*.md e
comandos inline (!`cmd`) desses .md, codigo em hooks/skills/agents/commands e instrucoes em CLAUDE.md/AGENTS.md.
Liga cada origem ao artefato de persistencia que ela cria (Run, tarefa, servico, WMI, Inicializar)
e remove a origem escolhida de TODOS os lugares, com backup em _backups e validacao do JSON gravado.
Com --so-linhas ID, em vez de remover o hook, limpa so as linhas que criam persistencia dentro do script
(para script legitimo do usuario que foi trojanizado), com backup e conferencia de sintaxe.

Uso:
  python -X utf8 -I origem.py varrer  --saida origem.json [--itens itens.json]
                                      [--raiz-extra DIR]... [--ignorar DIR]... [--sem-home]
  python -X utf8 -I origem.py remover --relatorio varredura.json --ids HKA-0001,MCP-0002 --backup DIR
                                      [--raiz-extra DIR]... [--ignorar DIR]... [--sem-home] [--remover-pasta-skill]
                                      [--so-linhas HKA-0001,...]
Somente biblioteca padrao (Python 3.8+; TOML do Codex so com Python 3.11+).
Nao imprime andamento: 'varrer' grava o resultado no arquivo --saida; 'remover' emite um JSON unico no stdout.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except Exception:  # pragma: no cover
    tomllib = None

HOME = Path(os.environ.get("USERPROFILE") or str(Path.home()))
APPDATA = Path(os.environ.get("APPDATA") or str(HOME / "AppData" / "Roaming"))
LOCALAPPDATA = Path(os.environ.get("LOCALAPPDATA") or str(HOME / "AppData" / "Local"))
PROGRAMDATA = Path(os.environ.get("ProgramData") or r"C:\ProgramData")
SISTEMA = [x.lower().rstrip("\\") + "\\" for x in (
    os.environ.get("SystemRoot") or r"C:\Windows",
    os.environ.get("ProgramFiles") or r"C:\Program Files",
    os.environ.get("ProgramFiles(x86)") or r"C:\Program Files (x86)",
)]

EXT_SCRIPT = ("ps1", "psm1", "py", "pyw", "js", "mjs", "cjs", "ts", "sh", "bash", "bat", "cmd", "vbs", "vbe", "jse", "wsf", "hta")
EXT_BIN = ("exe", "dll", "scr", "jar")
INTERPRETADORES = {
    "python.exe", "pythonw.exe", "py.exe", "pyw.exe", "node.exe", "bun.exe", "deno.exe", "uv.exe", "uvx.exe",
    "pwsh.exe", "powershell.exe", "cmd.exe", "bash.exe", "sh.exe", "wsl.exe", "git.exe", "java.exe", "javaw.exe",
    "ruby.exe", "perl.exe", "php.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "docker.exe", "claude.exe", "opencode.exe", "npx.cmd", "npm.cmd", "pnpm.cmd", "yarn.cmd", "bunx.cmd",
}
RE_CAMINHO = re.compile(
    r'(?<![A-Za-z0-9])(?:[A-Za-z]:[\\/]|\\\\)[^"\'<>|*?\r\n]*?\.(?:' + "|".join(EXT_SCRIPT + EXT_BIN) + r')(?=$|[\s"\',;)\]])',
    re.I)
RE_RELATIVO = re.compile(
    r'(?<![\w:\\/.])(\.claude[\\/][^"\'<>|*?\r\n\s]+?\.(?:' + "|".join(EXT_SCRIPT) + r'))(?=$|[\s"\',;)\]])', re.I)
RE_GRAVAVEL = re.compile(r'\\(?:appdata\\local\\temp|windows\\temp|users\\public|\$recycle\.bin|downloads|perflogs)\\', re.I)
RE_AGENTE = re.compile(
    r'settings(?:\.local)?\.json|cowork_settings|\.claude\.json|claude_desktop_config|mcpservers|\.mcp\.json|'
    r'opencode\.jsonc?|[\\/]\.claude[\\/]+(?:hooks|skills|plugins|agents|commands)', re.I)
RE_SEGREDO = [
    (re.compile(r'((?:--?|/)(?:api[-_]?key|apikey|token|secret|password|passwd|auth(?:orization)?)\S*?(?:\s+|=|:))(\S+)', re.I), r'\1[SEGREDO OMITIDO]'),
    (re.compile(r'\b(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abpr]-[A-Za-z0-9-]{10,})'), '[SEGREDO OMITIDO]'),
]

S = r'[\\/]{1,2}'
RUNKEY = r'currentversion' + S + r'(?:run|policies' + S + r'explorer' + S + r'run)|winlogon|image file execution options|appinit_dlls'
CAT_REG = ("Registro", "Winlogon", "IFEO", "AppInit")
# (regex que TODAS precisam casar, pontos, motivo, cria_persistencia, tipos de artefato que o codigo cria)
# A 1a regex de cada regra e a que marca a LINHA que cria o artefato (usada na ligacao por nome curto e no --so-linhas).
# As regras rodam no texto original E no texto normalizado (sem aspas, virgulas, colchetes e parenteses), para pegar
# ["reg","add",r"HKCU\...\Run"], ["sc","create",...] e ["schtasks","/create",...] em subprocess/execFile/spawn.
# Fontes das regras: hunting-for-registry-run-key-persistence, hunting-for-scheduled-task-persistence,
# hunting-for-persistence-via-wmi-subscriptions, configuring-windows-defender-advanced-settings
# (github.com/mukul975/Anthropic-Cybersecurity-Skills), aplicadas ao CODIGO que um agente executa.
PADROES = [
    ([r'\breg(?:\.exe)?\s+add\b[^\r\n]*?(?:' + RUNKEY + r'|' + S + r'services' + S + r')'],
     4, 'grava chave de inicializacao no registro (reg add)', True, CAT_REG + ("Servico",)),
    ([r'new-itemproperty|set-itemproperty|\.setvalue(?:ex)?\b|setvalueex|winreg\.|regwrite|\bregistry\.set|\bnew-item\b', RUNKEY],
     4, 'grava valor em chave Run/RunOnce/Winlogon/IFEO', True, CAT_REG),
    ([RUNKEY, r'\b(?:add|set\w*|new-\w+|write\w*|create\w*|put\w*|regwrite)\b'],
     3, 'cita chave de inicializacao do registro (Run/Winlogon/IFEO) junto com verbo de escrita', True, CAT_REG),
    ([r'\bschtasks(?:\.exe)?\b[^\r\n]*?/create\b|register-scheduledtask|new-scheduledtaskaction|itaskservice|schedule\.service'],
     4, 'cria tarefa agendada', True, ("Tarefa",)),
    ([r'\bsc(?:\.exe)?\s+(?:create|config)\b|\bnew-service\b|\bcreateservice[aw]?\b'], 4, 'cria servico do Windows', True, ("Servico",)),
    ([r'__eventfilter|__filtertoconsumerbinding|commandlineeventconsumer|activescripteventconsumer|set-wmiinstance|\bmofcomp\b'],
     4, 'cria assinatura WMI', True, ("WMI", "WMI-Filtro")),
    ([r'start menu' + S + r'programs' + S + r'startup|shell:startup|getfolderpath\s*\(?\s*[\'"]?startup|specialfolder\.startup'],
     4, 'grava na pasta Inicializar', True, ("Inicializar",)),
    ([r'add-mppreference[^\r\n]*-exclusion|set-mppreference[^\r\n]*-disable|disableantispyware|disablerealtimemonitoring'],
     4, 'desliga ou cria excecao no Microsoft Defender', True, ()),
    ([r'downloadstring|downloadfile|invoke-webrequest|\biwr\b|invoke-restmethod|net\.webclient|start-bitstransfer|bitsadmin|certutil[^\r\n]*urlcache|urlretrieve'],
     2, 'baixa conteudo da internet', False, ()),
    ([r'(?<![\w-])-e(?:c|nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}|frombase64string|b64decode|base64\s+(?:-d|--decode)'],
     3, 'decodifica/executa conteudo em base64', False, ()),
    ([r'(?<![\w-])-w(?:indowstyle)?\s+h(?:idden)?\b|createnowindow'], 1, 'execucao com janela oculta', False, ()),
]
COMPILADOS = [([re.compile(r, re.I) for r in rs], p, m, c, ct) for rs, p, m, c, ct in PADROES]
EVENTOS_SESSAO = ("PreToolUse", "PostToolUse", "PostToolUseFailure", "UserPromptSubmit", "Stop", "SubagentStart",
                  "SubagentStop", "SessionStart", "SessionEnd", "PreCompact", "Notification", "statusLine")
COMENTARIO = {"py": "#", "pyw": "#", "ps1": "#", "psm1": "#", "sh": "#", "bash": "#", "bat": "REM", "cmd": "REM",
              "vbs": "'", "vbe": "'", "js": "//", "mjs": "//", "cjs": "//", "ts": "//"}
MARCA_LIMPEZA = "[domfantoch-esterminador-de-virus] linha que criava persistencia removida"
CHAVES_CMD = ("apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper")
ENV_PERIGOSAS = ("NODE_OPTIONS", "PYTHONSTARTUP", "PERL5OPT", "RUBYOPT", "BASH_ENV", "JAVA_TOOL_OPTIONS")
PULAR_DIRS = {"node_modules", ".git", "__pycache__", "_backups", ".venv", "venv", "logs", ".ruff_cache", ".mypy_cache", "dist", "build"}
TIPOS_HOOK_JSON = ("settings", "plugin_hooks", "plugin_json")
TIPOS_MCP = ("mcp", "settings", "claude_json", "desktop", "opencode", "vscode", "codex")


# ---------------------------------------------------------------- utilitarios
def ocultar_segredos(t):
    for r, s in RE_SEGREDO:
        t = r.sub(s, t)
    return t


def hash_cmd(c):
    return hashlib.sha256(" ".join(str(c).split()).lower().encode("utf-8", "replace")).hexdigest()


def extensao(p):
    return os.path.splitext(p)[1].lower().lstrip(".")


def eh_sistema(p):
    lp = str(p).lower().replace("/", "\\")
    return any(lp.startswith(s) for s in SISTEMA)


def chave(p):
    return os.path.normcase(os.path.abspath(str(p)))


def sem_comentarios(t):
    out, i, n, em_str = [], 0, len(t), False
    while i < n:
        c = t[i]
        if em_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(t[i + 1])
                i += 2
                continue
            if c == '"':
                em_str = False
            i += 1
            continue
        if c == '"':
            em_str = True
            out.append(c)
            i += 1
            continue
        if t.startswith("//", i):
            j = t.find("\n", i)
            i = n if j < 0 else j
            continue
        if t.startswith("/*", i):
            j = t.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        out.append(c)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def carregar(arquivo, tipo=""):
    """Devolve (dados, editavel, erro). editavel=False para JSON com comentarios e TOML."""
    try:
        bruto = Path(arquivo).read_bytes()
    except OSError as e:
        return None, False, "nao foi possivel ler: %s" % e
    txt = bruto.decode("utf-8-sig", "replace")
    if tipo == "codex":
        if tomllib is None:
            return None, False, "TOML exige Python 3.11+"
        try:
            return tomllib.loads(txt), False, ""
        except Exception as e:
            return None, False, "TOML invalido: %s" % e
    try:
        return json.loads(txt), True, ""
    except ValueError:
        pass
    try:
        return json.loads(sem_comentarios(txt)), False, ""
    except ValueError as e:
        return None, False, "JSON invalido: %s" % e


def ler_texto(p, limite=2000000):
    try:
        if os.path.getsize(p) > limite:
            return ""
        with open(p, "rb") as f:
            b = f.read()
    except OSError:
        return ""
    if b.startswith(b"\xff\xfe") or b.startswith(b"\xfe\xff"):
        return b.decode("utf-16", "replace")
    return b.decode("utf-8", "replace")


def expandir(txt, extra):
    amb = {k.lower(): v for k, v in os.environ.items()}
    amb.setdefault("home", str(HOME))
    for k, v in extra.items():
        amb[k.lower()] = v

    def sub(m):
        nome = m.group(1) or m.group(2) or m.group(3) or m.group(4)
        v = amb.get(nome.lower())
        return v if v is not None else m.group(0)

    txt = re.sub(r'%([A-Za-z_][A-Za-z0-9_()]*)%|\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$env:([A-Za-z_][A-Za-z0-9_]*)|\$([A-Za-z_][A-Za-z0-9_]*)', sub, txt)
    txt = re.sub(r'(^|[\s"\'=])~(?=[\\/])', lambda m: m.group(1) + str(HOME), txt)
    return txt


def caminhos(txt, base):
    brutos = []
    for m in RE_CAMINHO.finditer(txt):
        brutos.append(re.split(r'\s(?=[A-Za-z]:[\\/])', m.group(0))[-1])
    if base:
        for m in RE_RELATIVO.finditer(txt):
            brutos.append(str(Path(base) / m.group(1)))
    res, vistos = [], set()
    for s in brutos:
        p = os.path.normpath(s.replace("/", "\\"))
        if p.lower() in vistos:
            continue
        vistos.add(p.lower())
        res.append(p)
    return res


def normalizar(texto):
    """Tira aspas, virgulas, colchetes e parenteses: ["reg","add",r"HKCU\\..."] vira  reg add HKCU\\... ."""
    t = re.sub(r'(?<![A-Za-z0-9_])[rRbBuUfF]{1,2}(?=["\'])', ' ', texto)
    t = re.sub(r'["\'`\[\](),{}+;]', ' ', t)
    return re.sub(r'[ \t]+', ' ', t)


def avaliar(texto):
    """Pontos, motivos, se cria persistencia e os tipos de artefato que o codigo cria."""
    alvo = texto + "\n" + normalizar(texto)
    pts, mot, cria, cats = 0, [], False, set()
    for rs, p, m, c, ct in COMPILADOS:
        if all(r.search(alvo) for r in rs):
            pts += p
            mot.append(m)
            cria = cria or c
            cats.update(ct)
    return pts, mot, cria, cats


def cats_linha(linha):
    """Tipos de artefato que UMA linha cria (vazio se a linha nao cria persistencia)."""
    alvo = linha + "\n" + normalizar(linha)
    cats, achou = set(), False
    for rs, p, m, c, ct in COMPILADOS:
        if c and all(r.search(alvo) for r in rs):
            achou = True
            cats.update(ct)
    return achou, cats


def trechos(texto, maximo=40, prefixo=""):
    res, total = [], 0
    for n, linha in enumerate(texto.splitlines(), 1):
        if cats_linha(linha)[0]:
            total += 1
            if len(res) < maximo:
                res.append("%slinha %d: %s" % (prefixo, n, ocultar_segredos(linha.strip())))
    if total > maximo:
        res.append("(%s%d linhas no total; as demais estao no proprio arquivo)" % (prefixo, total))
    return res


def trechos_scripts(scripts):
    res = []
    for s in scripts:
        res += trechos(ler_texto(s), 20, s + " ")
    return res


def texto_origem(comando, base, extra):
    """Texto analisado (comando + scripts que ele chama + scripts chamados por esses), scripts, aninhados, ausentes, executaveis."""
    exp = expandir(comando, extra)
    partes = [comando] if exp == comando else [comando, exp]
    scripts, aninhados, ausentes, execs = [], [], [], []
    for p in caminhos(exp, base):
        if eh_sistema(p):
            continue
        e = extensao(p)
        nome = os.path.basename(p).lower()
        if e in EXT_BIN or nome in INTERPRETADORES:
            if nome not in INTERPRETADORES:
                execs.append(p)
            continue
        if not os.path.isfile(p):
            ausentes.append(p)
            continue
        scripts.append(p)
        t = ler_texto(p)
        partes.append(t)
        for p2 in caminhos(expandir(t, extra), os.path.dirname(p)):
            if eh_sistema(p2) or p2.lower() == p.lower() or extensao(p2) not in EXT_SCRIPT:
                continue
            if os.path.isfile(p2) and p2 not in aninhados and p2 not in scripts:
                aninhados.append(p2)
                partes.append(ler_texto(p2))
    return "\n".join(partes), scripts, aninhados, ausentes, execs


def _rx_token(t):
    return re.compile(r'(?<![A-Za-z0-9_])' + re.escape(t.lower()) + r'(?![A-Za-z0-9_])')


def ligar(texto, itens):
    """Liga o codigo ao artefato do sistema que ele cria.
    Nome forte (>= 5 caracteres; arquivo fora do sistema): basta aparecer no codigo, se o codigo cria aquele TIPO de artefato.
    Nome fraco (2 a 4 caracteres): tem de aparecer na MESMA linha que cria aquele tipo de artefato
    (ex.: reg add ...\\Run /v Upd /d notepad.exe). Executavel do sistema (notepad.exe, cmd.exe) nao serve de nome:
    varios artefatos usam o mesmo, e a ligacao seria falsa."""
    low = (texto + "\n" + normalizar(texto)).lower()
    _, _, _, cats_todas = avaliar(texto)
    linhas = []
    for l in low.splitlines():
        achou, cl = cats_linha(l)
        if achou and cl:
            linhas.append((l, cl))
    lig = []
    for it in itens:
        tipo = str(it.get("Tipo") or "")
        fortes, fracos = [], []
        tk = str(it.get("Token") or "").strip()
        if len(tk) >= 5:
            fortes.append(tk)
        elif len(tk) >= 2:
            fracos.append(tk)
        for c in (it.get("Carga"), it.get("Caminho")):
            if c and c != "-" and not eh_sistema(c):
                b = os.path.basename(str(c))
                if len(b) >= 5:
                    fortes.append(b)
                elif len(b) >= 3:
                    fracos.append(b)
        ok = tipo in cats_todas and any(_rx_token(t).search(low) for t in fortes)
        if not ok:
            ok = any(tipo in cl and _rx_token(t).search(l) for t in fracos for l, cl in linhas)
        if ok:
            lig.append(str(it.get("Id")))
    return lig


def ligar_origem(texto, itens, mot, por_tipo=True):
    """Ligacao por nome; se nada ligar e a origem roda sozinha a cada sessao (por_tipo), liga aos itens RECENTES do
    mesmo tipo que o codigo cria (evidencia mais fraca, dita no motivo)."""
    lig = ligar(texto, itens)
    if lig or not por_tipo:
        return lig
    _, _, cria, cats = avaliar(texto)
    if not cria or not cats:
        return []
    rec = [str(it.get("Id")) for it in itens if it.get("Recente") and str(it.get("Tipo") or "") in cats]
    if rec:
        mot.append("ligacao por tipo e data (o nome do artefato nao aparece no codigo; o codigo cria %s e estes itens sao recentes): %s"
                   % ("/".join(sorted(cats)), ", ".join(rec)))
    return rec


def pegar(obj, cam):
    for k in cam:
        obj = obj[k]
    return obj


def andar(obj, cam):
    if isinstance(obj, dict):
        if isinstance(obj.get("command"), str):
            yield cam, obj
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                for x in andar(v, cam + [k]):
                    yield x
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, (dict, list)):
                for x in andar(v, cam + [i]):
                    yield x


# ---------------------------------------------------------------- onde estao as configuracoes
def listar_configs(raizes_extra, sem_home):
    lista, vistos = [], set()

    def add(p, agente, tipo, base, **kw):
        p = Path(p)
        if not p.is_file() or chave(p) in vistos:
            return
        vistos.add(chave(p))
        d = {"arquivo": str(p), "agente": agente, "tipo": tipo, "base": str(base)}
        d.update(kw)
        lista.append(d)

    homes = ([] if sem_home else [HOME]) + [Path(r) for r in raizes_extra]
    projetos = set()
    for h in homes:
        c = h / ".claude"
        for n in ("settings.json", "settings.local.json", "cowork_settings.json"):
            add(c / n, "Claude Code", "settings", h)
        add(h / ".claude.json", "Claude Code", "claude_json", h)
        add(h / ".mcp.json", "Claude Code", "mcp", h)
        add(h / ".gemini" / "settings.json", "Gemini CLI", "settings", h)
        add(h / ".cursor" / "mcp.json", "Cursor", "mcp", h)
        add(h / ".cursor" / "hooks.json", "Cursor", "settings", h)
        add(h / ".codeium" / "windsurf" / "mcp_config.json", "Windsurf", "mcp", h)
        for n in ("opencode.json", "opencode.jsonc"):
            add(h / ".config" / "opencode" / n, "OpenCode", "opencode", h)
        add(h / ".codex" / "config.toml", "Codex", "codex", h)
        dados, _, _ = carregar(h / ".claude.json")
        if isinstance(dados, dict) and isinstance(dados.get("projects"), dict):
            for k in dados["projects"]:
                projetos.add(str(k))
        # plugins do Claude Code instalados (installed_plugins.json + cache)
        raizes_plugin = {}
        ip, _, _ = carregar(c / "plugins" / "installed_plugins.json")
        if isinstance(ip, dict) and isinstance(ip.get("plugins"), dict):
            for nome, ents in ip["plugins"].items():
                for e in (ents if isinstance(ents, list) else [ents]):
                    if isinstance(e, dict) and e.get("installPath"):
                        raizes_plugin[chave(e["installPath"])] = (str(e["installPath"]), str(nome))
        cache = c / "plugins" / "cache"
        if cache.is_dir():
            for hj in cache.rglob("hooks.json"):
                if hj.parent.name == "hooks":
                    r = hj.parent.parent
                    raizes_plugin.setdefault(chave(r), (str(r), ""))
        for _, (r, nome) in sorted(raizes_plugin.items()):
            rp = Path(r)
            pj, _, _ = carregar(rp / ".claude-plugin" / "plugin.json")
            if not nome and isinstance(pj, dict):
                nome = str(pj.get("name") or "")
            nome = nome or rp.name
            add(rp / "hooks" / "hooks.json", "Claude Code plugin " + nome, "plugin_hooks", rp, plugin=nome, plugin_raiz=str(rp))
            add(rp / ".claude-plugin" / "plugin.json", "Claude Code plugin " + nome, "plugin_json", rp, plugin=nome, plugin_raiz=str(rp))
            add(rp / ".mcp.json", "Claude Code plugin " + nome, "mcp", rp, plugin=nome, plugin_raiz=str(rp))
    if not sem_home:
        projetos.add(os.getcwd())
    for pr in sorted(projetos):
        pp = Path(pr)
        if not pp.is_dir():
            continue
        add(pp / ".claude" / "settings.json", "Claude Code (projeto)", "settings", pp)
        add(pp / ".claude" / "settings.local.json", "Claude Code (projeto)", "settings", pp)
        add(pp / ".mcp.json", "Claude Code (projeto)", "mcp", pp)
        add(pp / ".cursor" / "mcp.json", "Cursor (projeto)", "mcp", pp)
        add(pp / "opencode.json", "OpenCode (projeto)", "opencode", pp)
    if not sem_home:
        cd = LOCALAPPDATA / "Claude-Data"
        if cd.is_dir():
            for p in cd.glob("*/claude_desktop_config.json"):
                add(p, "Claude Desktop", "desktop", p.parent)
        add(APPDATA / "Claude" / "claude_desktop_config.json", "Claude Desktop", "desktop", APPDATA / "Claude")
        add(APPDATA / "Code" / "User" / "mcp.json", "VS Code", "vscode", APPDATA / "Code" / "User")
        for b in (PROGRAMDATA / "ClaudeCode", Path(r"C:\Program Files\ClaudeCode")):
            add(b / "managed-settings.json", "Claude Code (gerenciado)", "settings", b)
            add(b / "managed-mcp.json", "Claude Code (gerenciado)", "mcp", b)
    return lista, sorted(projetos), homes


def arquivos_instrucao(homes, projetos):
    res = []
    for h in homes:
        res += [h / ".claude" / "CLAUDE.md", h / ".config" / "opencode" / "AGENTS.md", h / ".codex" / "AGENTS.md", h / ".gemini" / "GEMINI.md"]
    for pr in projetos:
        pp = Path(pr)
        res += [pp / "CLAUDE.md", pp / ".claude" / "CLAUDE.md", pp / "CLAUDE.local.md", pp / "AGENTS.md", pp / "GEMINI.md"]
    out, vistos = [], set()
    for p in res:
        if p.is_file() and chave(p) not in vistos:
            vistos.add(chave(p))
            out.append(p)
    return out


def dirs_codigo(homes, projetos):
    res = []
    for h in homes:
        for d in ("hooks", "skills", "agents", "commands"):
            res.append(h / ".claude" / d)
        res.append(h / ".claude" / "plugins" / "cache")
    for pr in projetos:
        for d in ("hooks", "skills", "agents", "commands"):
            res.append(Path(pr) / ".claude" / d)
    return [d for d in res if d.is_dir()]


def yaml_escalar(v):
    v = v.strip()
    if len(v) >= 2 and v[0] == "'" and v[-1] == "'":
        return v[1:-1].replace("''", "'")
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"' and '"' not in v[1:-1].replace('\\"', ''):
        return v[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return v


def frontmatter(linhas):
    """Indice da linha que fecha o frontmatter YAML (--- ... ---) ou -1."""
    if not linhas or linhas[0].lstrip("\ufeff").strip() != "---":
        return -1
    for i in range(1, len(linhas)):
        if linhas[i].strip() == "---":
            return i
    return -1


def bloco_hooks(linhas, fim):
    """(inicio, fim_exclusivo) do bloco 'hooks:' de nivel 0 dentro do frontmatter, ou None."""
    for i in range(1, fim):
        if re.match(r'^hooks\s*:', linhas[i]):
            j = i + 1
            while j < fim and (not linhas[j].strip() or linhas[j][0] in (" ", "\t") or linhas[j].lstrip().startswith("#")):
                j += 1
            return i, j
    return None


def md_executavel(p):
    """So SKILL.md e os .md de agents/ e commands/ sao carregados como skill/agente/comando (referencias nao)."""
    partes = [x.lower() for x in Path(p).parts]
    return os.path.basename(str(p)).lower() == "skill.md" or "agents" in partes[:-1] or "commands" in partes[:-1]


def comandos_md(texto, inline=True):
    """Comandos que um .md de skill/agente/comando executa sozinho: 'command:' dentro do bloco 'hooks:' do
    frontmatter (escalar simples, entre aspas ou bloco | / >) e, com inline=True, !`comando` no inicio da linha ou
    depois de espaco (executado ao carregar)."""
    res = []
    linhas = texto.splitlines()
    fim = frontmatter(linhas)
    if fim > 0:
        b = bloco_hooks(linhas, fim)
        if b:
            i = b[0] + 1
            while i < b[1]:
                m = re.match(r'^(\s*)(?:-\s*)?command\s*:\s*(.*?)\s*$', linhas[i])
                if m:
                    v = m.group(2)
                    if v in ("|", ">", "|-", ">-", "|+", ">+"):
                        ind = len(linhas[i]) - len(linhas[i].lstrip())
                        partes, j = [], i + 1
                        while j < b[1] and (not linhas[j].strip() or len(linhas[j]) - len(linhas[j].lstrip()) > ind):
                            partes.append(linhas[j].strip())
                            j += 1
                        sep = " " if v.startswith(">") else "\n"
                        v = sep.join(x for x in partes if x)
                    else:
                        v = yaml_escalar(re.sub(r'\s+#.*$', '', v) if not v.startswith(("'", '"')) else v)
                    if v:
                        res.append((i + 1, "hook no frontmatter", v))
                i += 1
    if not inline:
        return res
    for i, l in enumerate(linhas, 1):
        for m in re.finditer(r'(?:^|(?<=\s))!`([^`\r\n]+)`', l):
            if re.search(r'[A-Za-z]{2}', m.group(1)):
                res.append((i, "comando inline !`...`", m.group(1)))
    return res


def base_agente(p, homes, projetos):
    """Pasta que o agente usa como CLAUDE_PROJECT_DIR para um arquivo dentro de <base>\\.claude\\..."""
    kp = chave(p)
    for b in [str(h) for h in homes] + list(projetos):
        kb = chave(Path(b) / ".claude") + os.sep
        if kp.startswith(kb):
            return str(b)
    return str(HOME)


def dirs_plugin_opencode(homes, projetos):
    res = []
    for h in homes:
        res += [h / ".config" / "opencode" / "plugin", h / ".config" / "opencode" / "plugins"]
    for pr in projetos:
        res += [Path(pr) / ".opencode" / "plugin", Path(pr) / ".opencode" / "plugins"]
    return [d for d in res if d.is_dir()]


# ---------------------------------------------------------------- entradas dentro de cada configuracao
def vars_cfg(cfg):
    v = {"CLAUDE_PROJECT_DIR": cfg["base"]}
    if cfg.get("plugin_raiz"):
        v["CLAUDE_PLUGIN_ROOT"] = cfg["plugin_raiz"]
    return v


def entradas_hook(cfg, dados):
    res = []
    if not isinstance(dados, dict):
        return res
    if cfg["tipo"] in TIPOS_HOOK_JSON:
        h = dados.get("hooks")
        if isinstance(h, (dict, list)):
            for cam, d in andar(h, ["hooks"]):
                ev = str(cam[1]) if len(cam) > 1 else "hooks"
                mt = ""
                if len(cam) >= 5 and cam[3] == "hooks":
                    try:
                        g = pegar(dados, cam[:3])
                        if isinstance(g, dict):
                            mt = str(g.get("matcher", ""))
                    except Exception:
                        pass
                cmd = d["command"]
                if isinstance(d.get("args"), list) and d["args"]:
                    cmd = cmd + " " + " ".join(str(x) for x in d["args"])
                res.append({"caminho": cam, "comando": cmd, "evento": ev, "matcher": mt})
        sl = dados.get("statusLine")
        if isinstance(sl, dict) and isinstance(sl.get("command"), str):
            res.append({"caminho": ["statusLine"], "comando": sl["command"], "evento": "statusLine", "matcher": ""})
        for k in CHAVES_CMD:
            if isinstance(dados.get(k), str) and dados[k].strip():
                res.append({"caminho": [k], "comando": dados[k], "evento": k, "matcher": ""})
        env = dados.get("env")
        if isinstance(env, dict):
            for k, v in env.items():
                if str(k).upper() in ENV_PERIGOSAS and isinstance(v, str) and v.strip():
                    res.append({"caminho": ["env", k], "comando": "%s=%s" % (k, v), "evento": "env." + str(k), "matcher": ""})
    if cfg["tipo"] == "codex":
        n = dados.get("notify")
        if isinstance(n, list) and n:
            res.append({"caminho": ["notify"], "comando": " ".join(str(x) for x in n), "evento": "notify", "matcher": ""})
        elif isinstance(n, str) and n.strip():
            res.append({"caminho": ["notify"], "comando": n, "evento": "notify", "matcher": ""})
    return res


def entradas_mcp(cfg, dados):
    res = []
    if not isinstance(dados, dict) or cfg["tipo"] not in TIPOS_MCP:
        return res

    def ler(cam, cont, nivel=0):
        if not isinstance(cont, dict):
            return
        for nome, d in cont.items():
            if not isinstance(d, dict):
                continue
            cmd = d.get("command") or d.get("url") or d.get("serverUrl") or ""
            if not cmd and nivel == 0 and d and all(isinstance(v, dict) for v in d.values()):
                ler(cam + [nome], d, 1)  # ex.: opencode.json com "mcp": {"servers": {...}}
                continue
            if isinstance(cmd, list):
                cmd = " ".join(str(x) for x in cmd)
            args = d.get("args")
            if isinstance(args, list):
                cmd = (str(cmd) + " " + " ".join(str(a) for a in args)).strip()
            res.append({"caminho": cam + [nome], "nome": str(nome), "comando": str(cmd)})

    t = cfg["tipo"]
    if t in ("mcp", "settings", "claude_json", "desktop"):
        ler(["mcpServers"], dados.get("mcpServers"))
    if t == "claude_json" and isinstance(dados.get("projects"), dict):
        for p, v in dados["projects"].items():
            if isinstance(v, dict):
                ler(["projects", p, "mcpServers"], v.get("mcpServers"))
    if t == "opencode":
        ler(["mcp"], dados.get("mcp"))
    if t == "vscode":
        ler(["servers"], dados.get("servers"))
    if t == "codex":
        ler(["mcp_servers"], dados.get("mcp_servers"))
    return res


def pasta_skill(scripts, homes):
    for s in scripts:
        for h in homes:
            base = chave(h / ".claude" / "skills") + os.sep
            ks = chave(s)
            if ks.startswith(base):
                nome = ks[len(base):].split(os.sep)[0]
                return str(h / ".claude" / "skills" / nome)
    return ""


def dirs_instaladores(homes):
    """Pastas de primeiro nivel do perfil com 'mcp' no nome (ex.: um instalador/vigia proprio que reinjeta configuracao
    de servidores MCP). So existem em alguns computadores; se nao houver nenhuma, nada e lido."""
    res = []
    for h in homes:
        try:
            filhos = sorted(Path(h).iterdir())
        except OSError:
            continue
        for d in filhos:
            nome = d.name.lower()
            if d.is_dir() and "mcp" in nome and nome not in (".claude", ".cursor", ".codeium", ".config", ".vscode"):
                res.append(d)
    return res


def indice_reinjetores(homes):
    """Linhas de arquivos de instaladores que reinjetam configuracao de MCP (pastas de dirs_instaladores)."""
    linhas = []
    for d in dirs_instaladores(homes):
        n = 0
        for raiz, dns, fns in os.walk(d):
            dns[:] = [x for x in dns if x.lower() not in PULAR_DIRS and x.lower() not in ("pw-browsers", "puppeteer-install", "samples", "reports")]
            for f in fns:
                p = os.path.join(raiz, f)
                if extensao(p) not in EXT_SCRIPT + ("json", "txt", "toml", "yaml", "yml"):
                    continue
                n += 1
                if n > 3000:
                    break
                for i, l in enumerate(ler_texto(p, 1000000).splitlines(), 1):
                    linhas.append((p, i, l))
    return linhas


# ---------------------------------------------------------------- copias desta skill
def sha256_arquivo(p):
    h = hashlib.sha256()
    try:
        with open(longo(p), "rb") as f:
            for bloco in iter(lambda: f.read(1048576), b""):
                h.update(bloco)
    except OSError:
        return ""
    return h.hexdigest()


def hashes_desta_skill():
    """Nome do arquivo -> SHA256 dos arquivos da skill em execucao (fora logs/_backups/_teste). Um arquivo de outra pasta
    com o MESMO nome e o MESMO SHA256 e copia desta ferramenta (ex.: repositorio clonado duas vezes), nao codigo malicioso.
    So hash identico conta: marcador em comentario poderia ser copiado por um malware."""
    raiz = Path(__file__).resolve().parent.parent
    res = {}
    for r, dns, fns in os.walk(raiz):
        dns[:] = [x for x in dns if x.lower() not in ("logs", "_backups", "_teste", "__pycache__", ".git")]
        for f in fns:
            res.setdefault(f.lower(), set()).add(sha256_arquivo(os.path.join(r, f)))
    return res


def copia_da_skill(p, hashes):
    hs = hashes.get(os.path.basename(str(p)).lower())
    return bool(hs) and sha256_arquivo(p) in hs


# ---------------------------------------------------------------- varrer
def novo_item(**kw):
    base = {"Tipo": "", "Agente": "", "Nome": "", "Local": "", "Comando": "", "Caminho": "-", "Pontos": 0, "Motivos": "",
            "LigadoA": [], "Removivel": True, "Evento": "", "Scripts": [], "ScriptsAninhados": [], "Executaveis": [],
            "HashComando": "", "PastaSkill": "", "Plugin": "", "PluginRaiz": "", "NomeServidor": "", "Reinjetores": [],
            "Trechos": [], "Editavel": True, "ArquivoMd": "", "LinhaMd": 0}
    base.update(kw)
    return base


def varrer(a):
    itens_persist = []
    if a.itens and os.path.isfile(a.itens):
        try:
            d = json.loads(Path(a.itens).read_text(encoding="utf-8-sig"))
            itens_persist = d if isinstance(d, list) else ([d] if isinstance(d, dict) else [])
        except ValueError as e:
            print("itens invalidos: %s" % e, file=sys.stderr)  # scroll-ok: erro unico no stderr, lido pelo varrer.ps1
    ignorar = [chave(x) for x in a.ignorar]
    extras = [chave(x) for x in a.raiz_extra]

    def ignorado(p, eh_dir=False):
        k = chave(p)
        # pasta pedida com --raiz-extra (ex.: perfil falso do teste dentro da pasta da skill) nunca e ignorada;
        # a pasta que a contem continua sendo percorrida (eh_dir), mas os arquivos dela continuam ignorados
        if any(k == e or k.startswith(e + os.sep) for e in extras):
            return False
        if eh_dir and any(e.startswith(k + os.sep) for e in extras):
            return False
        return any(k == i or k.startswith(i + os.sep) for i in ignorar)

    t0 = time.time()
    configs, projetos, homes = listar_configs(a.raiz_extra, a.sem_home)
    out = {"Itens": [], "Reinjetores": {}, "ErrosLeitura": [], "ArquivosLidos": [], "Projetos": len(projetos),
           "Homes": [str(h) for h in homes], "CopiasDaSkill": []}
    hashes_skill = hashes_desta_skill()
    copias = set()
    referenciados = set()
    linhas_reinj = None
    for cfg in configs:
        dados, editavel, err = carregar(cfg["arquivo"], cfg["tipo"])
        if err:
            out["ErrosLeitura"].append("%s: %s" % (cfg["arquivo"], err))
            continue
        out["ArquivosLidos"].append(cfg["arquivo"])
        for e in entradas_hook(cfg, dados):
            texto, scripts, anin, aus, execs = texto_origem(e["comando"], cfg["base"], vars_cfg(cfg))
            for s in scripts + anin:
                referenciados.add(chave(s))
            pts, mot, cria, _ = avaliar(texto)
            if aus:
                pts += 1
                mot.append("script chamado pelo comando nao existe: " + " | ".join(aus))
            for s in scripts + execs:
                if RE_GRAVAVEL.search(s):
                    pts += 2
                    mot.append("arquivo em pasta temporaria/gravavel: " + s)
            lig = ligar_origem(texto, itens_persist, mot) if cria else []
            if lig:
                pts += 4
                mot.append("o codigo deste comando cria persistencia que esta no sistema agora: " + ", ".join(lig))
            if e["evento"].startswith("env."):
                pts += 1
                mot.append("variavel de ambiente que injeta codigo em todo processo do agente")
            tipo = "HookPlugin" if cfg["tipo"] in ("plugin_hooks", "plugin_json") else "HookAgente"
            nome = e["evento"] + (" [matcher=" + e["matcher"] + "]" if e["matcher"] else "")
            out["Itens"].append(novo_item(
                Tipo=tipo, Agente=cfg["agente"], Nome=nome, Local=cfg["arquivo"], Comando=ocultar_segredos(e["comando"]),
                Caminho=(scripts[0] if scripts else "-"), Pontos=pts, Motivos="; ".join(mot), LigadoA=lig,
                Removivel=True, Evento=e["evento"], Scripts=scripts, ScriptsAninhados=anin, Executaveis=execs,
                HashComando=hash_cmd(e["comando"]), PastaSkill=pasta_skill(scripts, homes),
                Plugin=cfg.get("plugin", ""), PluginRaiz=cfg.get("plugin_raiz", ""), Editavel=editavel,
                Trechos=(trechos(e["comando"], 5, "comando ") + trechos_scripts(scripts + anin)) if cria else []))
        for e in entradas_mcp(cfg, dados):
            texto, scripts, anin, aus, execs = texto_origem(e["comando"], cfg["base"], vars_cfg(cfg))
            for s in scripts + anin:
                referenciados.add(chave(s))
            pts, mot, cria, _ = avaliar(texto)
            if aus:
                pts += 1
                mot.append("script chamado pelo servidor MCP nao existe: " + " | ".join(aus))
            for s in scripts + execs:
                if RE_GRAVAVEL.search(s):
                    pts += 2
                    mot.append("arquivo em pasta temporaria/gravavel: " + s)
            lig = ligar_origem(texto, itens_persist, mot) if cria else []
            if lig:
                pts += 4
                mot.append("o codigo deste servidor MCP cria persistencia que esta no sistema agora: " + ", ".join(lig))
            if linhas_reinj is None:
                linhas_reinj = indice_reinjetores(homes)
            reinj = []
            if len(e["nome"]) >= 3:
                rx = re.compile(r'(?<![A-Za-z0-9_-])' + re.escape(e["nome"]) + r'(?![A-Za-z0-9_-])', re.I)
                for p, i, l in linhas_reinj:
                    if rx.search(l):
                        reinj.append("%s:%d: %s" % (p, i, ocultar_segredos(l.strip())))
            out["Itens"].append(novo_item(
                Tipo="McpAgente", Agente=cfg["agente"], Nome=e["nome"], Local=cfg["arquivo"] + " -> " + "/".join(str(x) for x in e["caminho"]),
                Comando=ocultar_segredos(e["comando"]), Caminho=(scripts[0] if scripts else "-"), Pontos=pts,
                Motivos="; ".join(mot), LigadoA=lig, Removivel=True, Evento="inicio de sessao (servidor MCP)",
                Scripts=scripts, ScriptsAninhados=anin, Executaveis=execs, HashComando=hash_cmd(e["comando"]),
                NomeServidor=e["nome"], Plugin=cfg.get("plugin", ""), PluginRaiz=cfg.get("plugin_raiz", ""),
                Reinjetores=reinj, Editavel=editavel))
    # plugins do OpenCode: carregados a cada sessao
    for d in dirs_plugin_opencode(homes, projetos):
        for f in sorted(d.iterdir()):
            if not f.is_file() or extensao(str(f)) not in ("js", "mjs", "cjs", "ts"):
                continue
            texto = ler_texto(str(f))
            pts, mot, cria, _ = avaliar(texto)
            lig = ligar_origem(texto, itens_persist, mot) if cria else []
            if lig:
                pts += 4
                mot.append("o codigo deste plugin cria persistencia que esta no sistema agora: " + ", ".join(lig))
            mot.insert(0, "plugin do OpenCode carregado a cada sessao")
            out["Itens"].append(novo_item(
                Tipo="PluginAgente", Agente="OpenCode", Nome=f.name, Local=str(f), Comando=str(f), Caminho=str(f),
                Pontos=pts, Motivos="; ".join(mot), LigadoA=lig, Removivel=True, Evento="inicio de sessao (plugin)",
                Scripts=[str(f)], Trechos=trechos(texto) if cria else []))
            referenciados.add(chave(f))
    # arquivos de hooks/skills/agents/commands/plugins (uma lista so, usada pelas duas passagens abaixo)
    arquivos_cod, vistos_cod = [], set()
    for d in dirs_codigo(homes, projetos):
        if ignorado(d, True):
            continue
        for raiz, dns, fns in os.walk(d):
            dns[:] = [x for x in dns if x.lower() not in PULAR_DIRS and not ignorado(os.path.join(raiz, x), True)]
            for f in fns:
                p = os.path.join(raiz, f)
                if len(arquivos_cod) >= 60000 or chave(p) in vistos_cod or ignorado(p):
                    continue
                vistos_cod.add(chave(p))
                arquivos_cod.append(p)
    # 1a passagem: hooks no frontmatter de SKILL.md / agents/*.md / commands/*.md e comandos inline !`cmd`.
    # Rodam sozinhos quando a skill/agente/comando e carregado: sao origem de reinstalacao como um hook do settings.json.
    for p in arquivos_cod:
        if extensao(p) != "md":
            continue
        if copia_da_skill(p, hashes_skill):
            copias.add(os.path.dirname(p) if os.path.basename(p).lower() == "skill.md" else os.path.dirname(os.path.dirname(p)))
            continue
        txt_md = ler_texto(p, 1000000)
        if "command" not in txt_md and "!`" not in txt_md:
            continue
        base_md = base_agente(p, homes, projetos)
        extra_md = {"CLAUDE_PROJECT_DIR": base_md, "CLAUDE_SKILL_DIR": os.path.dirname(p),
                    "CLAUDE_PLUGIN_ROOT": os.path.dirname(p)}
        for nlinha, ev, cmd in comandos_md(txt_md, md_executavel(p)):
            texto, scripts, anin, aus, execs = texto_origem(cmd, base_md, extra_md)
            for s in scripts + anin:
                referenciados.add(chave(s))
            pts, mot, cria, _ = avaliar(texto)
            pts += 1
            mot.insert(0, "comando que roda sozinho quando a skill/agente/comando e carregado (%s, linha %d do .md)" % (ev, nlinha))
            if aus:
                pts += 1
                mot.append("script chamado pelo comando nao existe: " + " | ".join(aus))
            for s in scripts + execs:
                if RE_GRAVAVEL.search(s):
                    pts += 2
                    mot.append("arquivo em pasta temporaria/gravavel: " + s)
            lig = ligar_origem(texto, itens_persist, mot) if cria else []
            if lig:
                pts += 4
                mot.append("o codigo deste comando cria persistencia que esta no sistema agora: " + ", ".join(lig))
            out["Itens"].append(novo_item(
                Tipo="HookAgente", Agente="Claude Code (hook em .md)", Nome="%s (linha %d)" % (ev, nlinha), Local=p,
                Comando=ocultar_segredos(cmd), Caminho=(scripts[0] if scripts else "-"), Pontos=pts, Motivos="; ".join(mot),
                LigadoA=lig, Removivel=True, Evento=ev, Scripts=scripts, ScriptsAninhados=anin, Executaveis=execs,
                HashComando=hash_cmd(cmd), PastaSkill=pasta_skill([p], homes), ArquivoMd=p, LinhaMd=nlinha,
                Trechos=(trechos(cmd, 5, "comando ") + trechos_scripts(scripts + anin)) if cria else []))
    # 2a passagem: codigo em hooks/skills/agents/commands que cria persistencia (so roda se for chamado)
    n = 0
    for p in arquivos_cod:
        if extensao(p) not in EXT_SCRIPT or chave(p) in referenciados:
            continue
        if copia_da_skill(p, hashes_skill):
            copias.add(os.path.dirname(os.path.dirname(p)) if os.path.basename(os.path.dirname(p)).lower() == "scripts" else os.path.dirname(p))
            continue
        n += 1
        if n > 30000:
            break
        texto = ler_texto(p)
        pts, mot, cria, _ = avaliar(texto)
        if not cria:
            continue
        lig = ligar_origem(texto, itens_persist, mot, por_tipo=False)
        if lig:
            pts += 4
            mot.append("o codigo deste arquivo cria persistencia que esta no sistema agora: " + ", ".join(lig))
        mot.insert(0, "codigo de agente que cria persistencia (so roda se um hook, skill ou o agente chamar)")
        out["Itens"].append(novo_item(
            Tipo="CodigoAgente", Agente="arquivos de agente", Nome=os.path.basename(p), Local=p, Comando=p,
            Caminho=p, Pontos=max(pts - 2, 1), Motivos="; ".join(mot), LigadoA=lig, Removivel=True,
            Evento="sob demanda", Scripts=[p], PastaSkill=pasta_skill([p], homes), Trechos=trechos(texto)))
    # instrucoes carregadas em toda sessao (CLAUDE.md, AGENTS.md, GEMINI.md)
    for p in arquivos_instrucao(homes, projetos):
        texto = ler_texto(str(p))
        pts, mot, cria, _ = avaliar(texto)
        if not cria:
            continue
        lig = ligar_origem(texto, itens_persist, mot, por_tipo=False)
        if lig:
            pts += 4
            mot.append("instrucao que cria persistencia que esta no sistema agora: " + ", ".join(lig))
        mot.insert(0, "instrucao lida pelo agente em toda sessao e que manda criar persistencia")
        out["Itens"].append(novo_item(
            Tipo="CodigoAgente", Agente="instrucoes do agente", Nome=p.name, Local=str(p), Comando=str(p), Caminho=str(p),
            Pontos=pts, Motivos="; ".join(mot), LigadoA=lig, Removivel=False, Evento="inicio de sessao (instrucao)",
            Scripts=[], Trechos=trechos(texto)))
    # persistencia cujo script mexe em configuracao de agente (vigia que reinjeta hook/MCP)
    for it in itens_persist:
        for c in (it.get("Carga"), it.get("Caminho")):
            if not c or c == "-" or eh_sistema(c) or extensao(str(c)) not in EXT_SCRIPT or not os.path.isfile(str(c)):
                continue
            t = ler_texto(str(c))
            m = RE_AGENTE.search(t)
            if m:
                ini = t.rfind("\n", 0, m.start()) + 1
                fim = t.find("\n", m.start())
                linha = t[ini:(fim if fim >= 0 else len(t))].strip()
                nl = t.count("\n", 0, m.start()) + 1
                out["Reinjetores"].setdefault(str(it.get("Id")), []).append(
                    "o script %s mexe em configuracao de agente de IA (linha %d: %s)" % (c, nl, ocultar_segredos(linha)))
    out["CopiasDaSkill"] = sorted(copias)
    out["DuracaoSeg"] = round(time.time() - t0, 1)
    Path(a.saida).write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


# ---------------------------------------------------------------- remover
def nome_seguro(t, n=70):
    s = re.sub(r"[^A-Za-z0-9._-]", "_", str(t))
    if len(s) <= n:
        return s
    return hashlib.sha1(str(t).encode("utf-8", "replace")).hexdigest()[:8] + "_" + s[-n:]


def longo(p):
    """Prefixo \\\\?\\ no Windows para caminho perto do limite de 260 caracteres."""
    p = os.path.abspath(str(p))
    if os.name == "nt" and len(p) >= 240 and not p.startswith("\\\\"):
        return "\\\\?\\" + p
    return p


def backup_arquivo(arquivo, bk):
    d = Path(bk) / "agentes"
    os.makedirs(longo(d), exist_ok=True)
    dest = d / nome_seguro(arquivo)
    i = 1
    while os.path.exists(longo(dest)):
        dest = d / (nome_seguro(arquivo) + "_%d" % i)
        i += 1
    shutil.copy2(longo(arquivo), longo(dest))
    return str(dest)


def quarentena(p, bk):
    d = Path(bk) / "quarentena"
    os.makedirs(longo(d), exist_ok=True)
    base = os.path.basename(str(p).rstrip("\\/"))
    dest = d / (nome_seguro(base) + ".quarentena")
    i = 1
    while os.path.exists(longo(dest)):
        dest = d / (nome_seguro(base) + "_%d.quarentena" % i)
        i += 1
    shutil.move(longo(p), longo(dest))
    if os.path.exists(longo(p)):
        raise RuntimeError("continua no lugar depois de mover: %s" % p)
    return str(dest)


def gravar_json(arquivo, dados, bk):
    bkp = backup_arquivo(arquivo, bk)
    tmp = longo(str(arquivo) + ".tmp-domfantoch")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(dados, f, indent=2, ensure_ascii=False)
        f.write("\n")
    with open(tmp, encoding="utf-8") as f:
        json.load(f)  # valida ANTES de trocar o original
    os.replace(tmp, longo(arquivo))
    with open(longo(arquivo), encoding="utf-8") as f:
        json.load(f)  # valida DEPOIS de gravar
    return bkp


def ordem(c):
    return [(0, x) if isinstance(x, int) else (1, str(x)) for x in c]


def apagar_caminhos(dados, cams):
    for c in sorted(cams, key=ordem, reverse=True):
        pai = pegar(dados, c[:-1])
        if isinstance(pai, list):
            del pai[c[-1]]
        elif isinstance(pai, dict):
            pai.pop(c[-1], None)
    h = dados.get("hooks") if isinstance(dados, dict) else None
    if isinstance(h, dict):
        for ev in list(h.keys()):
            lst = h[ev]
            if isinstance(lst, list):
                h[ev] = [g for g in lst if not (isinstance(g, dict) and isinstance(g.get("hooks"), list) and not g["hooks"])]
                if not h[ev]:
                    del h[ev]


def remover_hooks(alvo_hash, alvo_scripts, configs, bk):
    """Tira de todas as configuracoes as entradas com o mesmo comando ou que chamam os mesmos scripts."""
    editados, pend = [], []
    alvo_scripts = set(chave(s) for s in alvo_scripts)

    def casa(cfg, e):
        if alvo_hash and hash_cmd(e["comando"]) == alvo_hash:
            return True
        if alvo_scripts:
            _, sc, _, _, _ = texto_origem(e["comando"], cfg["base"], vars_cfg(cfg))
            return bool(set(chave(s) for s in sc) & alvo_scripts)
        return False

    for cfg in configs:
        if cfg["tipo"] not in TIPOS_HOOK_JSON + ("codex",):
            continue
        dados, editavel, err = carregar(cfg["arquivo"], cfg["tipo"])
        if err:
            continue
        alvos = [e for e in entradas_hook(cfg, dados) if casa(cfg, e)]
        if not alvos:
            continue
        if not editavel:
            pend.append("%s: %s (arquivo com comentarios/TOML: editar com a ferramenta Edit, com backup antes)" % (
                cfg["arquivo"], " | ".join("/".join(str(x) for x in e["caminho"]) for e in alvos)))
            continue
        apagar_caminhos(dados, [e["caminho"] for e in alvos])
        bkp = gravar_json(cfg["arquivo"], dados, bk)
        editados.append("%s (%d entrada(s): %s; backup %s)" % (
            cfg["arquivo"], len(alvos), " | ".join(e["evento"] for e in alvos), bkp))
    # conferencia: nada pode sobrar
    sobra = []
    for cfg in configs:
        if cfg["tipo"] not in TIPOS_HOOK_JSON:
            continue
        dados, _, err = carregar(cfg["arquivo"], cfg["tipo"])
        if err:
            continue
        for e in entradas_hook(cfg, dados):
            if casa(cfg, e):
                sobra.append("%s -> %s" % (cfg["arquivo"], e["evento"]))
    return editados, pend, sobra


def ler_linhas(p):
    """Linhas com o fim de linha original e a codificacao usada (utf-8, utf-8-sig ou utf-16)."""
    b = Path(longo(p)).read_bytes()
    if b.startswith(b"\xff\xfe") or b.startswith(b"\xfe\xff"):
        cod = "utf-16"
    elif b.startswith(b"\xef\xbb\xbf"):
        cod = "utf-8-sig"
    else:
        cod = "utf-8"
    return b.decode(cod, "surrogateescape" if cod == "utf-8" else "strict").splitlines(True), cod


def gravar_linhas(p, linhas, cod):
    dados = "".join(linhas)
    with open(longo(p), "wb") as f:
        f.write(dados.encode(cod, "surrogateescape" if cod == "utf-8" else "strict"))


def checar_sintaxe(p):
    """Confere a sintaxe do script editado. Levanta SyntaxError se quebrou; devolve como foi conferido."""
    e = extensao(p)
    if e in ("py", "pyw"):
        compile(Path(longo(p)).read_bytes(), str(p), "exec")
        return "sintaxe Python conferida (compile)"
    if e in ("ps1", "psm1"):
        exe = shutil.which("pwsh") or shutil.which("powershell")
        if not exe:
            return "sintaxe NAO VERIFICADA (PowerShell fora do PATH)"
        cmd = ("$e = $null; $null = [System.Management.Automation.Language.Parser]::ParseFile($env:ALVO_SINTAXE_SKILL, "
               "[ref]$null, [ref]$e); exit @($e).Count")
        r = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command", cmd], capture_output=True, timeout=120,
                           env=dict(os.environ, ALVO_SINTAXE_SKILL=str(p)))
        if r.returncode != 0:
            raise SyntaxError("PowerShell ParseFile achou %d erro(s) de sintaxe" % r.returncode)
        return "sintaxe PowerShell conferida (Parser.ParseFile)"
    if e in ("js", "mjs", "cjs"):
        exe = shutil.which("node")
        if not exe:
            return "sintaxe NAO VERIFICADA (node fora do PATH)"
        r = subprocess.run([exe, "--check", str(p)], capture_output=True, timeout=120)
        if r.returncode != 0:
            raise SyntaxError("node --check: " + r.stderr.decode("utf-8", "replace").strip())
        return "sintaxe JavaScript conferida (node --check)"
    return "sintaxe NAO VERIFICADA para arquivo .%s" % e


def limpar_linhas(p, bk):
    """Script legitimo trojanizado: troca SO as linhas que criam persistencia por uma linha inerte com a mesma indentacao
    (Python: 'pass  # ...'; outros: comentario). Backup antes; se a sintaxe quebrar, restaura o original e falha."""
    e = extensao(p)
    if e not in COMENTARIO:
        raise RuntimeError("limpeza por linha nao suportada para .%s: editar com a ferramenta Edit, com backup antes" % e)
    linhas, cod = ler_linhas(p)
    trocadas = []
    for i, l in enumerate(linhas):
        corpo = l.rstrip("\r\n")
        if MARCA_LIMPEZA in corpo or not cats_linha(corpo)[0]:
            continue
        fim = l[len(corpo):]
        ind = corpo[:len(corpo) - len(corpo.lstrip())]
        if e in ("py", "pyw"):
            nova = ind + "pass  # " + MARCA_LIMPEZA
        else:
            nova = ind + COMENTARIO[e] + " " + MARCA_LIMPEZA
        trocadas.append("linha %d: %s" % (i + 1, ocultar_segredos(corpo.strip())))
        linhas[i] = nova + (fim or "")
    if not trocadas:
        return [], "nenhuma linha que cria persistencia sozinha numa linha (o codigo pode estar quebrado em varias linhas): editar com a ferramenta Edit"
    bkp = backup_arquivo(p, bk)
    gravar_linhas(p, linhas, cod)
    try:
        como = checar_sintaxe(p)
    except Exception as ex:  # noqa: BLE001
        shutil.copy2(longo(bkp), longo(p))
        raise RuntimeError("a limpeza quebrou a sintaxe de %s (%s); original restaurado do backup %s; editar com a ferramenta Edit as linhas: %s"
                           % (p, ex, bkp, " | ".join(trocadas)))
    resto = trechos(ler_texto(p))
    if resto:
        raise RuntimeError("depois da limpeza %s ainda tem linhas que criam persistencia: %s (backup %s)" % (p, " | ".join(resto), bkp))
    return trocadas, "backup %s; %s" % (bkp, como)


def limpar_md(p, linha, comando, bk):
    """Hook em .md: tira o bloco 'hooks:' do frontmatter (hook no frontmatter) ou a linha do !`comando` (inline).
    O resto da skill/agente/comando fica como esta. Backup antes; confere que o comando nao esta mais no arquivo."""
    linhas, cod = ler_linhas(p)
    simples = [l.rstrip("\r\n") for l in linhas]
    fim = frontmatter(simples)
    tiradas = []
    b = bloco_hooks(simples, fim) if fim > 0 else None
    if b and b[0] < linha <= b[1]:
        tiradas = ["linhas %d-%d (bloco hooks do frontmatter): %s" % (b[0] + 1, b[1], " / ".join(x.strip() for x in simples[b[0]:b[1]] if x.strip()))]
        del linhas[b[0]:b[1]]
    elif 1 <= linha <= len(linhas) and "!`" in simples[linha - 1]:
        tiradas = ["linha %d: %s" % (linha, simples[linha - 1].strip())]
        del linhas[linha - 1]
    else:
        raise RuntimeError("o hook da linha %d nao foi achado em %s (arquivo mudou desde a varredura?): rodar varrer.ps1 de novo" % (linha, p))
    bkp = backup_arquivo(p, bk)
    gravar_linhas(p, linhas, cod)
    sobra = [c for _, _, c in comandos_md(ler_texto(p)) if hash_cmd(c) == hash_cmd(comando)]
    if sobra:
        raise RuntimeError("o comando continua em %s depois da edicao (backup %s)" % (p, bkp))
    return tiradas, bkp


def remover_mcp(nome, configs, homes, bk):
    editados, pend = [], []
    for cfg in configs:
        if cfg["tipo"] not in TIPOS_MCP:
            continue
        dados, editavel, err = carregar(cfg["arquivo"], cfg["tipo"])
        if err:
            continue
        alvos = [e for e in entradas_mcp(cfg, dados) if e["nome"] == nome]
        if not alvos:
            continue
        if not editavel:
            pend.append("%s: %s (arquivo com comentarios/TOML: editar com a ferramenta Edit, com backup antes)" % (
                cfg["arquivo"], " | ".join("/".join(str(x) for x in e["caminho"]) for e in alvos)))
            continue
        apagar_caminhos(dados, [e["caminho"] for e in alvos])
        bkp = gravar_json(cfg["arquivo"], dados, bk)
        editados.append("%s (%d registro(s); backup %s)" % (cfg["arquivo"], len(alvos), bkp))
    movidos = []
    for d in dirs_instaladores(homes):
        c = d / "configs" / (nome + ".json")
        if c.is_file():
            movidos.append(quarentena(c, bk))
    rx = re.compile(r'(?<![A-Za-z0-9_-])' + re.escape(nome) + r'(?![A-Za-z0-9_-])', re.I)
    for p, i, l in indice_reinjetores(homes):
        if rx.search(l):
            pend.append("%s:%d: %s (instalador que reinjeta: tirar o nome com a ferramenta Edit, com backup antes)" % (p, i, l.strip()))
    sobra = []
    for cfg in configs:
        dados, _, err = carregar(cfg["arquivo"], cfg["tipo"])
        if err:
            continue
        for e in entradas_mcp(cfg, dados):
            if e["nome"] == nome and cfg["tipo"] != "codex":
                sobra.append(cfg["arquivo"])
    return editados, pend, sobra, movidos


def remover_plugin(nome, raiz, configs, homes, bk):
    editados, movidos = [], []
    if raiz and os.path.isdir(raiz) and not eh_sistema(raiz):
        movidos.append(quarentena(raiz, bk))
    base = nome.split("@")[0].lower()

    def bate(k):
        k = str(k).lower()
        return k == base or k.split("@")[0] == base

    arquivos = [cfg["arquivo"] for cfg in configs if cfg["tipo"] == "settings"]
    for h in homes:
        arquivos.append(str(h / ".claude" / "plugins" / "installed_plugins.json"))
    for arq in arquivos:
        dados, editavel, err = carregar(arq)
        if err or not editavel or not isinstance(dados, dict):
            continue
        mudou = 0
        for cont in (dados.get("enabledPlugins"), dados.get("plugins")):
            if isinstance(cont, dict):
                for k in [k for k in cont if bate(k)]:
                    del cont[k]
                    mudou += 1
        if mudou:
            bkp = gravar_json(arq, dados, bk)
            editados.append("%s (%d chave(s); backup %s)" % (arq, mudou, bkp))
    return editados, movidos


def remover(a):
    resultados = []
    try:
        rel = json.loads(Path(a.relatorio).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as e:
        print(json.dumps({"Resultados": [], "Erro": "relatorio ilegivel: %s" % e}, ensure_ascii=False))  # scroll-ok: JSON unico lido pelo remover.ps1
        return 2
    itens = {}
    for i in (rel.get("Itens") or []):
        if isinstance(i, dict):
            itens[str(i.get("Id"))] = i
    configs, projetos, homes = listar_configs(a.raiz_extra, a.sem_home)
    ids = [x.strip().upper() for x in re.split(r"[,;\s]+", a.ids) if x.strip()]
    so_linhas = set(x.strip().upper() for x in re.split(r"[,;\s]+", a.so_linhas or "") if x.strip())

    def lista(x):
        if x is None:
            return []
        if isinstance(x, list):
            return [str(v) for v in x if v]
        return [str(x)] if str(x) else []

    for idv in ids:
        r = {"Id": idv, "Status": "", "Detalhe": ""}
        it = itens.get(idv)
        if not it:
            r.update(Status="NAO_ENCONTRADO", Detalhe="Id fora do relatorio")
            resultados.append(r)
            continue
        tipo = it.get("Tipo")
        try:
            partes, pend, sobra = [], [], []
            scripts_so = lista(it.get("Scripts")) + lista(it.get("ScriptsAninhados"))
            if tipo in ("HookAgente", "HookPlugin", "CodigoAgente", "PluginAgente") and idv in so_linhas and scripts_so:
                # script legitimo do usuario que foi trojanizado: limpa so as linhas que criam persistencia;
                # o hook continua registrado e o script continua no lugar
                for s in scripts_so:
                    if not os.path.isfile(s) or eh_sistema(s):
                        continue
                    trocadas, info = limpar_linhas(s, a.backup)
                    if trocadas:
                        partes.append("linhas neutralizadas em %s (%s): %s" % (s, info, " | ".join(trocadas)))
                    else:
                        partes.append("%s: %s" % (s, info))
                if not any(x.startswith("linhas neutralizadas") for x in partes):
                    pend.append("nenhuma linha neutralizada nos scripts %s: editar com a ferramenta Edit as linhas de Trechos, com backup antes" % " | ".join(scripts_so))
                r["Status"] = "PARCIAL" if pend else "REMOVIDO"
                r["Detalhe"] = " || ".join(["modo --so-linhas (hook e script do usuario mantidos)"] + partes + ["PENDENTE: " + x for x in pend])
                resultados.append(r)
                continue
            if tipo in ("HookAgente", "HookPlugin", "CodigoAgente", "PluginAgente"):
                if tipo == "CodigoAgente" and not it.get("Removivel"):
                    r.update(Status="NAO_REMOVIVEL", Detalhe="instrucao em arquivo de texto (%s): tirar as linhas indicadas em Trechos com a ferramenta Edit, com backup antes" % it.get("Local"))
                    resultados.append(r)
                    continue
                scripts = lista(it.get("Scripts"))
                hsh = it.get("HashComando") if tipo in ("HookAgente", "HookPlugin") else ""
                md = str(it.get("ArquivoMd") or "")
                if md:
                    if os.path.isfile(md):
                        tiradas, bkp_md = limpar_md(md, int(it.get("LinhaMd") or 0), str(it.get("Comando") or ""), a.backup)
                        partes.append("hook tirado de %s (backup %s): %s" % (md, bkp_md, " | ".join(tiradas)))
                    else:
                        pend.append("arquivo .md do hook nao encontrado: %s (rodar varrer.ps1 de novo e conferir)" % md)
                if not scripts and str(it.get("Evento") or "") in EVENTOS_SESSAO + ("hook no frontmatter", "comando inline !`...`"):
                    partes.append("ATENCAO SESSAO ABERTA: comando inline (sem script para por em quarentena); sessoes do agente ja abertas "
                                  "guardam uma copia dos hooks de quando comecaram e podem recriar o artefato ate serem fechadas. "
                                  "Fazer a prova numa sessao nova (SKILL.md, passo 5)")
                ed, pd, sb = remover_hooks(hsh, scripts, configs, a.backup)
                partes += ["configuracao editada: " + x for x in ed]
                pend += pd
                sobra += sb
                for s in scripts:
                    if os.path.isfile(s) and not eh_sistema(s) and (extensao(s) in EXT_SCRIPT or RE_GRAVAVEL.search(s)):
                        partes.append("script movido para quarentena: %s -> %s" % (s, quarentena(s, a.backup)))
                if tipo == "HookPlugin" and it.get("Plugin"):
                    ed2, mv2 = remover_plugin(str(it.get("Plugin")), str(it.get("PluginRaiz") or ""), configs, homes, a.backup)
                    partes += ["plugin desabilitado em: " + x for x in ed2] + ["pasta do plugin movida para quarentena: " + x for x in mv2]
                ps = str(it.get("PastaSkill") or "")
                if ps and a.remover_pasta_skill and os.path.isdir(ps):
                    partes.append("pasta da skill movida para quarentena: %s -> %s" % (ps, quarentena(ps, a.backup)))
                    nome_sk = os.path.basename(ps)
                    for cfg in configs:
                        if nome_sk.lower() in ler_texto(cfg["arquivo"]).lower():
                            pend.append("%s ainda cita a skill '%s': tirar a referencia com a ferramenta Edit, com backup antes" % (cfg["arquivo"], nome_sk))
                elif ps:
                    partes.append("o script fica dentro da skill %s (use -RemoverPastaSkill se a skill inteira for maliciosa)" % ps)
                for s in scripts:
                    if os.path.exists(s) and (extensao(s) in EXT_SCRIPT):
                        sobra.append("script continua no disco: " + s)
            elif tipo == "McpAgente":
                ed, pd, sb, mv = remover_mcp(str(it.get("NomeServidor") or it.get("Nome")), configs, homes, a.backup)
                partes += ["registro do servidor MCP tirado de: " + x for x in ed] + ["configuracao do instalador movida para quarentena: " + x for x in mv]
                pend += pd
                sobra += ["servidor MCP continua em " + x for x in sb]
            else:
                r.update(Status="FALHOU", Detalhe="tipo sem rotina no origem.py: %s" % tipo)
                resultados.append(r)
                continue
            if sobra:
                r["Status"] = "FALHOU"
            elif pend:
                r["Status"] = "PARCIAL"
            else:
                r["Status"] = "REMOVIDO"
            if not partes and not pend and not sobra:
                partes.append("nenhuma entrada encontrada nas configuracoes (ja tinha sido removida?)")
            r["Detalhe"] = " || ".join(partes + ["PENDENTE: " + x for x in pend] + ["SOBROU: " + x for x in sobra])
        except Exception as e:  # noqa: BLE001 - qualquer falha vira FALHOU com a mensagem exata
            r.update(Status="FALHOU", Detalhe="%s: %s" % (type(e).__name__, e))
        resultados.append(r)
    print(json.dumps({"Resultados": resultados}, ensure_ascii=False))  # scroll-ok: JSON unico lido pelo remover.ps1
    return 0


def main():
    ap = argparse.ArgumentParser(description="origem de infeccao em agentes de IA")
    sub = ap.add_subparsers(dest="acao")
    for nome in ("varrer", "remover"):
        p = sub.add_parser(nome)
        p.add_argument("--raiz-extra", action="append", default=[])
        p.add_argument("--ignorar", action="append", default=[])
        p.add_argument("--sem-home", action="store_true")
        if nome == "varrer":
            p.add_argument("--saida", required=True)
            p.add_argument("--itens", default="")
        else:
            p.add_argument("--relatorio", required=True)
            p.add_argument("--ids", required=True)
            p.add_argument("--backup", required=True)
            p.add_argument("--remover-pasta-skill", action="store_true")
            p.add_argument("--so-linhas", default="")
    a = ap.parse_args()
    if a.acao in ("varrer", "remover"):
        # caminhos absolutos: o relatorio guarda caminhos que o 'remover' usa depois, de outra pasta de trabalho
        a.raiz_extra = [os.path.abspath(x) for x in a.raiz_extra]
        a.ignorar = [os.path.abspath(x) for x in a.ignorar]
    if a.acao == "varrer":
        return varrer(a)
    if a.acao == "remover":
        return remover(a)
    ap.print_usage(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
