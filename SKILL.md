---
name: domfantoch-esterminador-de-virus
description: Encontra e remove malware, backdoor e persistência no Windows do próprio usuário E A ORIGEM que a reinstala - chaves Run, tarefas agendadas, WMI, serviços, pasta Inicializar, Winlogon, IFEO, políticas que desligam o Defender, e hooks, skills (hook no frontmatter), plugins e servidores MCP de agentes de IA (Claude Code, Cursor, OpenCode, Codex) que recriam o artefato a cada sessão; também ransomware, rootkit, Defender e Sysmon. Use para "tem vírus no PC", "remover malware/backdoor", "caçar persistência", "o vírus volta sozinho", "hook/skill/MCP malicioso", "ransomware", "rootkit", "configurar o Defender", "instalar Sysmon". NÃO use para análise de amostra em laboratório nem Linux/macOS.
---

# DOMFANTOCH ESTERMINADOR DE VIRUS

Encontra e remove persistência maliciosa no Windows (Run, tarefas, WMI, serviços, Inicializar, Winlogon, IFEO, políticas
do Defender) e a ORIGEM que a reinstala (hooks, skills, plugins e servidores MCP de agentes de IA), com backup de tudo.

## Instalar e requisitos

- Windows 10 ou 11; Windows PowerShell 5.1 (já vem no Windows) ou PowerShell 7; Python 3 é opcional (sem ele a parte
  ORIGEM em agentes de IA é pulada com aviso e o resto funciona); `claude` (Claude Code CLI) é opcional (só `sessao-nova.ps1` usa).
- Instalar: `git clone https://github.com/magoderiga/DOMFANTOCH-ESTERMINADOR-DE-VIRUS "%USERPROFILE%\.claude\skills\domfantoch-esterminador-de-virus"`.
  Caminho de perfil com espaço ou acento funciona (todos os caminhos são passados entre aspas e lidos por objeto); se o
  caminho total passar de ~200 caracteres, instale a skill num caminho mais curto.
- Para remover é preciso PowerShell **como administrador** (o `remover.ps1` recusa sem isso e diz o motivo). Sem
  administrador, o `varrer.ps1` roda o que der e lista em `LIMITES DESTA VARREDURA` o que ficou de fora.

## Avisos

- O agente lista e **pergunta antes de remover** tudo o que não tiver prova no relatório; remove só pelo Id escolhido.
- Tudo o que é alterado ou removido tem backup em `_backups\<carimbo>\` (na pasta da skill); arquivos vão para quarentena, não são apagados.
- Nada é enviado para fora do computador. O único download é o Sysmon (`sysmon.ps1 -Acao Instalar`), e só com confirmação do usuário.
- Vários usuários na máquina: as chaves Run de todos os perfis carregados (`HKEY_USERS\<SID>`), as pastas Inicializar de
  todos os perfis, as tarefas, os serviços e o WMI são lidos para a máquina inteira; a ORIGEM em agentes de IA é lida só
  do perfil de quem roda (`%USERPROFILE%`, `%APPDATA%`, `%LOCALAPPDATA%`) e das pastas dadas em `-RaizAgente`.
  Perfil de usuário deslogado não tem a hive carregada e não é lido.
- Decisões não dependem do idioma do Windows: os scripts usam códigos de saída e objetos (CIM, registro), não o texto das mensagens.

Tudo roda em PowerShell (5.1 ou 7). Scripts em `scripts/`, histórico em `logs/`, backup e quarentena em `_backups/<carimbo>/`.

Comando base (use `pwsh`; se não existir, `powershell`):

```
pwsh -NoProfile -ExecutionPolicy Bypass -File "<pasta da skill>\scripts\<script>.ps1" <parametros>
```

| Script | O que faz | Altera o sistema? |
|---|---|---|
| `varrer.ps1 [-Todos] [-SemAssinatura] [-RaizAgente DIR] [-DiasRecentes 7] [-NovaLinhaDeBase]` | Varre persistência, sinais de malware e a ORIGEM em agentes de IA; grava `logs\ultima-varredura.json` e imprime o resumo | Não |
| `remover.ps1 -Id ID1,ID2 [-ApagarArquivo] [-Forcar] [-RemoverPastaSkill] [-SoLinhas ID]` | Remove os itens escolhidos (origens primeiro), com backup e conferência; `-SoLinhas` limpa só as linhas injetadas num script legítimo | Sim (com backup) |
| `teste.ps1` | Prova de ponta a ponta: 3 origens falsas (hook no settings.json, hook no frontmatter de um SKILL.md com nome curto, hook legítimo trojanizado), tarefa, WMI, serviço, Inicializar, MCP | Cria e apaga só os próprios artefatos |
| `sessao-nova.ps1 [-Prompt T] [-PrazoSeg 300] [-Pasta DIR]` | Abre uma sessão nova do agente FORA do app desktop (`Win32_Process.Create`), espera com prazo, log em `logs\` | Só o que os hooks da sessão fizerem |
| `origem.py` | Chamado pelo varrer/remover: lê hooks, plugins, MCP e instruções de agentes; edita JSON com backup e validação | Só no `remover` |
| `defender.ps1 -Acao Status\|VarreduraRapida\|VarreduraCompleta\|VarrerArquivo\|AplicarProtecao\|Religar` | Estado, políticas, varredura MpCmdRun, PUA + regras ASR; `Religar` tira as políticas `Disable*=1` (backup .reg), roda `gpupdate` e tenta iniciar o `WinDefend`; sem Defender, `VarrerArquivo` devolve SHA256 e assinatura | `AplicarProtecao` e `Religar` |
| `sysmon.ps1 -Acao Status\|Eventos\|Instalar` | Estado, eventos 6/12/13/14/19/20/21, instalação com `sysmon-config.xml` | Só `Instalar` (baixa da Sysinternals) |

## Fluxo

1. **Confirmar administrador**: `net session` (código 0). Sem administrador a varredura sai incompleta e a remoção recusa.
2. **Varrer** (cerca de 30 s): `varrer.ps1`. Andamento em `logs\varrer-*.log`; se passar de 1 min, ler esse log enquanto roda.
   O resumo tem duas partes:
   - **ORIGEM**: todo hook (`HKA`; inclui hook declarado no **frontmatter** de `SKILL.md`, `agents\*.md` e `commands\*.md` e
     comando inline (ponto de exclamação seguido de comando entre crases) desses `.md`, com `Local` = o `.md` e `ArquivoMd` preenchido), hook de plugin (`HKP`), servidor
     MCP (`MCP`), plugin do OpenCode (`PAG`) e código/instrução de agente que cria persistência (`CAG`), com o comando completo,
     os scripts que ele chama (e os que esses chamam), os motivos, as linhas que criam persistência (`trechos`, com arquivo e
     número da linha) e a linha **`CRIA ESTES ITENS DE PERSISTENCIA: REG-0007, ...`** quando o código da origem cria um artefato
     que está no sistema agora. A ligação vale também para `subprocess.run(["reg","add",...])`, `["sc","create",...]`,
     `["schtasks","/create",...]` (as regras rodam no texto sem aspas/vírgulas/colchetes) e para nome curto de artefato (2 a 4
     letras) quando o nome aparece na mesma linha que cria aquele tipo de artefato. Sem nome no código, uma origem que roda a cada
     sessão é ligada aos itens **recentes** do mesmo tipo que ela cria, e o motivo diz "ligacao por tipo e data" (evidência mais fraca).
   - **PERSISTÊNCIA**: itens médio/alto, todos os de Run/Inicializar/WMI/Winlogon/IFEO/AppInit (são poucos), todo item **recente**
     (criado/alterado nos últimos 7 dias: data da chave do registro, do arquivo da tarefa ou do arquivo) e todo item **novo**
     (fora da linha de base `logs\linha-de-base.json`), mesmo sem nenhum sinal suspeito. `ORIGEM=HKA-0039` no item diz quem o recria;
     `REINJETA AGENTE` diz que o script do item mexe em configuração de agente (vigia que reinjeta hook/MCP).
   Detalhes completos em `logs\ultima-varredura.json` (campos `Itens`, `Origem`, `Defesas`, `EventosSysmon`, `Erros`).
3. **Analisar** com a evidência do relatório (Id, campo e valor):
   - Item com `OrigemProvavel` ou origem com `LigadoA`: é o par artefato + origem. Remove-se **os dois juntos**.
   - Hook/MCP do usuário: quase todos em `%USERPROFILE%\.claude` são automações legítimas dele. Só remover
     origem com prova: cria persistência (`LigadoA`/motivo "cria ..."), baixa/decodifica código, script em pasta temporária, script
     ausente, ou foi criado/alterado junto com o artefato (`DataRef`). Na dúvida, listar ao usuário com a evidência e perguntar.
   - **Origem é script do usuário que foi trojanizado ou é código estranho?** Script do usuário = já estava na linha de base
     (`Novo` falso), faz outras coisas além da linha suspeita, e os `trechos` mostram só 1 ou 2 linhas que criam persistência
     (ex.: um script de hook conhecido com uma linha `reg add ...\Run` a mais). Nesse caso usar `-SoLinhas <Id>`: o hook continua registrado
     em todos os arquivos e o script continua no lugar; só as linhas dos `trechos` viram linha inerte, com backup e sintaxe
     conferida. Script que só existe para criar a persistência, ou que o usuário não reconhece: remoção completa (sem `-SoLinhas`).
   - `Caminho` x `Carga`: quando o comando é um interpretador (powershell, wscript, rundll32, cmd), a assinatura que importa é a da
     `Carga` (o script/DLL), não a do binário da Microsoft.
   - `Protegido=true` (padrão genérico de ferramentas comuns, como gerenciadores de serviço, Docker, Ollama, ngrok, Burp, mais o que o
     usuário puser em `protegidos.txt`): só usar `-Forcar` com evidência no relatório de que o item é malicioso
     (ex.: `OrigemProvavel` preenchido, que já tira a proteção sozinho). Pastas de agente (`.claude`) **não** são protegidas: é onde
     um hook/skill malicioso mora.
   - Item que aponta para pasta de projeto do usuário (Desktop, `%USERPROFILE%\<projeto>`) é quase sempre automação dele: listar e perguntar antes.
   - Conferir arquivo suspeito: `defender.ps1 -Acao VarrerArquivo -Alvo <arquivo>`. Com o Defender parado (código 3), o script
     devolve SHA256 e assinatura e aponta o passo seguinte (`-Acao Religar`, passo 6).
   - O que não tiver prova fica NAO VERIFICADO.
4. **Remover** artefato e origem no mesmo comando: `remover.ps1 -Id HKA-0039,REG-0007 -ApagarArquivo`.
   - Origens saem **primeiro** (`origem.py remover`): a entrada é tirada de **todos** os arquivos de configuração que a citam
     (mesmo comando ou mesmo script: `settings.json`, `settings.local.json`, `cowork_settings.json`, `.claude.json` global e por projeto,
     `.mcp.json`, `claude_desktop_config.json`, `.cursor\mcp.json`, `opencode.json`, `hooks.json` de plugin), cada arquivo com backup em
     `_backups\<carimbo>\agentes\` e JSON validado antes e depois de gravar; o script do hook vai para a quarentena. Hook de plugin:
     a pasta do plugin vai para a quarentena e o plugin sai de `enabledPlugins` e de `installed_plugins.json`. Servidor MCP: sai de
     todos os registros; se o perfil tiver uma pasta de instalador com `mcp` no nome que guarda `configs\<nome>.json`, esse arquivo vai
     para a quarentena.
   - Depois, o artefato: `reg export`/XML da tarefa/JSON do WMI/chave do serviço no backup, remoção e **conferência no sistema**.
     `-ApagarArquivo` põe na quarentena o executável e a **carga** (nunca de `C:\Windows`/Arquivos de Programas, nunca assinado válido)
     e encerra o processo que roda dela.
   - Hook em `.md` (`ArquivoMd`): sai o bloco `hooks:` inteiro do frontmatter (ou a linha do comando inline), com backup do `.md`;
     o resto da skill/agente/comando fica; o script que o hook chamava vai para a quarentena.
   - `-SoLinhas HKA-xxxx` (o Id também vai em `-Id`): script legítimo trojanizado; ver passo 3. Se a troca quebrar a sintaxe
     (`compile` do Python, `Parser.ParseFile` do PowerShell, `node --check`), o original volta do backup e o item sai `FALHOU`
     com as linhas exatas: fazer a edição com a ferramenta Edit, com cópia antes em `_backups\`.
   - `-RemoverPastaSkill`: quando o script do hook mora dentro de uma skill (`PastaSkill`) que é toda maliciosa, move a pasta inteira.
   - Status `PARCIAL` = sobrou referência que o script não edita sozinho (arquivo com comentários, TOML do Codex, linhas de
     scripts de instalador/vigia que reinjetam configuração). O Detalhe traz arquivo e linha: **fazer a edição com a ferramenta Edit**, com cópia antes
     em `_backups\`, validar o JSON (`python -c "import json;json.load(open(r'<arquivo>',encoding='utf-8'))"`) e rodar o varrer de novo.
   - Saída: código 0 = tudo removido; 1 = algum item `FALHOU`, `PARCIAL`, `RECUSADO_PROTEGIDO`, `NAO_REMOVIVEL` ou `NAO_ENCONTRADO`.
5. **Provar que não volta, sem a sessão atual atrapalhar.** O Claude Code guarda uma cópia dos hooks quando a sessão começa:
   editar o `settings.json` não desliga um hook numa sessão que já está aberta (inclusive a que roda esta skill). Origem com
   script vai para a quarentena, então o hook antigo falha e não recria nada; origem com **comando inline** (o remover avisa
   `ATENCAO SESSAO ABERTA`) continua rodando nas sessões abertas até elas fecharem. Por isso a prova é feita numa ÚNICA chamada
   de ferramenta, entre dois hooks da sessão atual: remover de novo os artefatos (caso a sessão atual os tenha recriado), abrir
   uma sessão nova do agente (lê os arquivos já editados e dispara `SessionStart`) e varrer, tudo no mesmo comando. O remover usa
   o MESMO relatório da remoção, pelo arquivo com data (linha `Relatorio JSON:` da varredura; ex.:
   `logs\varredura-AAAAMMDD_HHMMSS.json`; o `ultima-varredura.json` é regravado a cada varredura), em que o Id aponta para o
   mesmo tipo, local e nome:
   ```
   $s = '<pasta da skill>\scripts'
   & pwsh -NoProfile -ExecutionPolicy Bypass -File "$s\remover.ps1" -Relatorio '<relatorio usado>' -Id <Ids dos ARTEFATOS> | Out-Null
   & pwsh -NoProfile -ExecutionPolicy Bypass -File "$s\sessao-nova.ps1" -PrazoSeg 300
   & pwsh -NoProfile -ExecutionPolicy Bypass -File "$s\varrer.ps1" -Saida "$s\..\logs\prova-depois.json"
   ```
   **Por que `sessao-nova.ps1` e não `claude -p` direto:** processo lançado de dentro do app Claude desktop (empacotado) grava
   valor novo de HKCU numa visão VIRTUAL que o Windows real não tem; o hook recriaria o valor só ali e a prova ficaria cega.
   O script abre a sessão por `Win32_Process.Create` (fora do app, mesmo usuário), espera com prazo e grava log em `logs\`
   (código 0 = sessão terminou bem; 2 = prazo; 3 = falha ao lançar). O `varrer.ps1` compara a visão do próprio processo com a de
   fora (StdRegProv) e, se diferirem, avisa no resumo e marca `SO NA VISAO VIRTUAL` os valores que não existem no Windows real
   (não são inicialização real: apagá-los só limpa a visão virtual; a prova de que não voltou vale só com a sessão aberta fora do app).
   (Nesse remover, `FALHOU`/`NAO_ENCONTRADO` porque o artefato já não existe é o esperado.) Nenhum item removido (nem a origem
   nem o artefato; comparar Tipo, Local e Nome, porque os Ids mudam entre varreduras) pode estar em `prova-depois.json`. Se
   estiver, há outra origem: procurar `REINJETA AGENTE`, `CRIA ESTES
   ITENS`, tarefas/serviços com o mesmo script, e o processo pai (`PIDPai`). Se a origem era inline, dizer ao usuário que as
   sessões do agente abertas antes da limpeza (listar: `Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'claude' }`)
   ainda guardam o hook antigo e precisam ser fechadas; esta é a única etapa que o agente não faz sozinho, porque não consegue
   reiniciar a própria sessão (fechar sessões do usuário só com OK dele).
6. **Defender e Sysmon**: `defender.ps1 -Acao Status`. Itens `PoliticaDefender` (ex.: `DisableAntiSpyware=1`) = Defender desligado por
   política: perguntar ao usuário se é intencional. Com OK, `defender.ps1 -Acao Religar` tira essas políticas (backup .reg),
   roda `gpupdate /target:computer /force`, tenta `Start-Service WinDefend` por até 30 s e confere `Get-MpComputerStatus`; se o
   serviço continuar parado, o resultado diz a causa provável e o próximo passo (reiniciar o PC, com OK). Só depois disso
   `VarreduraRapida`, `VarrerArquivo` e `AplicarProtecao` (PUA + 10 regras ASR em Auditoria) funcionam. `sysmon.ps1 -Acao Instalar`
   muda a configuração e baixa arquivo: pedir OK uma vez, depois executar sem mandar o usuário fazer nada.
7. **Relatório ao usuário**: origem achada (arquivo, evento, comando, script), artefatos que ela criava, o que foi removido (com o
   caminho do backup), o que ficou e por quê, e a prova do passo 5.

## Tipos de item e o que o remover faz

| Tipo (prefixo do Id) | Fonte da varredura | Remoção |
|---|---|---|
| HookAgente (HKA) | `hooks`, `statusLine`, `apiKeyHelper` e afins, `env.NODE_OPTIONS` e afins em settings do Claude Code (global, local, cowork, projetos, gerenciado), Cursor `hooks.json`, Gemini CLI, `notify` do Codex; `hooks:` no frontmatter e comando inline (exclamação + crases) de `SKILL.md`, `agents\*.md`, `commands\*.md` (do usuário, dos projetos e dos plugins) | tira a entrada de todos os arquivos (mesmo comando ou mesmo script) + script em quarentena; em `.md`, tira o bloco `hooks:`/a linha; com `-SoLinhas`, só neutraliza as linhas injetadas do script |
| HookPlugin (HKP) | `hooks/hooks.json` e `plugin.json` dos plugins instalados do Claude Code | o mesmo + pasta do plugin em quarentena + sai de `enabledPlugins`/`installed_plugins.json` |
| McpAgente (MCP) | `mcpServers` de `.claude.json` (global e por projeto), `.mcp.json`, Claude Desktop, Cursor, Windsurf, VS Code, `mcp` do OpenCode, `mcp_servers` do Codex; linhas de instalador do perfil (pasta com `mcp` no nome) que citam o nome | tira o registro de todos os arquivos; `configs\<nome>.json` desse instalador em quarentena; linhas de instalador ficam como PENDENTE |
| PluginAgente (PAG) | plugins do OpenCode (`.config\opencode\plugin(s)`), carregados a cada sessão | arquivo em quarentena |
| CodigoAgente (CAG) | código em `.claude\` (pastas hooks, skills, agents, commands e plugins\cache) que cria persistência; `CLAUDE.md`/`AGENTS.md`/`GEMINI.md` que mandam criar | código: quarentena + tira hooks que o chamam; instrução `.md`: NAO_REMOVIVEL (editar as linhas de `Trechos` com Edit) |
| Registro (REG) | Run, RunOnce, RunServices, Policies\Explorer\Run (HKLM, WOW6432Node e cada HKU\<SID>), Load/Run legados | apaga o valor (backup .reg da chave) |
| Inicializar (INI) | pastas Startup de todos os perfis e ProgramData (.lnk resolvido) | move o arquivo para a quarentena |
| Tarefa (TAR) | `Get-ScheduledTask` (ações Exec e ComHandler, flag Hidden) | `Unregister-ScheduledTask` (backup XML) |
| WMI (WMI) / WMI-Filtro (WMF) | `root/subscription`: consumidores, filtros e vínculos | apaga vínculos, consumidor e filtros que só ele usava (backup JSON) |
| Servico (SRV) | `Win32_Service` (svchost resolvido para a ServiceDll) | para o serviço e `sc.exe delete` (backup .reg) |
| Winlogon (WLG) / IFEO (IFE) / AppInit (API) | Shell/Userinit, Debugger em IFEO, AppInit_DLLs | volta ao padrão / apaga o Debugger / esvazia AppInit |
| PoliticaDefender (PDF) | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` (Disable*=1) | apaga o valor da política (backup .reg) |
| Processo (PRC) | `Win32_Process` com pontuação >= 2 | `Stop-Process` |

### Itens só de diagnóstico (o remover recusa com `NAO_REMOVIVEL`)

- **TarefaOculta (TOC)**: tarefa ativa no `TaskCache` sem valor `SD` (técnica Tarrask) ou que o `Get-ScheduledTask` não lista. Remoção exige SYSTEM:
  informar o usuário com a chave exata do relatório.
- **ServicoOculto (SOC)**: serviço/driver na chave `Services` ausente do SCM. Pode ser resto inofensivo (ex.: driver de ferramenta que já foi apagado);
  se o arquivo existir e for suspeito, varrer o arquivo e, com OK do usuário, apagar a chave com `reg export` antes.
- **Driver (DRV)**, **ProcessoOculto (POC)**: sinais de rootkit. Visão de usuário tem limite: um rootkit de kernel engana as duas APIs comparadas.
  Recomendar varredura offline do Defender (`Start-MpWDOScan`, reinicia o PC: só com OK) ou mídia de resgate.
- **NotaResgate (RSG)** e **ExclusaoDefender (EXC)**: ver a seção de ransomware abaixo; exclusão do Defender sai com `Remove-MpPreference` quando o Defender estiver ativo.

## Ransomware (de performing-ransomware-response)

Sinais no relatório: itens `NotaResgate`, motivo "apaga cópias de sombra", `Defesas.CopiasSombra` = 0 numa máquina que tinha cópias.
Ordem: (1) com OK do usuário, isolar a rede (`Get-NetAdapter | Disable-NetAdapter -Confirm:$false`; reverter com `Enable-NetAdapter`);
(2) não reiniciar nem apagar a nota (é evidência; a chave pode estar na memória); (3) varrer e remover a persistência e a origem como acima;
(4) restaurar arquivos de backup/cópia de sombra só depois de a varredura sair limpa; (5) não pagar resgate; procurar o decriptador da família em nomoreransom.org.

## Prova de que funciona

`teste.ps1` (como administrador, cerca de 1-2 min) monta um perfil de agente falso em `_teste\<nome>\home` com três origens que
recriam valores Run a cada sessão: (a) hook `SessionStart` no `settings.json` que chama um `.ps1` (nome longo, carga `.ps1`);
(b) `SKILL.md` com hook no **frontmatter** que chama um `.py` com `subprocess.run(["reg","add",...])` e nome de valor de 4 letras
apontando para `notepad.exe`; (c) hook **legítimo** `.py` trojanizado com uma linha dessas. Tem ainda um hook de controle e um
servidor MCP. Simula uma sessão (as origens criam os valores), cria tarefa agendada com `notepad.exe` (sem sinal suspeito: tem de
aparecer por ser recente), assinatura WMI, serviço e arquivo na pasta Inicializar. Exige que a varredura liste todos no resumo e
ligue cada origem ao SEU valor Run (e não ao dos outros); remove tudo pelos Ids com `-ApagarArquivo` e `-SoLinhas` para (c);
confere sistema, quarentena, JSON válido, `SKILL.md` sem o bloco `hooks:` e com o corpo, hook (c) e hook de controle mantidos,
script (c) no lugar só com a linha injetada neutralizada; simula uma **nova sessão** e exige que nenhum valor Run volte; e limpa
as sobras (o valor de nome curto só é apagado se o dado for exatamente o do teste). Saída `RESULTADO: PASSOU` e código 0, ou a
lista do que falhou e código 1.

## Limites conhecidos

- Detecção por heurística + assinatura digital + data de criação + linha de base; não há antivírus de assinatura próprio.
- Assinaturas WMI só em `root/subscription`. Hives de usuários deslogados não são carregadas.
- Origem em agentes: lê os arquivos de configuração conhecidos (lista no relatório, campo `Origem.ArquivosLidos`); agente instalado
  em lugar fora dessa lista não é lido (usar `-RaizAgente` para apontar uma pasta extra). Hook que baixa o código na hora só é
  ligado ao artefato se o nome do artefato aparecer no comando ou nos scripts locais; senão aparece pelos motivos (baixa conteúdo, base64).
- Ligação por nome é por texto: nome montado em pedaços (`"Up"+"d"`) ou guardado em variável numa linha longe da que cria o
  artefato não liga por nome; nesse caso vale a ligação por tipo e data (só para origens que rodam a cada sessão) e os motivos.
- Hook em `.md`: lê `command:` do bloco `hooks:` em YAML de blocos (o formato da documentação); YAML em estilo fluxo
  (`hooks: {...}` numa linha só) não é lido (NAO VERIFICADO se o Claude Code aceita esse estilo).
- `-SoLinhas` troca linha inteira; código que cria a persistência espalhado em várias linhas sai `FALHOU`/`PARCIAL` com as
  linhas exatas para a edição com a ferramenta Edit.
- `.claude.json` é regravado pelo Claude Code em execução: remover MCP com o mínimo de sessões abertas e conferir com o varrer depois.
- Remoção de rootkit de kernel e de tarefas ocultas exige mídia de resgate/SYSTEM; a skill aponta, não remove.

## Arquivo `protegidos.txt` (opcional)

Na raiz da skill, uma expressão regular por linha (linhas com `#` são comentário). Qualquer item cujo nome, comando, caminho ou local bata vira
`Protegido` e o `remover.ps1` recusa sem `-Forcar` (a proteção cai sozinha se a varredura ligar o item a uma origem).
