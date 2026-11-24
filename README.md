# DOMFANTOCH ESTERMINADOR DE VIRUS

Skill para o [Claude Code](https://claude.com/claude-code) que **encontra e remove malware, backdoor e persistência no Windows** e, principalmente, **acha a origem que reinstala o vírus**: hooks, skills, plugins e servidores MCP de agentes de IA (Claude Code, Cursor, OpenCode, Codex) que recriam o artefato toda vez que uma conversa é aberta.

> English summary: a Claude Code skill for Windows that hunts and removes malware persistence (Run keys, scheduled tasks, WMI subscriptions, services, Startup folder, Winlogon, IFEO) **and the origin that reinstalls it** from AI-agent hooks, skills, plugins and MCP servers. Everything is backed up before removal. Scripts and messages are in Brazilian Portuguese.

## O que ela faz

| Etapa | Script | Altera o sistema? |
|---|---|---|
| Varre os pontos de inicialização automática, sinais de ransomware e rootkit, estado do Defender e do Sysmon | `scripts\varrer.ps1` | Não |
| Lê hooks, plugins, servidores MCP e instruções de agentes de IA e liga cada origem ao artefato que ela recria | `scripts\origem.py` (chamado pelo varrer) | Não |
| Remove os itens escolhidos, a origem primeiro, com backup e conferência no sistema | `scripts\remover.ps1` | Sim, com backup |
| Abre uma sessão nova do agente para provar que nada voltou | `scripts\sessao-nova.ps1` | Não |
| Estado, varredura e proteção do Microsoft Defender | `scripts\defender.ps1` | Só quando pedido |
| Estado, eventos e instalação do Sysmon | `scripts\sysmon.ps1` | Só quando pedido |
| Prova de ponta a ponta com artefatos inofensivos | `scripts\teste.ps1` | Cria e apaga só os próprios artefatos |

O que a varredura cobre:

- chaves `Run`, `RunOnce` e `Policies\Explorer\Run` (máquina e cada usuário logado);
- tarefas agendadas, inclusive as escondidas no `TaskCache`;
- assinaturas WMI (`root/subscription`);
- serviços e drivers, inclusive os que estão no registro e fora do gerenciador de serviços;
- pasta Inicializar, `Winlogon`, `IFEO`, `AppInit_DLLs`;
- políticas que desligam o Defender;
- processos suspeitos e notas de resgate;
- hooks, plugins, servidores MCP e arquivos de instrução de agentes de IA.

## Requisitos

- Windows 10 ou 11.
- Windows PowerShell 5.1 (já vem no Windows) ou PowerShell 7.
- PowerShell aberto **como administrador** para a varredura completa e para remover.
- Python 3 (opcional): necessário só para a parte de origem em agentes de IA.
- [Claude Code](https://claude.com/claude-code), para usar como skill.

## Instalação

```powershell
git clone https://github.com/magoderiga/DOMFANTOCH-ESTERMINADOR-DE-VIRUS "$env:USERPROFILE\.claude\skills\domfantoch-esterminador-de-virus"
```

Use um caminho curto: o Windows PowerShell 5.1 não grava em caminho com mais de 260 caracteres.

## Como usar

Com o Claude Code aberto como administrador, peça em linguagem normal, por exemplo:

- "tem vírus no meu PC, encontra e remove"
- "o vírus volta sozinho toda vez que abro o Claude"
- "procura hook, skill ou MCP malicioso"

O agente roda a varredura, mostra o que achou com a evidência, pergunta antes de remover o que não tem prova e confere depois que nada voltou.

Também dá para rodar à mão:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "$env:USERPROFILE\.claude\skills\domfantoch-esterminador-de-virus\scripts\varrer.ps1"
```

O resumo traz um Id por item (por exemplo `REG-0007`, `TAR-0012`, `HKA-0039`). Para remover, passe os Ids:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "$env:USERPROFILE\.claude\skills\domfantoch-esterminador-de-virus\scripts\remover.ps1" -Id HKA-0039,REG-0007 -ApagarArquivo
```

## Segurança

- **Nada é removido sozinho.** A varredura só lê. A remoção é por Id, escolhido com a evidência do relatório.
- **Tudo tem backup.** Cada item removido é copiado antes para `_backups\<data>\` dentro da pasta da skill (chave do registro, XML da tarefa, definição WMI, chave do serviço, arquivo em quarentena).
- **Nada sai da máquina.** Os scripts não enviam dados para nenhum servidor. O único download é o do Sysmon, no site da Microsoft Sysinternals, e só com confirmação.
- **Leia antes de rodar.** São scripts que mexem em registro, tarefas e serviços com privilégio de administrador. O código está todo aqui para ser conferido.

## Teste

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "$env:USERPROFILE\.claude\skills\domfantoch-esterminador-de-virus\scripts\teste.ps1"
```

O teste cria artefatos inofensivos (valores `Run`, tarefa agendada, assinaturas WMI, serviço, arquivo na pasta Inicializar e um perfil de agente falso com três origens), roda a varredura e a remoção, simula uma sessão nova e confere que nada volta. Termina com `RESULTADO: PASSOU` e código 0, ou com a lista do que falhou.

## Limites

- A detecção é por heurística, assinatura digital, data de criação e linha de base. **Não é um antivírus de assinaturas e não garante achar todo malware.** Use junto com o Microsoft Defender ou outro antivírus.
- Rootkit de kernel engana as APIs que a skill compara; nesse caso a skill aponta o sinal e recomenda varredura offline.
- Tarefas ocultas e serviços ocultos são apontados, não removidos automaticamente.
- Só Windows. Para análise de amostra em laboratório, use ferramentas próprias.

## Créditos

As regras de caça a persistência foram montadas a partir do estudo destas skills públicas, lidas como referência (nenhum script delas é usado aqui):

- [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) (Apache-2.0): erradicação de malware, caça em chaves Run, tarefas agendadas, WMI, rootkit, ransomware e configuração do Defender (inclusive os identificadores das regras ASR).
- [Masriyan/Claude-Code-CyberSecurity-Skill](https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill): contrato de evidência (observado, inferido, não verificado).

## Licença

[MIT](LICENSE).
