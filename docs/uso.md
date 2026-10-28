# Usando o CleiMesh

Receitas de comandos além do início rápido do [README](../README.pt-BR.md).

## Delegar

```sh
# O agente restringe o próprio token para um subagente: offline, sem servidor
cleimesh token derive cadeia.json <peer-id-do-subagente> --tool file_read --read ~/code/meu-projeto/docs -o sub.json

# Ampliar é recusado, pela CLI e de novo pelo nó
cleimesh token derive sub.json <qualquer> --tool file_read --read ~/.ssh
# Error: Cannot derive token: tool file_read: read access to /home/voce/.ssh not granted by the parent
```

## Reexecutar uma chamada

```sh
# Qualquer pessoa com o log, a chave pública do nó e a entrada da chamada
cleimesh audit replay <step-id> --args entrada.json
# REPRODUCED 01a1…f80d: same outcome and output (sha256 84a7…)
```

Chamadas que não usam pastas nem rede são reexecutáveis; o recibo diz isso e, quando não são, diz por quê.

## Encolher o token para o que o agente usou

```sh
# O sandbox registra quais pastas cada chamada tocou (por pseudônimo com chave, nunca nomes de arquivo);
# audit suggest compara com o token e propõe as permissões mínimas (ou --formato json)
cleimesh audit suggest --token chain.json -o permissao.json --lang pt
#   echo: 0 chamada(s), 0 arquivo(s) lido(s), 0 gravado(s)
#     nunca chamada no período: retirar do token
#   file_read: 10 chamada(s), 10 arquivo(s) lido(s), 0 gravado(s)
#     leitura: /home/voce/code/meu-projeto -> /home/voce/code/meu-projeto/docs

# Nada muda até você derivar; um arquivo de permissões maior que o pai é recusado
cleimesh token derive chain.json <peer-id-do-agente> --tool file_read --grants permissao.json -o menor.json
```

## Auditoria e retenção

```sh
cleimesh invoke <nó> <tool> '<args>' --token cadeia.json --titular cliente-42 --finalidade atendimento
cleimesh audit report --titular cliente-42 --lang pt # o que foi feito com os dados dessa pessoa (Markdown ou --formato json)
cleimesh audit report --agente <peer-id-do-agente> --lang pt  # registro das operações do agente (LGPD art. 37)
cleimesh audit head > cabeca.json                    # guarde a cabeça assinada fora; audit verify --head prova que nada foi cortado
cleimesh audit prune --antes 2026-01-01 --dry-run    # retenção, deixando o recibo da eliminação
```

Flags de token: sandbox `--read DIR`, `--write DIR`, `--network`, `--max-instructions N`, `--max-memory BYTES`, `--timeout-ms MS`, limitadas a uma tool com `--sandbox-for TOOL`; fluxo `--taints`, `--clean-only`; restrições de argumento `--tools '{"echo":{"message":{"constraint_type":"exact","value":"oi"}}}'`.

## Configurar um agente

```sh
cleimesh setup openclaw --read ~/code/proj --nao-confiavel ~/mail/entrada --write ~/mail/saida --dry-run
cleimesh setup hermes --nao-confiavel ~/mail/entrada --write ~/mail/saida
```

No Linux, para o OpenClaw e o Hermes Agent, o `setup` faz o que o [separate-user.md](separate-user.md) descreve à mão:

- como root (`sudo`): instala o binário em `/usr/local/bin`, cria o usuário `cleimesh` e roda o nó como serviço systemd em `127.0.0.1:7400` (`--node-user`, `--port`);
- como você: deixa o `cleimesh` alcançar as pastas concedidas com ACLs (só nas entradas que são suas, então arquivos que o nó escreveu não travam uma segunda execução) e faz o nó emitir os tokens do agente em `~/.config/cleimesh/<agente>/` (modo `0600`): `read.json`, `untrusted.json` (ler contamina), `write.json` (só limpo);
- registra `cleimesh mcp serve --node ...` como servidor MCP do agente e desliga as ferramentas próprias dele: no OpenClaw, `tools.deny` (read, write, edit, apply_patch, exec, process, ls); no Hermes, os toolsets `terminal`, `file`, `browser`, `code_execution` e `computer_use`.

Mostra cada comando com o usuário que o executa e pergunta antes de rodar (`-y` pula a pergunta). Rode de novo para renovar os tokens (30 dias por padrão, `--dias`): a contaminação fica no nó, então um agente contaminado continua contaminado. `--read` e `--nao-confiavel` juntos ainda são recusados.

O Hermes precisa do suporte a MCP dele (`hermes setup`, ou `uv sync --extra mcp` no checkout). Sem ele, o `hermes mcp add` não consegue iniciar o servidor e o salva desativado; o `setup` então para antes de desligar as ferramentas próprias do Hermes, para o agente não ficar sem ferramenta nenhuma, e o `doctor` acusa a entrada desativada.

### Usando com o airlock

O [airlock](https://github.com/otsoa-dubief/airlock) é um plugin do Hermes que confere cada chamada de ferramenta dentro do Hermes e pede aprovação do dono antes das arriscadas. Os dois cobrem camadas diferentes e podem rodar juntos: o airlock vigia o terminal e o navegador do Hermes; o CleiMesh faz o trabalho com arquivos no sandbox dele, como outro usuário do sistema, com recibo assinado para cada chamada.

```sh
hermes plugins install airlock --enable
cleimesh setup hermes --nao-confiavel ~/mail/entrada --write ~/mail/saida --with-airlock
```

Com `--with-airlock`, o `setup` mantém ligados o `terminal` e o `browser` do Hermes e desliga só `file`, `code_execution` e `computer_use`. Também faz o airlock admitir as ferramentas do CleiMesh: se `~/.hermes/airlock.yaml` não existe, escreve um com `tools.admitted_mcp_servers: [cleimesh]`; uma política existente nunca é reescrita, e o `setup` para se ela não admitir o `cleimesh` (acrescente lá e rode de novo). Recusa rodar se o airlock não estiver habilitado no Hermes, e com qualquer agente que não seja o Hermes.

Assim, ler o e-mail envenenado pelo CleiMesh contamina os dois: a próxima escrita do CleiMesh é recusada pelo nó com recibo, e um `curl -d @mail.txt` pelo terminal fica retido pelo airlock até o dono aprovar. O `doctor` aceita o terminal e o navegador só enquanto o airlock estiver habilitado e admitindo o CleiMesh:

```sh
cleimesh doctor
# ok    Hermes Agent uses CleiMesh for files; its own terminal, browser stay on, guarded by airlock
```

O que cada um não faz:

- O terminal ainda alcança arquivos diretamente, fora das pastas que o token concede, e essas chamadas não deixam recibo do CleiMesh. O airlock as julga pela cara do comando e pela contaminação da sessão; as garantias do CleiMesh valem só para as chamadas que passam por ele.
- O airlock não olha dentro dos argumentos de MCP: para ele, uma escrita do CleiMesh em `~/.ssh` é uma chamada normal; quem recusa é o sandbox do CleiMesh.
- O CleiMesh ainda não tem aprovação humana por chamada; o airlock tem.

Se você precisa das garantias do CleiMesh para tudo o que o agente faz, deixe o `--with-airlock` de fora: aí as ferramentas próprias do Hermes ficam todas desligadas.

## Conferir a instalação

```sh
cleimesh doctor
# ok    node key     /home/voce/.config/cleimesh/identity.key (12D3KooW…)
# ok    receipts     42 receipts in /home/voce/.local/share/cleimesh/receipts/receipts.jsonl verify
# ok    sandbox      runs a builtin tool and refuses a file it was not granted
# warn  OpenClaw     uses CleiMesh, but its own exec, process tool(s) are still on and bypass it; add them to "tools": {"deny": [...]} in ~/.openclaw/openclaw.json
```

Chaves (existem, `0600`), o log de recibos (verifica, tem cabeça assinada), o sandbox e cada agente com o CleiMesh registrado (Claude Code, OpenClaw, Hermes Agent): um agente que mantém as próprias ferramentas de arquivo ou shell faz o que o token recusa, sem recibo. Cada nó que os agentes chamam com `--node` é discado: falha se nada responder ou se responder outro nó (ele reiniciou com outra chave, e toda chamada falharia); a discagem não faz chamada, então não deixa recibo lá. O Claude Code é lido em todos os escopos (usuário, local e o `.mcp.json` do projeto). Quando os agentes chamam um nó que roda como outro usuário (`--node`), as chaves e o log do nó não são seus: confira-os com `sudo -u cleimesh cleimesh doctor`. Não altera nada; só sai com erro quando algo falha.

## Escrevendo uma tool (ABI v1)

Um módulo `wasm32-wasip1` que exporta `memory`, `cleimesh_alloc(len) -> ptr`, `cleimesh_execute(ptr, len) -> u64` (devolve `(out_ptr << 32) | out_len` apontando para `{"ok": ...}` ou `{"error": "..."}`) e, opcionalmente, `cleimesh_dealloc(ptr, len)`. Veja [`wasm-tools/builtins`](../wasm-tools/builtins/src/lib.rs). A ABI vai migrar para o Component Model (WIT) antes da 1.0.
