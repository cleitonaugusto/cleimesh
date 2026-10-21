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

## Conferir a instalação

```sh
cleimesh doctor
# ok    node key     /home/voce/.config/cleimesh/identity.key (12D3KooW…)
# ok    receipts     42 receipts in /home/voce/.local/share/cleimesh/receipts/receipts.jsonl verify
# ok    sandbox      runs a builtin tool and refuses a file it was not granted
# warn  OpenClaw     uses CleiMesh, but its own exec, process tool(s) are still on and bypass it; add them to "tools": {"deny": [...]} in ~/.openclaw/openclaw.json
```

Chaves (existem, `0600`), o log de recibos (verifica, tem cabeça assinada), o sandbox e cada agente com o CleiMesh registrado (Claude Code, OpenClaw; do Hermes Agent, só o registro): um agente que mantém as próprias ferramentas de arquivo ou shell faz o que o token recusa, sem recibo. O Claude Code é lido em todos os escopos (usuário, local e o `.mcp.json` do projeto). Quando os agentes chamam um nó que roda como outro usuário (`--node`), as chaves e o log do nó não são seus: confira-os com `sudo -u cleimesh cleimesh doctor`. Não altera nada; só sai com erro quando algo falha.

## Escrevendo uma tool (ABI v1)

Um módulo `wasm32-wasip1` que exporta `memory`, `cleimesh_alloc(len) -> ptr`, `cleimesh_execute(ptr, len) -> u64` (devolve `(out_ptr << 32) | out_len` apontando para `{"ok": ...}` ou `{"error": "..."}`) e, opcionalmente, `cleimesh_dealloc(ptr, len)`. Veja [`wasm-tools/builtins`](../wasm-tools/builtins/src/lib.rs). A ABI vai migrar para o Component Model (WIT) antes da 1.0.
