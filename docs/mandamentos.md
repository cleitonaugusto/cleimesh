# Os Dez Mandamentos do Agente Sob Controle

[English](commandments.md)

Agentes de IA leem e-mails, abrem arquivos, chamam APIs e delegam trabalho a outros agentes. Estes são os princípios que o CleiMesh segue para que isso aconteça sob controle. Valem para qualquer sistema de agentes, com ou sem o CleiMesh.

**Regra de ouro: mandamento sem teste é marketing.** Cada mandamento abaixo aponta para os testes que falham se ele for violado, e o teste `every_commandment_names_tests_that_exist` (`cleimesh-cli/tests/commandments.rs`) falha se algum desses testes deixar de existir.

---

### 1. A permissão é a jaula.
O que foi assinado é exatamente o que o sandbox aplica. A permissão não é um papel ao lado da execução: ela é a configuração do ambiente onde a ferramenta roda.

Testes: `same_tool_sees_only_the_directory_its_token_grants`, `symlink_inside_a_grant_cannot_lead_outside_it` (`cleimesh-p2p/tests/grants.rs`).

### 2. Nada por padrão.
Sem permissão escrita, não há acesso: nenhuma pasta, nenhuma rede. Campo que o executor não entende é recusado, porque pode ser uma restrição que ele não saberia aplicar.

Testes: `token_without_grants_runs_with_no_directory`, `raised_limit_and_unknown_grant_field_are_refused` (`cleimesh-p2p/tests/grants.rs`).

### 3. Delegar só estreita.
Um subagente nunca recebe mais do que quem delegou: nem pasta, nem escrita, nem rede, nem limite.

Testes: `subagent_cannot_reach_what_its_parent_can`, `derived_grant_wider_than_its_parent_is_refused` (`cleimesh-p2p/tests/grants.rs`), `accepted_chain_never_widens` (`cleimesh-p2p/tests/grant_properties.rs`, 20 mil cadeias aleatórias).

### 4. Quem decide é o executor, não o agente.
A regra é aplicada fora do processo que pode ser enganado. O agente não guarda o próprio rótulo, não escolhe a própria política e não consegue trocar de identidade para escapar dela. Um agente com shell roda como outro usuário do sistema, diferente do executor, então também não alcança a chave, o log nem os rótulos do executor.

Testes: `taint_blocks_clean_only_tools_through_the_cli` (`cleimesh-cli/tests/cli.rs`, executor real: outro token para a mesma chave continua barrado), `mcp_serve_forwards_to_a_node_and_holds_nothing_of_it` (`cleimesh-cli/tests/mcp.rs`, o lado do agente não guarda nada do executor).

### 5. O que entrou sujo segue sujo.
Conteúdo de fora (e-mail, página, pasta compartilhada) contamina toda a cadeia de delegação. Delegar a um subagente novo não lava.

Testes: `after_reading_untrusted_content_the_agent_cannot_act_on_the_world`, `delegating_to_a_fresh_subagent_does_not_launder_the_taint`, `a_subagent_reading_mail_taints_the_agents_above_it`, `a_subagent_cannot_shed_the_flags`, `a_new_token_for_the_same_key_is_still_refused`, `the_refusal_does_not_depend_on_what_the_next_call_carries`, `any_forest_and_any_order_follow_the_rule` (`cleimesh-p2p/tests/taint.rs`).

### 6. Só um humano lava, e a limpeza fica registrada.
Nenhum agente se declara limpo. A liberação é um ato humano, com motivo, num recibo assinado; sem o recibo, a contaminação continua, inclusive depois de reiniciar.

Testes: `taint_survives_a_restart_and_only_a_recorded_clearing_lifts_it`, `the_taint_survives_a_restart_even_without_the_result_receipt` (`cleimesh-p2p/tests/taint.rs`).

### 7. Toda ação deixa recibo.
Chamadas aceitas e recusadas geram recibos assinados e encadeados. Alterar, apagar ou reordenar uma linha é apontado na verificação. O recibo guarda resumos, nunca o conteúdo.

Testes: `allowed_and_denied_calls_leave_verifiable_receipts` (`cleimesh-p2p/tests/receipts.rs`), `edited_line_is_pointed_out`, `removed_interior_line_is_pointed_out`, `reordered_lines_are_pointed_out` (`cleimesh-receipt/tests/receipts.rs`).

### 8. A prova se refaz.
Não confie no recibo: reexecute. Quem duvida roda de novo a mesma chamada e confere o resultado, sem precisar confiar em quem executou.

Testes: `calls_replay_from_their_receipts`, `a_signed_but_false_result_is_caught_by_replay`, `a_log_recorded_on_another_machine_replays_here` (`cleimesh-p2p/tests/replay.rs`).

### 9. Use só o que usou.
A permissão deve encolher até o que foi necessário (princípio da necessidade, LGPD art. 6º, III). O sistema mostra o que o agente realmente usou e propõe uma permissão menor; quem aprova é um humano.

Testes: `ten_calls_in_docs_suggest_a_token_for_docs_only` (`cleimesh-p2p/tests/fs_observed.rs`), `audit_suggest_proposes_what_the_agent_used_and_derive_takes_it` (`cleimesh-cli/tests/mcp.rs`).

### 10. Na dúvida, falhe fechado.
Se não dá para aplicar a regra ou registrar a prova, a ação não acontece. Nunca cair para um modo mais fraco.

Testes: `call_is_refused_when_its_receipt_cannot_be_written` (`cleimesh-p2p/tests/receipts.rs`), `failed_write_leaves_the_log_refusing_appends` (`cleimesh-receipt/tests/receipts.rs`), `missing_directory_refuses_the_call` (`cleimesh-p2p/tests/grants.rs`).

---

## De onde vêm

Nada disso nasce do zero. Os mandamentos aplicam a agentes de IA ideias antigas da segurança de computadores:

- **Saltzer e Schroeder (1975), *The Protection of Information in Computer Systems*:** menor privilégio (3 e 9), padrões seguros (2 e 10), mediação completa (1 e 4).
- **Capabilities e delegação atenuada** (macaroons, Biscuit, UCAN e o rascunho IETF *Attenuating Authorization Tokens*): 3.
- **A "lethal trifecta" (Simon Willison, 2025) e a "Agents Rule of Two" (Meta, 2025):** o perigo de juntar dado privado, conteúdo não confiável e ação externa (5 e 6).
- **Controle de fluxo de informação** (CaMeL, FIDES): 5, aqui aplicado pelo executor e seguindo a cadeia de delegação.

O que é nosso: cada princípio é aplicado por código e verificado por teste.
