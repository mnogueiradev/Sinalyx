# Roteiro de apresentação do Sinalyx

## 1. Abertura

Apresentar o problema: logs de firewall registram muitos eventos, mas a análise
manual é lenta e dificulta perceber padrões de anomalia.

## 2. Objetivo

O Sinalyx analisa logs reais do pfSense, agrega eventos em janelas e usa IA com
regras interpretáveis para apoiar a detecção de anomalias.

## 3. Arquitetura

```text
pfSense/logs
-> parser
-> janelas agregadas
-> engenharia de features
-> Autoencoder
-> Isolation Forest
-> Heurística
-> Ensemble
-> Decision Engine
-> PostgreSQL
-> Dashboard
```

## 4. Logs reais do pfSense

Mostrar os quatro cenários:

- normal
- port_scan
- brute_force
- DDoS

## 5. Parser e janelas

Explicar que o parser transforma linhas do pfSense em eventos estruturados e
depois agrega por janela temporal.

## 6. Features

Apresentar as 13 features obrigatórias usadas no runtime, como conexões,
bytes, pacotes, portas e transformações `log1p`.

## 7. Módulos de decisão

- Autoencoder: detector principal individual.
- Isolation Forest: apoio estatístico.
- Heurística: contexto e interpretação.
- Ensemble: agregação dos sinais.
- Decision Engine: decisão final explicável.

## 8. API e PostgreSQL

Mostrar FastAPI, `/health`, histórico, detalhes por janela e persistência no
PostgreSQL.

## 9. Frontend

Demonstrar:

- Dashboard.
- Modo Demo.
- Alertas.
- Histórico com filtros.
- Detalhes da janela.
- Relatórios.
- Sistema.
- Painel admin.

## 10. Demonstração prática

1. Fazer login.
2. Abrir Dashboard.
3. Abrir Modo Demo.
4. Abrir Alertas.
5. Abrir uma janela anômala.
6. Mostrar explicabilidade.
7. Gerar relatório HTML e usar impressão para PDF.

## 11. Resultados

Na rodada limpa de validação:

- normal ficou normal.
- port_scan foi detectado como varredura de portas.
- brute_force foi detectado como força bruta.
- DDoS foi detectado corretamente.
- O PostgreSQL e a API permaneceram funcionais.

## 12. Limitações

- Base real ainda pequena.
- Coleta SSH/SFTP real ainda precisa de validação em ambiente final.
- Não bloqueia ataques automaticamente.
- Não substitui firewall nem equipe técnica.

## 13. Próximos passos

- Ampliar corpus real.
- Validar coleta SSH/SFTP no laboratório.
- Melhorar métricas estatísticas com mais dados.
- Evoluir frontend conforme feedback da banca.

## 14. Encerramento

Reforçar que o Sinalyx entrega um MVP funcional, com dados reais, API,
PostgreSQL e dashboard apresentável.
