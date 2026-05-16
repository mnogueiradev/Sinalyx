<template>
  <section class="space-y-5">
    <div>
      <h1 class="text-xl font-semibold text-white">Sobre o Sinalyx</h1>
      <p class="mt-2 max-w-3xl text-sm text-slate-400">
        O Sinalyx analisa logs de firewall pfSense com IA para apoiar a detecção de anomalias e classificar possíveis ataques de forma interpretável.
      </p>
    </div>

    <section class="panel p-5">
      <h2 class="text-sm font-semibold text-white">O que o sistema faz</h2>
      <p class="mt-3 text-sm leading-6 text-slate-400">
        O sistema recebe logs reais do pfSense, transforma eventos em janelas agregadas, calcula features compatíveis com os modelos treinados e consolida sinais de IA, heurística e regras de decisão em um resultado exibido no dashboard.
      </p>
    </section>

    <section class="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
      <InfoCard title="IA como apoio" text="Autoencoder e Isolation Forest produzem sinais numéricos para apoiar a detecção." />
      <InfoCard title="Heurística" text="Regras interpretáveis dão contexto para padrões como DDoS, força bruta e varredura." />
      <InfoCard title="Decision Engine" text="Camada final que consolida os sinais e gera classificação, risco e explicação." />
      <InfoCard title="Dashboard" text="Interface para consultar histórico, alertas, detalhes e estado operacional." />
    </section>

    <section class="panel p-5">
      <h2 class="text-sm font-semibold text-white">Arquitetura</h2>
      <div class="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <Step v-for="step in steps" :key="step" :label="step" />
      </div>
    </section>

    <section class="panel p-5">
      <h2 class="text-sm font-semibold text-white">Limites do escopo</h2>
      <p class="mt-3 text-sm leading-6 text-slate-400">
        O Sinalyx não substitui firewall nem promete prever ataques futuros. A proposta desta versão é análise de logs, apoio por IA, persistência e visualização clara para estudo e validação do TCC.
      </p>
    </section>
  </section>
</template>

<script setup lang="ts">
import { defineComponent, h } from 'vue'

const steps = [
  'pfSense/logs',
  'Parser',
  'Janelas agregadas',
  'Engenharia de features',
  'Autoencoder',
  'Isolation Forest',
  'Heurística',
  'Ensemble',
  'Decision Engine',
  'PostgreSQL',
  'Dashboard',
]

const InfoCard = defineComponent({
  props: {
    title: { type: String, required: true },
    text: { type: String, required: true },
  },
  setup(props) {
    return () => h('article', { class: 'panel p-4' }, [
      h('h2', { class: 'text-sm font-semibold text-white' }, props.title),
      h('p', { class: 'mt-2 text-sm leading-6 text-slate-400' }, props.text),
    ])
  },
})

const Step = defineComponent({
  props: {
    label: { type: String, required: true },
  },
  setup(props) {
    return () => h('div', { class: 'rounded-md border border-slate-800 bg-surface-850 p-3 text-sm font-medium text-slate-200' }, props.label)
  },
})
</script>
