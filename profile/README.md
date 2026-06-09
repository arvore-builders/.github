# Árvore Builders 🌱

Este é o espaço onde o time da Árvore publica seus apps e projetos com **segurança por padrão**.

Toda vez que você sobe código aqui, uma revisão de segurança automática (feita por IA) analisa o que mudou e avisa se encontrar algum problema — antes que ele vire dor de cabeça. Você foca em construir; a gente cuida pra que o que você construiu seja seguro.

> 💡 **Não é do time de tecnologia?** Sem problema. Este espaço foi feito pra você. Siga o passo a passo abaixo e, se travar em qualquer ponto, o time de tecnologia ajuda (veja a seção [Precisa de ajuda?](#precisa-de-ajuda)).

---

## O que acontece quando você sobe um projeto

Sempre que você envia código (seja abrindo um *Pull Request* ou subindo direto), acontece automaticamente:

1. 🔍 Uma IA lê as mudanças procurando falhas de segurança (senhas expostas, brechas que permitiriam invasão, etc.)
2. 💬 Se achar algo, ela comenta exatamente onde está o problema e como corrigir
3. 🚨 Se for algo grave, o time recebe um aviso no canal **#security-alerts** no Slack

Você não precisa configurar nada disso manualmente — está tudo pronto pra ser ligado no seu projeto.

---

## Como colocar seu projeto aqui

### 1. Crie ou suba seu repositório nesta organização

Se ainda não tem o projeto aqui, crie um repositório novo ou suba o existente.

### 2. Ligue a revisão de segurança

Na hora de criar o repositório, escolha o template **"Claude Security Review"** na aba **Actions** — são 2 cliques.

Se o projeto já existe, crie o arquivo `.github/workflows/security.yml` com este conteúdo:

```yaml
name: Claude Security Review
on:
  pull_request:
    types: [opened, synchronize, reopened]
  push:
    branches: [main, master]

permissions:
  contents: read
  pull-requests: write

jobs:
  claude-security:
    uses: arvore-builders/.github/.github/workflows/claude-security.yml@main
    secrets:
      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
      SLACK_SECURITY_WEBHOOK: ${{ secrets.SLACK_SECURITY_WEBHOOK }}
```

### 3. Peça as duas chaves de acesso

O projeto precisa de duas "chaves" (chamadas *secrets*) pra funcionar: `ANTHROPIC_API_KEY` e `SLACK_SECURITY_WEBHOOK`.

**Não precisa entender o que elas são** — só peça ao time de tecnologia pra adicioná-las no seu repositório, ou siga a seção técnica abaixo se você mesmo souber fazer.

Pronto. A partir daí, todo código que entrar passa pela revisão. ✅

---

## Para o time de tecnologia

Detalhes de implementação da esteira.

### Arquitetura

```
arvore-builders/.github  (este repositório)
├── .github/workflows/claude-security.yml   workflow reutilizável (fonte única da lógica)
├── .github/security-scripts/               scripts de scan (push) e notificação
└── workflow-templates/claude-security.yml   template oferecido ao criar repos novos
```

- **PRs** usam a action oficial [`anthropics/claude-code-security-review`](https://github.com/anthropics/claude-code-security-review).
- **Pushes diretos** chamam a API da Anthropic sobre o diff do push (cobre quem sobe sem PR).
- Findings **HIGH/CRITICAL** notificam o Slack `#security-alerts` e deixam o check vermelho.

### Secrets (por repositório)

No plano Free, secrets de organização **não chegam em eventos `push`** em repos privados. Por isso os secrets são definidos **por repositório**:

```bash
gh secret set ANTHROPIC_API_KEY      --repo arvore-builders/<repo>
gh secret set SLACK_SECURITY_WEBHOOK --repo arvore-builders/<repo>
```

### Ajustes opcionais

O workflow reutilizável aceita inputs via `with:`:

- `exclude-directories` — pastas a ignorar (padrão: `node_modules,dist,build,.next,coverage,vendor`)
- `claude-model` — troca o modelo Claude (padrão: `claude-sonnet-4-6`)

### Limitações do plano Free (importante)

- **A esteira é informativa, não bloqueante.** Em repositório privado no Free, o GitHub não permite bloquear merge nem impedir push direto (exige plano **Team/Pro**). A defesa atual é detectar + avisar.
- **Sem enforcement automático org-wide.** Cada repo é habilitado individualmente (template + 2 secrets).
- Para bloqueio real e aplicação automática em todos os repos, o caminho é migrar para **GitHub Team**, que destrava branch protection em repos privados e org rulesets.

### Segurança da própria esteira

Este repositório é público e é o ponto de confiança de todos os projetos (todos usam o workflow `@main`). Por isso:
- A branch `main` é protegida (exige PR + 1 aprovação, sem force-push).
- Nenhum secret é versionado — tudo vem de *secrets* do GitHub via variáveis de ambiente.

---

## Precisa de ajuda?

Travou em algum passo, recebeu um alerta de segurança e não sabe o que fazer, ou quer entender um aviso?

👉 Chame o **time de tecnologia** no canal **#security-alerts** no Slack. A gente ajuda a colocar seu projeto no ar com segurança.
