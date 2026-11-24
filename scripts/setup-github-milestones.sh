#!/usr/bin/env bash
set -euo pipefail

repo=F3rreir4L19/prometheus
api="repos/$repo"
command -v gh >/dev/null || { printf '%s\n' 'Instale o gh CLI.' >&2; exit 1; }
gh auth status --hostname github.com

# Um processo de setup por vez. As consultas incluem itens abertos e fechados.
declare -A milestones issues issue_titles
body_file=$(mktemp)
trap 'rm -f -- "$body_file"' EXIT

ensure_label() {
    gh label create "$1" --repo "$repo" --color "$2" --description "$3" --force
}

ensure_label 'area:scope-engine' 1D76DB 'Compilação e decisão de política'
ensure_label 'area:storage' 006B75 'SQLite, migrações e auditoria'
ensure_label 'area:runner' 5319E7 'Replay e contenção de recursos'
ensure_label 'area:intel' 7057FF 'Deduplicação e triagem'
ensure_label 'area:control-plane' 0052CC 'Controle e watchdog'
ensure_label security-invariant B60205 'Fronteiras de segurança'
ensure_label fx6300-perf D4C5F9 'Recursos do Data Plane'
ensure_label arm64-termux C5DEF5 'Build e execução no telefone'
ensure_label hitl FBCA04 'Revisão humana'

milestone_rows=$(gh api --hostname github.com --paginate "$api/milestones?state=all&per_page=100" \
    --jq '.[] | [.number, .title] | @tsv')
while IFS=$'\t' read -r number title; do
    if [[ -n "$number" && -n "$title" ]]; then
        milestones["$title"]=$number
    fi
done <<< "$milestone_rows"

ensure_milestone() {
    local title=$1 description=$2
    if [[ -z "${milestones[$title]:-}" ]]; then
        milestones["$title"]=$(gh api --hostname github.com --method POST "$api/milestones" \
            -f "title=$title" -f "description=$description" --jq '.number')
    fi
}

m0='M0 Fundação e Shadow Mode'
m1='M1 Ingestão passiva e delta'
m2='M2 Políticas oficiais'
m3='M3 Inteligência web offline'
m4='M4 Triagem por IA'
m5='M5 Revisão humana'
m6='M6 Escala e recuperação'
m7='M7 Sistema Completo'

ensure_milestone "$m0" 'Fundação offline, política, SQLite WAL e CI.'
ensure_milestone "$m1" 'Importação transacional, descoberta e delta por fixture.'
ensure_milestone "$m2" 'Políticas oficiais HackerOne, Bugcrowd e Intigriti.'
ensure_milestone "$m3" 'Fingerprints, inventário offline e clusters reversíveis.'
ensure_milestone "$m4" 'Redação, cache, budgets e triagem estruturada.'
ensure_milestone "$m5" 'Controle autenticado e revisão humana.'
ensure_milestone "$m6" 'Recuperação, métricas e avaliação de PostgreSQL.'
ensure_milestone "$m7" 'Evidências, calibração e relatório assistido.'

issue_rows=$(gh api --hostname github.com --paginate "$api/issues?state=all&per_page=100" --jq '
    .[] | select(has("pull_request") | not)
    | [(.body // "" | (split("\n") | map(select(startswith("<!-- prometheus-bootstrap:"))) | first) // "-"), .title]
    | @tsv')
while IFS=$'\t' read -r marker title; do
    if [[ -n "$title" ]]; then
        issues["$marker"]=1
        issue_titles["$title"]=1
    fi
done <<< "$issue_rows"

ensure_issue() {
    local id=$1 milestone=$2 label=$3 title=$4 acceptance=$5
    local marker="<!-- prometheus-bootstrap:$id -->"
    if [[ -n "${issues[$marker]:-}" || -n "${issue_titles[$title]:-}" ]]; then
        return
    fi
    printf '%s\n\n## Aceite\n\n%s\n\nUse fixtures sintéticas e verifique AGENTS.md.\n' \
        "$marker" "$acceptance" > "$body_file"
    gh api --hostname github.com --method POST "$api/issues" -f "title=$title" \
        -F "body=@$body_file" -F "milestone=${milestones[$milestone]}" \
        -f "labels[]=$label" --jq '.html_url'
    issues["$marker"]=1
    issue_titles["$title"]=1
}

ensure_issue 01 "$m0" area:scope-engine 'Cobrir URLs ambíguas com uma matriz de regressão' \
    'Cada URL ambígua da fixture responde UNKNOWN; amostras canônicas mantêm o resultado esperado.'
ensure_issue 02 "$m0" fx6300-perf 'Medir memória no replay de política' \
    'Registre pico de RSS e tempo do Shadow Mode com dataset sintético crescente no FX-6300.'
ensure_issue 03 "$m0" arm64-termux 'Verificar ELF musl no Redmi Note 10' \
    'Inspecione AArch64 sem INTERP/NEEDED e registre saída do smoke test em Termux.'
ensure_issue 04 "$m1" area:storage 'Publicar snapshot manual em uma transação' \
    'Falha ao inserir uma regra deixa a revisão ativa intacta; sucesso sela o snapshot.'
ensure_issue 05 "$m1" security-invariant 'Importar feed de descoberta como dados locais' \
    'Um fixture de bounty-targets-data gera candidatos a inventário e nunca muda o snapshot ativo.'
ensure_issue 06 "$m1" area:runner 'Reproduzir observações a partir de arquivos' \
    'Fixtures distinguem replay completo, parcial e truncado sob limite de bytes.'
ensure_issue 07 "$m2" area:scope-engine 'Mapear política exportada do HackerOne' \
    'Fixture cobre inclusão, exclusão e origem autenticada preservada no documento normalizado.'
ensure_issue 08 "$m2" area:scope-engine 'Mapear política exportada do Bugcrowd' \
    'Fixture cobre exclusão e campo desconhecido com bloqueio por padrão.'
ensure_issue 09 "$m2" area:scope-engine 'Mapear política exportada da Intigriti' \
    'Fixture cobre janelas de validade e revisão obsoleta com bloqueio.'
ensure_issue 10 "$m3" area:intel 'Persistir associação reversível por versão' \
    'Um merge e uma reversão preservam observações e atribuição de versão.'
ensure_issue 11 "$m4" area:intel 'Validar triagem adversária contra schema e IDs' \
    'Fixtures rejeitam campo extra e referência a evidência de outro programa.'
ensure_issue 12 "$m5" hitl 'Consumir confirmação de revisão uma única vez' \
    'Duas confirmações simultâneas para o mesmo ID produzem exatamente um consumo; TTL expirado falha.'
