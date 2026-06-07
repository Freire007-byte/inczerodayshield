import { useState } from "react";

const SEVERITIES = {
  CRITICAL: { label: "Crítico", color: "#ff2d55", bg: "#1a0008" },
  HIGH:     { label: "Alto",    color: "#ff6b00", bg: "#1a0800" },
  MEDIUM:   { label: "Médio",   color: "#ffd60a", bg: "#1a1400" },
  LOW:      { label: "Baixo",   color: "#30d158", bg: "#001a08" },
  INFO:     { label: "Info",    color: "#0a84ff", bg: "#000d1a" },
};

const CATEGORIES = {
  N: { label: "REDE/TLS",      color: "#0a84ff" },
  D: { label: "DDoS/DoS",      color: "#ff2d55" },
  W: { label: "WEB APP",       color: "#ff6b00" },
  A: { label: "AUTH",          color: "#ffd60a" },
  P: { label: "API",           color: "#bf5af2" },
  I: { label: "CLOUD/INFRA",   color: "#30d158" },
  M: { label: "NMAP/PORTAS",   color: "#ff9f0a" },
  C: { label: "CONTRATO",      color: "#0a84ff" },
  G: { label: "GHIDRA/BYTEC.", color: "#64d2ff" },
  R: { label: "RECON/OSINT",  color: "#ff375f" },
  V: { label: "CÓDIGO FONTE", color: "#30d158" },
};

const URL_CHECKS = [
  { id:"N01", sev:"CRITICAL", name:"SSL/TLS Config",        desc:"TLS 1.0/1.1 ativo, ciphers fracos (RC4,DES,3DES), BEAST/POODLE/DROWN vulnerável" },
  { id:"N02", sev:"CRITICAL", name:"Certificado SSL",       desc:"Certificado expirado, autoassinado ou chain incompleta — MitM trivial" },
  { id:"N03", sev:"HIGH",     name:"HSTS",                  desc:"Strict-Transport-Security ausente — downgrade HTTP possível via SSLStrip" },
  { id:"N04", sev:"HIGH",     name:"Security Headers",      desc:"CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy ausentes" },
  { id:"N05", sev:"HIGH",     name:"CORS Aberto",           desc:"Access-Control-Allow-Origin:* em endpoints autenticados" },
  { id:"N06", sev:"HIGH",     name:"Versão Exposta",        desc:"Header Server/X-Powered-By expõe versão exata do software" },
  { id:"N07", sev:"MEDIUM",   name:"HTTP→HTTPS",            desc:"Redirect 301 ausente ou mal configurado" },
  { id:"N08", sev:"MEDIUM",   name:"Cookies Inseguros",     desc:"Flags Secure/HttpOnly/SameSite ausentes" },
  { id:"N09", sev:"MEDIUM",   name:"DNS — SPF/DKIM/DMARC", desc:"Registos de segurança de email ausentes — spoofing possível" },
  { id:"N10", sev:"LOW",      name:"DNSSEC",                desc:"DNSSEC não configurado — DNS cache poisoning possível" },
  { id:"N11", sev:"INFO",     name:"Uptime/Latência",       desc:"Disponibilidade e tempo de resposta do servidor" },
  { id:"D01", sev:"CRITICAL", name:"DDoS — Amplificação",  desc:"Serviços UDP abertos (DNS/NTP/SSDP/Memcached) passíveis de amplificação" },
  { id:"D02", sev:"CRITICAL", name:"DDoS — IP Exposto",    desc:"IP real do servidor acessível diretamente sem CDN/WAF" },
  { id:"D03", sev:"CRITICAL", name:"DDoS — Sem WAF",       desc:"Ausência de Cloudflare/AWS Shield para filtrar tráfego L7 malicioso" },
  { id:"D04", sev:"HIGH",     name:"DoS — Slowloris",      desc:"Servidor aceita conexões HTTP parciais indefinidamente sem timeout" },
  { id:"D05", sev:"HIGH",     name:"DoS — HTTP Flood",     desc:"Rate limiting ausente — sem 429, sem backoff, sem CAPTCHA" },
  { id:"D06", sev:"HIGH",     name:"DoS — ReDoS",          desc:"Input aceite em regex sem limite de complexidade — CPU exhaustion" },
  { id:"D07", sev:"HIGH",     name:"DoS — XML Bomb",       desc:"Parser XML sem limite de expansão — Billion Laughs Attack" },
  { id:"D08", sev:"MEDIUM",   name:"DDoS — SYN Flood",    desc:"SYN cookies desativados — backlog TCP esgotado com poucos pacotes" },
  { id:"D09", sev:"MEDIUM",   name:"DoS — Payload Gigante",desc:"Content-Length máximo não configurado — upload consome memória ilimitada" },
  { id:"D10", sev:"MEDIUM",   name:"DoS — WebSocket",     desc:"Conexões WS sem limite por IP — resource exhaustion" },
  { id:"D11", sev:"LOW",      name:"DDoS — Anycast",      desc:"Falta de Anycast routing para distribuir tráfego de ataque" },
  { id:"D12", sev:"LOW",      name:"DDoS — BGP Hijack",   desc:"Ausência de RPKI/ROA — prefixos BGP suscetíveis a hijacking" },
  { id:"W01", sev:"CRITICAL", name:"SQL Injection",        desc:"Parâmetros não sanitizados em queries SQL" },
  { id:"W02", sev:"CRITICAL", name:"RCE",                  desc:"Input executado como código no servidor (eval, exec, system)" },
  { id:"W03", sev:"CRITICAL", name:"Path Traversal",       desc:"../../etc/passwd acessível via parâmetros" },
  { id:"W04", sev:"CRITICAL", name:"File Upload Inseguro", desc:"Upload de .php/.jsp sem validação — webshell possível" },
  { id:"W05", sev:"CRITICAL", name:"SSRF",                 desc:"Servidor faz requests internos via input do utilizador" },
  { id:"W06", sev:"CRITICAL", name:"XXE Injection",        desc:"XML External Entity — leitura de ficheiros locais" },
  { id:"W07", sev:"HIGH",     name:"XSS Refletido",        desc:"Input refletido na resposta sem encoding" },
  { id:"W08", sev:"HIGH",     name:"XSS Armazenado",       desc:"Payload malicioso guardado e executado para todos os visitantes" },
  { id:"W09", sev:"HIGH",     name:"CSRF",                 desc:"Tokens CSRF ausentes — ações forçadas via links maliciosos" },
  { id:"W10", sev:"HIGH",     name:"IDOR",                 desc:"/api/user/123 acessível por qualquer utilizador" },
  { id:"W11", sev:"HIGH",     name:"Open Redirect",        desc:"?redirect= sem whitelist — phishing via domínio legítimo" },
  { id:"W12", sev:"HIGH",     name:"SSTI",                 desc:"Server-Side Template Injection — RCE em Jinja2/Twig" },
  { id:"W13", sev:"MEDIUM",   name:"Clickjacking",         desc:"X-Frame-Options ausente — UI redressing attack" },
  { id:"W14", sev:"MEDIUM",   name:"User Enumeration",     desc:"Login distingue 'user não existe' de 'password errada'" },
  { id:"W15", sev:"MEDIUM",   name:"Stack Trace Exposto",  desc:"Erro 500 expõe paths internos e versões de libs" },
  { id:"W16", sev:"MEDIUM",   name:"Directory Listing",    desc:"Listagem de diretórios ativa — ficheiros sensíveis acessíveis" },
  { id:"W17", sev:"MEDIUM",   name:"Ficheiros de Backup",  desc:".bak/.sql/.env.bak acessíveis publicamente" },
  { id:"W18", sev:"LOW",      name:"Cache Inseguro",       desc:"Respostas sensíveis cacheadas sem Cache-Control: no-store" },
  { id:"W19", sev:"LOW",      name:"Subdomain Takeover",   desc:"CNAME aponta para serviço externo desativado" },
  { id:"A01", sev:"CRITICAL", name:"Admin Exposto",        desc:"/admin, /wp-admin, /phpmyadmin sem autenticação" },
  { id:"A02", sev:"CRITICAL", name:"Credenciais Default",  desc:"admin/admin, root/root ativas em painéis de gestão" },
  { id:"A03", sev:"HIGH",     name:"JWT Fraco",            desc:"alg:none, segredo fraco ou dados sensíveis no payload" },
  { id:"A04", sev:"HIGH",     name:"Sem 2FA",              desc:"Autenticação multi-fator ausente em contas privilegiadas" },
  { id:"A05", sev:"HIGH",     name:"Password Reset Inseguro",desc:"Token de reset previsível, sem expiração ou reutilizável" },
  { id:"A06", sev:"MEDIUM",   name:"Brute Force",          desc:"Sem lockout após tentativas falhadas de login" },
  { id:"A07", sev:"MEDIUM",   name:"Session Timeout",      desc:"Sessões sem expiração por inatividade" },
  { id:"A08", sev:"MEDIUM",   name:"Logout Incompleto",    desc:"Token não invalidado no servidor após logout" },
  { id:"P01", sev:"CRITICAL", name:"API Key Exposta",      desc:"Chaves visíveis em JS/HTML, resposta JSON ou headers" },
  { id:"P02", sev:"HIGH",     name:"GraphQL Introspection",desc:"Schema completo exposto em produção" },
  { id:"P03", sev:"HIGH",     name:"Mass Assignment",      desc:"Campos extra aceites — escalada de privilégios" },
  { id:"P04", sev:"HIGH",     name:"API sem Auth",         desc:"Endpoints /api/* acessíveis sem token" },
  { id:"P05", sev:"MEDIUM",   name:"Rate Limit API",       desc:"Sem rate limiting — scraping e abuso possíveis" },
  { id:"P06", sev:"MEDIUM",   name:"Excessive Data",       desc:"API retorna campos sensíveis desnecessários" },
  { id:"I01", sev:"CRITICAL", name:".env Exposto",         desc:"/.env com credenciais de BD e API keys acessível" },
  { id:"I02", sev:"CRITICAL", name:".git Exposto",         desc:"/.git/config acessível — código fonte reconstruível" },
  { id:"I03", sev:"CRITICAL", name:"S3/Bucket Público",   desc:"Bucket cloud público — dados sensíveis expostos" },
  { id:"I04", sev:"HIGH",     name:"Portas BD Expostas",  desc:"MySQL/PostgreSQL/MongoDB/Redis sem firewall" },
  { id:"I05", sev:"HIGH",     name:"Config Files",         desc:"/config.json, /package.json, /database.yml acessíveis" },
  { id:"I06", sev:"HIGH",     name:"Cloud Metadata SSRF", desc:"169.254.169.254 — credenciais IAM da instância cloud" },
  { id:"I07", sev:"MEDIUM",   name:"Monitoring Exposto",  desc:"Grafana/Prometheus/Kibana sem autenticação" },
  { id:"I08", sev:"LOW",      name:"robots.txt",           desc:"robots.txt revela paths privados de admin ou APIs" },
  { id:"M01", sev:"CRITICAL", name:"NMAP — EternalBlue",  desc:"Porta 445 SMB — MS17-010 WannaCry/NotPetya" },
  { id:"M02", sev:"CRITICAL", name:"NMAP — Docker API",   desc:"Porta 2375/2376 sem TLS — RCE no host" },
  { id:"M03", sev:"HIGH",     name:"NMAP — SSH Fraco",    desc:"SSH com password auth ativo ou versão <8.0" },
  { id:"M04", sev:"HIGH",     name:"NMAP — RDP Exposto",  desc:"Porta 3389 pública — brute force, BlueKeep" },
  { id:"M05", sev:"HIGH",     name:"NMAP — Redis/MongoDB",desc:"Portas 6379/27017 sem autenticação" },
  { id:"M06", sev:"HIGH",     name:"NMAP — Elasticsearch",desc:"Porta 9200 sem auth — todos os dados acessíveis" },
  { id:"M07", sev:"MEDIUM",   name:"NMAP — Portas UDP",   desc:"DNS/NTP/SNMP abertos sem restrição de origem" },
  { id:"M08", sev:"MEDIUM",   name:"NMAP — Jenkins",      desc:"Porta 8080 Jenkins — RCE via Groovy console" },
  { id:"M09", sev:"MEDIUM",   name:"NMAP — Firewall",     desc:"Regras muito permissivas — superfície de ataque grande" },
  { id:"M10", sev:"LOW",      name:"NMAP — Banner Grab",  desc:"Banners de serviços revelam versões exatas" },
  { id:"R01", sev:"CRITICAL", name:"JS Secrets Expostos",  desc:"API keys, tokens, passwords hardcoded em JS/HTML públicos (AWS, Google, Stripe, JWT)" },
  { id:"R02", sev:"HIGH",     name:"CORS Origin Bypass",   desc:"Access-Control-Allow-Origin reflete origem do atacante — requests cross-origin autenticados possíveis" },
  { id:"R03", sev:"HIGH",     name:"Open Redirect",        desc:"Parâmetros ?redirect=/?url=/?next= sem validação — phishing via domínio legítimo" },
  { id:"R04", sev:"HIGH",     name:"Subdomain Takeover",   desc:"Subdomínios admin/dev/staging/internal acessíveis — superfície de ataque alargada" },
  { id:"R05", sev:"MEDIUM",   name:"Tech Stack Exposto",   desc:"Frameworks, CMS e versões detetados nos headers/HTML — facilita exploits direcionados" },
  { id:"R06", sev:"MEDIUM",   name:"Subdomínios Sensíveis",desc:"Subdomínios de infraestrutura (kibana, grafana, jenkins) acessíveis sem autenticação" },
];

const CODE_CHECKS = [
  { id:"V01", sev:"CRITICAL", name:"SQL Injection",        desc:"Queries com string concatenation/interpolação direta de input do utilizador" },
  { id:"V02", sev:"CRITICAL", name:"Command Injection",    desc:"exec/system/shell_exec/child_process com input não sanitizado — RCE" },
  { id:"V03", sev:"CRITICAL", name:"Deserialização Inseg.",desc:"pickle.loads/unserialize/ObjectInputStream de fonte não confiável" },
  { id:"V04", sev:"CRITICAL", name:"SSTI",                 desc:"Template engines com input direto — Jinja2/Twig/Pebble/Handlebars" },
  { id:"V05", sev:"CRITICAL", name:"Path Traversal",       desc:"../.. em file paths, open/readFile com input do utilizador" },
  { id:"V06", sev:"CRITICAL", name:"Hardcoded Secrets",    desc:"API keys, passwords, tokens, connection strings no código fonte" },
  { id:"V07", sev:"CRITICAL", name:"XXE",                  desc:"XML parser sem disableExternalEntities — leitura de ficheiros locais" },
  { id:"V08", sev:"CRITICAL", name:"Prototype Pollution",  desc:"Object.assign/__proto__/constructor merge sem sanitização — Node.js" },
  { id:"V09", sev:"HIGH",     name:"XSS",                  desc:"innerHTML/document.write/eval com dados do utilizador" },
  { id:"V10", sev:"HIGH",     name:"SSRF",                 desc:"fetch/http.get/requests.get com URL controlado pelo utilizador" },
  { id:"V11", sev:"HIGH",     name:"CSRF",                 desc:"Rotas POST/PUT/DELETE sem verificação de token ou origin" },
  { id:"V12", sev:"HIGH",     name:"Broken Auth",          desc:"Tokens sem expiração, validação fraca de JWT, passwords plaintext" },
  { id:"V13", sev:"HIGH",     name:"IDOR",                 desc:"Acesso a recursos por ID sem verificação de ownership" },
  { id:"V14", sev:"HIGH",     name:"ReDoS",                desc:"Regex com backtracking exponencial em input não limitado" },
  { id:"V15", sev:"HIGH",     name:"Race Condition",       desc:"Operações check-then-act sem locks — TOCTOU" },
  { id:"V16", sev:"HIGH",     name:"Eval Inseguro",        desc:"eval/exec/Function/vm.runInNewContext com input externo" },
  { id:"V17", sev:"MEDIUM",   name:"Error Info Leak",      desc:"Stack traces, erros internos ou config expostos em respostas" },
  { id:"V18", sev:"MEDIUM",   name:"Log Injection",        desc:"Input do utilizador em logs sem sanitização — log forging" },
  { id:"V19", sev:"MEDIUM",   name:"Dependency Vuln",      desc:"Dependências antigas com CVEs conhecidos (npm/pip/composer)" },
  { id:"V20", sev:"MEDIUM",   name:"Broken Access Control",desc:"Verificações de permissão ausentes em funções privilegiadas" },
  { id:"V21", sev:"MEDIUM",   name:"Weak Crypto",          desc:"MD5/SHA1 para passwords, IV fixo, ECB mode, chaves fracas" },
  { id:"V22", sev:"MEDIUM",   name:"Open Redirect",        desc:"Redirect para URL fornecida pelo utilizador sem whitelist" },
  { id:"V23", sev:"LOW",      name:"Verbose Logging",      desc:"Passwords, tokens ou dados sensíveis escritos em logs" },
  { id:"V24", sev:"LOW",      name:"Dead Code / Debug",    desc:"console.log com dados sensíveis, TODO de segurança, debugger" },
  { id:"V25", sev:"INFO",     name:"Code Quality",         desc:"Padrões que aumentam a superfície de ataque" },
];

const CONTRACT_CHECKS = [
  { id:"C01", sev:"CRITICAL", name:"Reentrancy",             desc:"Estado atualizado após chamada externa — sem ReentrancyGuard" },
  { id:"C02", sev:"CRITICAL", name:"Access Control",         desc:"Funções privilegiadas sem onlyOwner/AccessControl" },
  { id:"C03", sev:"CRITICAL", name:"Integer Overflow",       desc:"Aritmética sem SafeMath em Solidity <0.8.0" },
  { id:"C04", sev:"CRITICAL", name:"Delegatecall Inseguro",  desc:"delegatecall para endereço do utilizador — storage corruption" },
  { id:"C05", sev:"CRITICAL", name:"Selfdestruct",           desc:"selfdestruct sem multisig — destruição irreversível" },
  { id:"C06", sev:"CRITICAL", name:"Arbitrary Call",         desc:"call{value}(data) com target e data do utilizador" },
  { id:"C07", sev:"CRITICAL", name:"Proxy Não Inicializado", desc:"initialize() público — proxy takeover possível" },
  { id:"C08", sev:"HIGH",     name:"Oracle Manipulation",   desc:"Price feed único sem heartbeat check ou TWAP" },
  { id:"C09", sev:"HIGH",     name:"Front-Running / MEV",   desc:"Sem deadline ou slippage — sandwich attacks possíveis" },
  { id:"C10", sev:"HIGH",     name:"Flash Loan Attack",     desc:"Preço manipulável em única transação" },
  { id:"C11", sev:"HIGH",     name:"Tx.origin Auth",        desc:"tx.origin em vez de msg.sender — phishing contract" },
  { id:"C12", sev:"HIGH",     name:"Block.timestamp",       desc:"Lógica crítica baseada em timestamp manipulável" },
  { id:"C13", sev:"HIGH",     name:"Signature Replay",      desc:"Assinaturas sem nonce ou chainId — reutilizáveis" },
  { id:"C14", sev:"HIGH",     name:"Griefing / DoS",        desc:"Transfer em loop — um revert bloqueia todos" },
  { id:"C15", sev:"MEDIUM",   name:"Centralização",         desc:"Owner pode drain sem timelock ou multisig" },
  { id:"C16", sev:"MEDIUM",   name:"Unbounded Loops",       desc:"Loops sobre arrays dinâmicos — gas limit DoS" },
  { id:"C17", sev:"MEDIUM",   name:"Missing Events",        desc:"Funções críticas sem emit de eventos" },
  { id:"C18", sev:"MEDIUM",   name:"Emergency Pause",       desc:"Sem Pausable pattern para reagir a exploits" },
  { id:"C19", sev:"MEDIUM",   name:"ERC20 Return Check",    desc:"transfer sem verificação de bool — falha silenciosa" },
  { id:"C20", sev:"MEDIUM",   name:"Storage Collision",     desc:"Proxy + implementation com slots conflituantes" },
  { id:"C21", sev:"LOW",      name:"rescueERC20",           desc:"Sem função de resgate de tokens acidentalmente enviados" },
  { id:"C22", sev:"LOW",      name:"Pragma Flutuante",      desc:"^0.8.x em vez de versão fixada" },
  { id:"C23", sev:"INFO",     name:"NatSpec",               desc:"Documentação de funções ausente ou incompleta" },
  { id:"G01", sev:"CRITICAL", name:"GHIDRA — Função Oculta",desc:"Bytecode EVM tem CALL/DELEGATECALL não visíveis no ABI" },
  { id:"G02", sev:"CRITICAL", name:"GHIDRA — Metamorphic",  desc:"Padrão CREATE2+SELFDESTRUCT — reimplantação com lógica diferente" },
  { id:"G03", sev:"CRITICAL", name:"GHIDRA — Selfdestruct Oculto",desc:"SELFDESTRUCT em assembly inline não visível no código fonte" },
  { id:"G04", sev:"HIGH",     name:"GHIDRA — JUMPI Suspeito",desc:"JUMPs para destinos calculados dinamicamente" },
  { id:"G05", sev:"HIGH",     name:"GHIDRA — Assembly Inseguro",desc:"mstore/mload em assembly sem limites — memory corruption" },
  { id:"G06", sev:"MEDIUM",   name:"GHIDRA — Selector Clash",desc:"Colisão de seletores de função (4 bytes) no ABI" },
  { id:"G07", sev:"LOW",      name:"GHIDRA — Versão Compilador",desc:"Bytecode identifica versão exata do compilador Solidity" },
];

const GITHUB_TOOLS = [
  { cat:"NMAP",    name:"nmap",         desc:"Network scanner — port scan, service detection, OS fingerprint",        url:"https://github.com/nmap/nmap",                      stars:"10k+" },
  { cat:"NMAP",    name:"masscan",      desc:"Port scanner ultra-rápido — scan de internet completa",                 url:"https://github.com/robertdavidgraham/masscan",      stars:"23k+" },
  { cat:"NMAP",    name:"nmap NSE",     desc:"Scripts NSE para vulnerabilidades específicas (EternalBlue, etc.)",     url:"https://github.com/scipag/vulscan",                 stars:"3.4k" },
  { cat:"REVERSING",name:"ghidra",      desc:"NSA reverse engineering — bytecode EVM e binários",                     url:"https://github.com/NationalSecurityAgency/ghidra",  stars:"53k+" },
  { cat:"REVERSING",name:"pyevmasm",    desc:"EVM bytecode disassembler — contratos sem código fonte",                url:"https://github.com/crytic/pyevmasm",                stars:"1.2k" },
  { cat:"WEB APP", name:"nuclei",       desc:"Template-based scanner — 8000+ templates de vulnerabilidades",          url:"https://github.com/projectdiscovery/nuclei",        stars:"22k+" },
  { cat:"WEB APP", name:"sqlmap",       desc:"SQL injection detection e exploitation automático",                      url:"https://github.com/sqlmapproject/sqlmap",           stars:"33k+" },
  { cat:"WEB APP", name:"nikto",        desc:"Web server scanner — 6700+ checks",                                     url:"https://github.com/sullo/nikto",                    stars:"8.2k" },
  { cat:"WEB APP", name:"ffuf",         desc:"Fast web fuzzer — endpoints, parâmetros, subdomínios",                  url:"https://github.com/ffuf/ffuf",                      stars:"13k+" },
  { cat:"DDOS",    name:"slowhttptest", desc:"Slowloris, Slow Read, Apache Killer",                                    url:"https://github.com/shekyan/slowhttptest",           stars:"2.3k" },
  { cat:"DDOS",    name:"hping3",       desc:"TCP/IP packet tool — SYN flood, DDoS simulation",                       url:"https://github.com/antirez/hping",                  stars:"1.4k" },
  { cat:"CONTRACT",name:"slither",      desc:"Solidity static analyzer — reentrancy, overflow, access control",       url:"https://github.com/crytic/slither",                 stars:"5.5k" },
  { cat:"CONTRACT",name:"mythril",      desc:"EVM symbolic execution — detecta vulnerabilidades on-chain",             url:"https://github.com/Consensys/mythril",              stars:"3.6k" },
  { cat:"CONTRACT",name:"echidna",      desc:"Fuzzer de smart contracts — testa invariantes",                          url:"https://github.com/crytic/echidna",                 stars:"2.8k" },
  { cat:"CONTRACT",name:"foundry",      desc:"Toolchain Solidity — testes, fuzzing, debug de contratos",              url:"https://github.com/foundry-rs/foundry",             stars:"8.9k+" },
  { cat:"RECON",   name:"subfinder",    desc:"Subdomain discovery massivo",                                            url:"https://github.com/projectdiscovery/subfinder",     stars:"11k+" },
  { cat:"RECON",   name:"amass",        desc:"Attack surface mapping — DNS, certs SSL",                               url:"https://github.com/owasp-amass/amass",              stars:"12k+" },
  { cat:"RECON",   name:"theHarvester", desc:"OSINT — emails, subdomínios, IPs de motores de busca",                  url:"https://github.com/laramies/theHarvester",          stars:"11k+" },
  { cat:"RECON",   name:"shodan-python",desc:"API Shodan — descoberta de dispositivos e serviços expostos",            url:"https://github.com/achillean/shodan-python",        stars:"2.2k" },
  { cat:"RECON",   name:"httpx",        desc:"HTTP toolkit — fingerprint, status, tech stack em massa",               url:"https://github.com/projectdiscovery/httpx",         stars:"8.3k" },
  { cat:"RECON",   name:"dnsx",         desc:"DNS toolkit rápido — resolução em massa, brute force de subdomínios",   url:"https://github.com/projectdiscovery/dnsx",          stars:"2.3k" },
  { cat:"RECON",   name:"gau",          desc:"Get All URLs — URLs históricas de Wayback Machine e Common Crawl",      url:"https://github.com/lc/gau",                         stars:"3.7k" },
  { cat:"RECON",   name:"waybackurls",  desc:"Extrai URLs antigas do Wayback Machine — endpoints abandonados",        url:"https://github.com/tomnomnom/waybackurls",          stars:"3.1k" },
  { cat:"SECRETS", name:"trufflehog",   desc:"Scan de secrets em git repos, S3, filesystem — 700+ detetores",        url:"https://github.com/trufflesecurity/trufflehog",     stars:"18k+" },
  { cat:"SECRETS", name:"gitleaks",     desc:"Scan de API keys e tokens em repositórios git",                         url:"https://github.com/gitleaks/gitleaks",              stars:"18k+" },
  { cat:"SECRETS", name:"secretfinder", desc:"Extrai API keys e secrets de JS files em tempo real",                   url:"https://github.com/m4ll0k/SecretFinder",            stars:"3.3k" },
  { cat:"NETWORK", name:"wireshark",    desc:"Network protocol analyzer — captura e análise em tempo real",            url:"https://github.com/wireshark/wireshark",            stars:"7.5k" },
  { cat:"NETWORK", name:"bettercap",    desc:"MitM framework — ARP spoofing, SSL stripping",                          url:"https://github.com/bettercap/bettercap",            stars:"17k+" },
  { cat:"NETWORK", name:"responder",    desc:"LLMNR/NBT-NS poisoner — captura de hashes NTLM em redes Windows",      url:"https://github.com/lgandx/Responder",               stars:"5.4k" },
  { cat:"EXPLOIT", name:"metasploit",   desc:"Framework de exploits — 2000+ módulos para pentest",                    url:"https://github.com/rapid7/metasploit-framework",    stars:"34k+" },
  { cat:"EXPLOIT", name:"exploitdb",    desc:"Base de dados de exploits — searchsploit para CVEs conhecidos",         url:"https://github.com/offensive-security/exploitdb",  stars:"3.5k" },
  { cat:"EXPLOIT", name:"pwntools",     desc:"CTF framework — exploit desenvolvimento, ROP chains, shellcode",        url:"https://github.com/Gallopsled/pwntools",            stars:"12k+" },
  { cat:"FUZZ",    name:"boofuzz",      desc:"Network protocol fuzzer — successor do Sulley",                         url:"https://github.com/jtpereyda/boofuzz",              stars:"2.1k" },
  { cat:"FUZZ",    name:"wfuzz",        desc:"Web fuzzer — brute force de dirs, params, auth, headers",               url:"https://github.com/xmendez/wfuzz",                  stars:"5.8k" },
  { cat:"AUTH",    name:"hashcat",      desc:"Password cracker — GPU accelerated, 300+ algoritmos",                   url:"https://github.com/hashcat/hashcat",                stars:"22k+" },
  { cat:"AUTH",    name:"john",         desc:"John the Ripper — offline password cracking",                           url:"https://github.com/openwall/john",                  stars:"10k+" },
  { cat:"AUTH",    name:"hydra",        desc:"Brute force de autenticação — SSH, FTP, HTTP, SMB, RDP",               url:"https://github.com/vanhauser-thc/thc-hydra",        stars:"10k+" },
];

// ─── components ─────────────────────────────────────────────────────────────

function SeverityBadge({ sev }) {
  const s = SEVERITIES[sev];
  return (
    <span style={{
      background: s.bg, color: s.color, border: `1px solid ${s.color}40`,
      borderRadius: 4, padding: "2px 8px", fontSize: 11,
      fontFamily: "monospace", fontWeight: 700, letterSpacing: 1,
    }}>{s.label.toUpperCase()}</span>
  );
}

function ScoreRing({ score }) {
  const r = 54, circ = 2 * Math.PI * r;
  const color = score >= 80 ? "#30d158" : score >= 50 ? "#ffd60a" : "#ff2d55";
  return (
    <div style={{ position: "relative", width: 140, height: 140, margin: "0 auto" }}>
      <svg width={140} height={140} style={{ transform: "rotate(-90deg)" }}>
        <circle cx={70} cy={70} r={r} fill="none" stroke="#1a1a2e" strokeWidth={12} />
        <circle cx={70} cy={70} r={r} fill="none" stroke={color} strokeWidth={12}
          strokeDasharray={`${(score/100)*circ} ${circ}`}
          strokeLinecap="round" style={{ transition: "stroke-dasharray 1s ease" }} />
      </svg>
      <div style={{ position:"absolute", top:0, left:0, right:0, bottom:0,
        display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center" }}>
        <span style={{ fontSize:32, fontWeight:900, color, fontFamily:"'Courier New', monospace" }}>{score}</span>
        <span style={{ fontSize:11, color:"#666", letterSpacing:2 }}>/ 100</span>
      </div>
    </div>
  );
}

function catColor(id) { return CATEGORIES[id[0]]?.color || "#888"; }

// ─── main ────────────────────────────────────────────────────────────────────

// ── Padrões de vulnerabilidade por linguagem ─────────────────────────────────
const CODE_PATTERNS = {
  V01: [/[`'"].*(?:SELECT|INSERT|UPDATE|DELETE).*\$\{/i, /\.query\s*\([^)]*\+/, /execute\s*\([^)]*%s/, /f["']SELECT.*\{/i, /cursor\.execute\s*\([^)]*%/],
  V02: [/\b(exec|system|shell_exec|popen)\s*\([^)]*(?:req\.|_GET|_POST|input|user|param)/i, /child_process\.(exec|execSync|spawn)\s*\([^)]*(?:req\.|body\.|params\.|query\.)/,/subprocess\.(call|run|Popen)\s*\([^)]*(?:request\.|input|user)/i],
  V03: [/pickle\.loads?\s*\(/, /yaml\.load\s*\((?!.*Loader)/, /unserialize\s*\(/, /ObjectInputStream/, /Marshal\.load/],
  V04: [/render_template_string\s*\([^)]*(?:req\.|request\.|input|user)/, /Environment\(\)\.from_string/, /ejs\.render\s*\([^)]*req/, /nunjucks\.renderString\s*\([^)]*req/, /Handlebars\.compile\s*\([^)]*req/],
  V05: [/(?:readFile|readFileSync|open|fopen|file_get_contents)\s*\([^)]*(?:req\.|_GET|_POST|params\.|body\.|query\.|input|user)/i, /path\.join\s*\([^)]*(?:req\.|params\.|query\.|body\.)/],
  V06: [/(password|passwd|secret|api_?key|token|private_?key|access_?key|auth)\s*[=:]\s*["'][^"']{8,}/i, /AKIA[0-9A-Z]{16}/, /sk-[A-Za-z0-9]{48}/, /sk-ant-[A-Za-z0-9_-]{40}/],
  V07: [/(?:parseXML|DOMParser|SAXParser|libxml|XMLReader)/, /loadXML/, /LIBXML_NOENT/],
  V08: [/__proto__/, /constructor\s*\[\s*["']prototype/, /Object\.assign\s*\([^)]*(?:req\.|body\.|params\.)/, /merge\s*\([^)]*(?:req\.|body\.|params\.)/],
  V09: [/innerHTML\s*=\s*[^"'`]*(?:req\.|params\.|query\.|body\.|user\.|input)/, /document\.write\s*\([^)]*(?:req\.|location\.|hash)/, /dangerouslySetInnerHTML/, /\.html\s*\([^)]*(?:req\.|params\.|query\.)/],
  V10: [/(?:fetch|axios\.get|http\.get|requests\.get|urllib\.urlopen|curl_exec)\s*\([^)]*(?:req\.|params\.|query\.|body\.|url|host|endpoint)/i],
  V11: [/app\.(post|put|delete|patch)\s*\(/, /router\.(post|put|delete|patch)\s*\(/],
  V12: [/(?:md5|sha1)\s*\([^)]*(?:password|passwd)/i, /(?:password|passwd)\s*==\s*(?:req\.|input|user)/, /algorithm.*["']none["']/, /jwt\.sign\s*\([^)]*,\s*["']["']/, /Math\.random\s*\(\s*\).*(?:token|key|secret)/i],
  V13: [/findById\s*\([^)]*(?:req\.|params\.|query\.)/, /getById\s*\([^)]*req\./, /WHERE.*id\s*=\s*(?:req\.|params\.|query\.)/i],
  V14: [/new RegExp\s*\([^)]*\+/, /\/((?:[^/]*[+*]){2,})\//],
  V15: [/(?:readFile|stat|access)\s*\([\s\S]{0,100}(?:writeFile|unlink|rename)\s*\(/],
  V16: [/\beval\s*\([^)]*(?:req\.|params\.|query\.|body\.|user\.|input)/, /Function\s*\(\s*(?:req\.|params\.|query\.)/, /vm\.runInNewContext\s*\([^)]*req/],
  V17: [/(?:res\.json|res\.send)\s*\([^)]*(?:err|error|stack|e\.message)/, /catch\s*\([^)]*\)\s*\{[^}]*res\.(?:json|send)\s*\([^)]*(?:err|error|e)\b/],
  V18: [/(?:console\.log|logger\.\w+)\s*\([^)]*(?:req\.|params\.|query\.|body\.|request\.)/],
  V19: [/"version"\s*:\s*"\^?0\.\d|"dependencies"\s*:\s*\{[\s\S]{0,2000}\}/],
  V20: [/function\s+\w+\s*\([^)]*\)\s*\{(?![\s\S]{0,500}(?:isAdmin|hasRole|checkAuth|authorize|permission))/],
  V21: [/\b(?:md5|sha1|sha-1|DES|RC4|AES-ECB)\s*\(|createCipher\b(?!iv)|Math\.random\s*\(\s*\).*(?:salt|nonce|iv)/i],
  V22: [/res\.redirect\s*\([^)]*(?:req\.|params\.|query\.|body\.)/, /header\s*\(\s*["']Location["']\s*,\s*(?:req\.|request\.)/],
  V23: [/(?:console\.log|print|logger)\s*\([^)]*(?:password|secret|token|key|credential)/i],
  V24: [/console\.log\s*\([^)]*(?:password|secret|token)/, /\/\/\s*(?:TODO|FIXME|HACK).*(?:security|auth|vuln)/i, /\bdebugger\b/],
  V25: [/setTimeout\s*\([^)]*user/, /setInterval\s*\([^)]*req\./],
};

const CONTRACT_PATTERNS = {
  C01: [/\.call\s*\{[^}]*value[^}]*\}|\.transfer\s*\(|\.send\s*\(/, /\.call\s*\(/],
  C02: [/function\s+\w+\s*\([^)]*\)\s*(?:external|public)(?![\s\S]{0,200}(?:onlyOwner|onlyRole|require\s*\(\s*msg\.sender|modifier))/],
  C03: [/pragma solidity\s*\^?0\.[0-7]\.|uint\d*.*[+\-\*](?!.*SafeMath|.*unchecked)/],
  C04: [/delegatecall\s*\(/, /\.delegatecall\s*\(/],
  C05: [/selfdestruct\s*\(/, /suicide\s*\(/],
  C06: [/\.call\s*\{[^}]*value[^}]*\}\s*\([^)]*(?:data|input|_data)/, /\.call\s*\([^)]*(?:data|input)/],
  C07: [/function\s+initialize\s*\(.*\)\s*(?:external|public)(?!.*initializer)/],
  C08: [/latestAnswer\s*\(\s*\)|latestRoundData\s*\(\s*\)(?![\s\S]{0,300}require)/],
  C09: [/swap\s*\w*\s*\([^)]*\)(?![\s\S]{0,200}deadline)/, /amountOutMin\s*==\s*0|slippage.*100/],
  C10: [/flashLoan|flashBorrow|callback.*IFlash/],
  C11: [/tx\.origin\s*==|require\s*\(\s*tx\.origin/],
  C12: [/block\.timestamp(?![\s\S]{0,100}require\s*\([^)]*(?:<=|>=|<|>)[^)]*\d{4,})/, /now\s*[+\-\*]/],
  C13: [/ecrecover\s*\((?![\s\S]{0,300}nonce|[\s\S]{0,300}chainId)/],
  C14: [/for\s*\([^)]*\.length[^)]*\)[^{]*\{[^}]*\.transfer|\.transfer\s*\([^)]*\)[^;]*;[^}]*}/],
  C15: [/function\s+\w+\s*\([^)]*\)\s*(?:external|public)\s*onlyOwner(?![\s\S]{0,300}timelock|[\s\S]{0,300}multisig)/],
  C16: [/for\s*\([^;]*;\s*\w+\s*<\s*\w+\.length/],
  C17: [/function\s+(?:transfer|mint|burn|withdraw|deposit)\s*\([^)]*\)(?![\s\S]{0,500}emit\s+)/],
  C18: [/contract\s+\w+(?![\s\S]{0,500}Pausable|[\s\S]{0,500}pause)/],
  C19: [/\.transfer\s*\([^)]*\)(?![^;]*require\s*\(|[^;]*bool)/, /IERC20\([^)]*\)\.transfer\s*\([^)]*\)(?![^;]*require)/],
  C20: [/\+\+\s*\d\s*;|assembly\s*\{[^}]*sload/],
  C21: [],
  C22: [/pragma solidity\s*\^|pragma solidity\s*>=?[^;]*</],
  C23: [/function\s+\w+\s*\([^)]*\)(?![\s\S]{0,50}\/\*\*|[\s\S]{0,50}\/\/\/)/],
  G01: [/assembly\s*\{[^}]*call\b/, /bytes4\s*selector\s*=\s*bytes4\s*\(/],
  G02: [/CREATE2|selfdestruct[\s\S]{0,500}CREATE/, /create2\s*\(/i],
  G03: [/assembly\s*\{[^}]*selfdestruct/, /assembly\s*\{[^}]*0x55/],
  G04: [/assembly\s*\{[^}]*jumpi/, /assembly\s*\{[^}]*jump\b/],
  G05: [/assembly\s*\{[^}]*mstore\s*\([^)]*\w+/, /assembly\s*\{[^}]*mload/],
  G06: [],
  G07: [/\/\/ SPDX|pragma solidity/],
};

function scanPatterns(code, patterns) {
  for (const rx of patterns) {
    const m = code.match(rx);
    if (m) return { found: true, sample: m[0].slice(0, 120) };
  }
  return { found: false };
}

function analyzeCode(code, checks, isContract = false) {
  const patternMap = isContract ? CONTRACT_PATTERNS : CODE_PATTERNS;
  const findings = checks.map(c => {
    const pats = patternMap[c.id] || [];
    let status = "OK", detail = "", fix = "";
    if (pats.length === 0) {
      status = "WARNING";
      detail = `${c.name} — verificação manual recomendada para este padrão.`;
      fix = c.desc;
    } else {
      const res = scanPatterns(code, pats);
      if (res.found) {
        status = "VULNERABLE";
        detail = `Padrão detetado: \`${res.sample.replace(/\n/g, " ")}\` — ${c.desc}`;
        fix = getFix(c.id);
      } else {
        status = "OK";
        detail = `Nenhum padrão de ${c.name} detetado na análise estática.`;
      }
    }
    return { id: c.id, severity: c.sev, name: c.name, status, detail, fix };
  });

  const vc = findings.filter(f => f.status === "VULNERABLE" && f.severity === "CRITICAL").length;
  const vh = findings.filter(f => f.status === "VULNERABLE" && f.severity === "HIGH").length;
  const vm = findings.filter(f => f.status === "VULNERABLE" && f.severity === "MEDIUM").length;
  const score = Math.max(0, 100 - vc * 18 - vh * 10 - vm * 4);
  const vl = findings.filter(f => f.status === "VULNERABLE").map(f => f.name);
  const summary = vl.length === 0
    ? `Análise estática concluída — nenhum padrão vulnerável detetado. Score: ${score}/100. Recomenda-se revisão manual para lógica de negócio.`
    : `${vl.length} vulnerabilidade(s) detetadas: ${vl.slice(0, 5).join(", ")}${vl.length > 5 ? ` e mais ${vl.length - 5}` : ""}. Score: ${score}/100.`;
  return { score, summary, findings };
}

function getFix(id) {
  const fixes = {
    V01: "Usa prepared statements/queries parametrizadas. Nunca concatenas input do utilizador em SQL.",
    V02: "Nunca passas input externo para exec/system. Usa APIs nativas em vez de subprocessos.",
    V03: "Não deserializas dados de fontes não confiáveis. Usa formatos seguros como JSON com validação de schema.",
    V04: "Nunca renderizas input do utilizador como template. Usa auto-escape e renderização de valores, não de código.",
    V05: "Valida e normaliza paths com path.resolve(). Rejeita paths que contenham '../'.",
    V06: "Move todas as credenciais para variáveis de ambiente (.env). Roga as chaves expostas imediatamente.",
    V07: "Desativa external entities no parser XML: setFeature(FEATURE_SECURE_PROCESSING, true).",
    V08: "Valida chaves de objetos antes de merge. Rejeita '__proto__' e 'constructor' como chaves.",
    V09: "Usa textContent em vez de innerHTML. Sanitiza com DOMPurify antes de qualquer renderização HTML.",
    V10: "Valida URLs contra whitelist de domínios permitidos. Bloqueia IPs internos (169.254.x.x, 10.x.x.x, etc.).",
    V11: "Adiciona middleware CSRF (csurf) em todas as rotas POST/PUT/DELETE.",
    V12: "Usa bcrypt/argon2 para passwords. Usa RS256/ES256 para JWT. Nunca uses alg:none.",
    V13: "Verifica ownership do recurso: if (resource.userId !== req.user.id) return 403.",
    V14: "Usa regex com limites. Testa complexidade com ferramentas como safe-regex.",
    V15: "Usa operações atômicas ou locks. Evita padrões check-then-act em recursos partilhados.",
    V16: "Nunca usas eval() com input externo. Usa JSON.parse() para dados estruturados.",
    V17: "Não expões stack traces ou mensagens de erro internas. Usa IDs de erro para lookup interno.",
    V18: "Sanitiza input antes de escrever em logs. Usa loggers estruturados com campos separados.",
    V19: "Executa 'npm audit' / 'pip-audit'. Atualiza dependências vulneráveis.",
    V20: "Adiciona verificações de autorização explícitas em cada função que acede a recursos.",
    V21: "Usa SHA-256+ para hashing. AES-GCM ou ChaCha20-Poly1305 para encriptação. crypto.randomBytes() para tokens.",
    V22: "Implementa whitelist de URLs de redirect permitidas. Rejeita URLs absolutas de domínios externos.",
    V23: "Remove logs com dados sensíveis. Usa log levels e filtra campos sensíveis.",
    V24: "Remove console.log de dados sensíveis e declarações debugger antes de produção.",
    V25: "Revisa timeouts e intervals com dados externos para evitar execução arbitrária.",
    C01: "Atualiza estado ANTES de chamadas externas (Checks-Effects-Interactions). Usa ReentrancyGuard da OpenZeppelin.",
    C02: "Adiciona modifier onlyOwner ou AccessControl a todas as funções privilegiadas.",
    C03: "Usa Solidity ≥0.8.0 (overflow automático). Em versões antigas, usa SafeMath.",
    C04: "Nunca usas delegatecall para endereços fornecidos pelo utilizador.",
    C05: "Protege selfdestruct com multisig ou timelock.",
    C06: "Valida o target e os dados do call. Usa interfaces tipadas em vez de call baixo nível.",
    C07: "Adiciona modifier initializer (OpenZeppelin) e chama _disableInitializers() no constructor.",
    C08: "Usa TWAP price feeds. Valida freshness com require(block.timestamp - updatedAt < MAX_DELAY).",
    C09: "Adiciona parâmetro deadline e amountOutMin > 0 em swaps.",
    C10: "Adiciona validação de estado antes/depois em callbacks de flash loan.",
    C11: "Substitui tx.origin por msg.sender para autenticação.",
    C12: "Não usas block.timestamp como fonte de aleatoriedade. Usa Chainlink VRF.",
    C13: "Inclui nonce, chainId e endereço do contrato na mensagem assinada.",
    C14: "Evita loops com transfers. Usa padrão pull-payment (withdraw pattern).",
    C15: "Adiciona timelock de 24-48h ou multisig para funções críticas de owner.",
    C16: "Limita tamanho de arrays ou usa paginação para evitar gas limit.",
    C17: "Emite eventos em todas as funções críticas para auditabilidade on-chain.",
    C18: "Herda de Pausable (OpenZeppelin) e adiciona whenNotPaused às funções críticas.",
    C19: "Usa SafeERC20 da OpenZeppelin: safeTransfer() em vez de transfer().",
    C20: "Verifica slots de storage para evitar colisões em upgradeable proxies. Usa ERC-1967.",
    C22: "Fixa a versão do compilador: pragma solidity 0.8.20; (sem ^ ou >=).",
    C23: "Adiciona NatSpec (@notice, @param, @return) a todas as funções públicas.",
    G01: "Audita bytecode com Etherscan verified source ou Dedaub decompiler.",
    G02: "Cuidado com contratos CREATE2 — podem ser reimplantados com lógica diferente.",
    G03: "Procura SELFDESTRUCT em assembly inline que pode não aparecer no ABI.",
    G04: "JUMPs para destinos calculados são difíceis de auditar — verifica o bytecode.",
    G05: "Operações de memória em assembly devem ter limites explícitos.",
  };
  return fixes[id] || "Corrige o padrão identificado seguindo as melhores práticas OWASP.";
}

function analyzeProbe(probeData, checks) {
  const h = probeData.headers || {};
  const ssl = probeData.ssl || {};
  const dns = probeData.dns || {};
  const ports = probeData.ports || {};
  const paths = probeData.paths || {};
  const cdn = probeData.cdn || {};
  const rateLimit = probeData.rateLimit || {};
  const slowloris = probeData.slowloris || {};
  const cors = probeData.cors || {};
  const jsSecrets = probeData.jsSecrets || {};
  const openRedirect = probeData.openRedirect || {};
  const subdomains = probeData.subdomains || {};
  const http = probeData.http || {};

  const findings = checks.map(c => {
    let status = "WARNING", detail = "", fix = "";
    switch (c.id) {
      case "N01":
        if (!ssl.ok) { status="WARNING"; detail="SSL não verificável."; fix="Garante HTTPS ativo na porta 443."; }
        else if (ssl.isWeakProto || ssl.isWeakCipher) { status="VULNERABLE"; detail=`Protocolo: ${ssl.protocol} ${ssl.isWeakProto?"← FRACO":""} | Cipher: ${ssl.cipher} ${ssl.isWeakCipher?"← FRACO":""}`; fix="Desativa TLS 1.0/1.1. Usa apenas TLS 1.2+ com ciphers ECDHE/AES-GCM."; }
        else { status="OK"; detail=`TLS ${ssl.protocol} com ${ssl.cipher}.`; } break;
      case "N02":
        if (ssl.selfSigned) { status="VULNERABLE"; detail=`Certificado autoassinado. Expira: ${ssl.expiry}.`; fix="Instala certificado de CA válida (Let's Encrypt é gratuito)."; }
        else if (ssl.daysLeft < 0) { status="VULNERABLE"; detail=`Certificado EXPIRADO há ${Math.abs(ssl.daysLeft)} dias.`; fix="Renova o certificado imediatamente."; }
        else if (ssl.daysLeft < 30) { status="WARNING"; detail=`Expira em ${ssl.daysLeft} dias (${ssl.expiry}).`; fix="Renova em breve. Configura renovação automática com certbot."; }
        else if (!ssl.ok) { status="WARNING"; detail="Não foi possível verificar SSL."; fix="Verifica se HTTPS está configurado."; }
        else { status="OK"; detail=`Válido ${ssl.daysLeft} dias. Emissor: ${ssl.issuer}.`; } break;
      case "N03":
        if (!h.hsts) { status="VULNERABLE"; detail="Strict-Transport-Security AUSENTE — SSLStrip possível."; fix="Adiciona: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"; }
        else { status="OK"; detail=`HSTS: ${h.hsts}`; } break;
      case "N04": {
        const miss = [!h.csp&&"CSP",!h.xFrameOptions&&"X-Frame-Options",!h.xContentTypeOptions&&"X-Content-Type-Options",!h.referrerPolicy&&"Referrer-Policy"].filter(Boolean);
        if (miss.length >= 2) { status="VULNERABLE"; detail=`Headers ausentes: ${miss.join(", ")}`; fix=`Adiciona os headers: ${miss.join(", ")}`; }
        else if (miss.length===1) { status="WARNING"; detail=`Header ausente: ${miss[0]}`; fix=`Adiciona ${miss[0]}`; }
        else { status="OK"; detail="Principais security headers presentes."; } break; }
      case "N05":
        if (cors.vulnerable) { status="VULNERABLE"; detail=`CORS aceita origens maliciosas: ${cors.vulnerableOrigins?.map(o=>o.origin).join(", ")}`; fix="Restringe Access-Control-Allow-Origin a domínios específicos confiáveis."; }
        else { status="OK"; detail="CORS não aceita origens maliciosas testadas."; } break;
      case "N06":
        if (http.server||http.poweredBy) { status="VULNERABLE"; detail=`Server: ${http.server||"N/A"} | X-Powered-By: ${http.poweredBy||"N/A"}`; fix="Remove/oculta os headers Server e X-Powered-By."; }
        else { status="OK"; detail="Nenhum header de versão exposto."; } break;
      case "N07":
        if (!probeData.redirect?.redirectsToHTTPS) { status="VULNERABLE"; detail=`HTTP não redireciona para HTTPS. Status: ${probeData.redirect?.httpStatus||"sem resposta"}`; fix="Configura redirect 301 de HTTP para HTTPS."; }
        else { status="OK"; detail=`Redireciona HTTP→HTTPS (${probeData.redirect?.httpStatus}).`; } break;
      case "N08":
        if (h.setCookie) { status="WARNING"; detail="Cookies presentes — verifica Secure/HttpOnly/SameSite manualmente."; fix="Garante Secure; HttpOnly; SameSite=Strict em todos os cookies."; }
        else { status="OK"; detail="Nenhum cookie nas respostas testadas."; } break;
      case "N09": {
        const dm=[!dns.hasSPF&&"SPF",!dns.hasDKIM&&"DKIM",!dns.hasDMARC&&"DMARC"].filter(Boolean);
        if (dm.length>0) { status=dm.length>=2?"VULNERABLE":"WARNING"; detail=`Registos ausentes: ${dm.join(", ")}. SPF: ${dns.spfRecord||"AUSENTE"}`; fix=`Configura ${dm.join(", ")} para prevenir email spoofing.`; }
        else { status="OK"; detail=`SPF/DKIM/DMARC configurados. SPF: ${dns.spfRecord}`; } break; }
      case "N10": status="WARNING"; detail="DNSSEC não verificável via HTTP probe."; fix="Ativa DNSSEC no teu registrar."; break;
      case "N11": status=http.reachable?"OK":"WARNING"; detail=http.reachable?`Online. HTTP ${http.status}. CDN: ${cdn.detected||"Nenhum"}.`:"Servidor não respondeu."; break;
      case "D01": {
        const udp=ports.open?.filter(p=>[53,123,161,1900,11211].includes(p.port))||[];
        if(udp.length>0){status="VULNERABLE";detail=`Portas de amplificação: ${udp.map(p=>`${p.port}/${p.svc}`).join(", ")}`;fix="Bloqueia acesso externo a serviços UDP (DNS recursivo, NTP, SNMP, Memcached).";}
        else{status="OK";detail="Nenhuma porta UDP de amplificação detetada.";} break;}
      case "D02":
        if(!cdn.cloudflare&&!cdn.vercel&&!cdn.fastly){status="VULNERABLE";detail=`IP direto exposto sem CDN. IPs: ${dns.a?.join(", ")||"N/A"}`;fix="Coloca o servidor atrás do Cloudflare (gratuito) para ocultar o IP real.";}
        else{status="OK";detail=`Protegido por CDN: ${cdn.detected}.`;} break;
      case "D03":
        if(cdn.cloudflare||cdn.vercel||cdn.fastly){status="OK";detail=`WAF/CDN: ${cdn.detected}`;}
        else{status="VULNERABLE";detail="Nenhum WAF/CDN detetado.";fix="Ativa Cloudflare para proteção L3/L4/L7.";} break;
      case "D04":
        if(slowloris.vulnerable){status="VULNERABLE";detail=`Slowloris: ${slowloris.detail}`;fix="Configura timeout de conexões parciais (RequestReadTimeout no Apache, client_header_timeout no Nginx).";}
        else{status="OK";detail=`Slowloris: ${slowloris.detail||"Servidor fechou conexões parciais."}`} break;
      case "D05":
        if(!rateLimit.rateLimited){status="VULNERABLE";detail=`${rateLimit.tested} requests sem rate limiting. Statuses: ${rateLimit.statuses?.join(", ")}`;fix="Implementa rate limiting (nginx limit_req, express-rate-limit, Cloudflare Rate Limiting).";}
        else{status="OK";detail=`Rate limiting ativo após ${rateLimit.tested} requests.`;} break;
      case "D06":case"D07":case"D08":case"D09":case"D10":case"D11":case"D12":
        status="WARNING";detail=`${c.name} requer análise interna do servidor.`;fix="Implementa timeouts e limites específicos no servidor."; break;
      case "W11":
        if(openRedirect.vulnerable){status="VULNERABLE";detail=`Open redirect em: ${openRedirect.params?.map(p=>`?${p.param}=`).join(", ")}`;fix="Usa whitelist de domínios permitidos. Nunca redirecionas para URLs externas sem validação.";}
        else{status="OK";detail="Nenhum open redirect detetado nos parâmetros testados.";} break;
      case "W13":
        if(!h.xFrameOptions){status="VULNERABLE";detail="X-Frame-Options AUSENTE — clickjacking possível.";fix="Adiciona: X-Frame-Options: DENY";}
        else{status="OK";detail=`X-Frame-Options: ${h.xFrameOptions}`;} break;
      case "W16": {
        const lp=paths.exposed?.filter(p=>p.path.endsWith("/")||p.status===200)||[];
        if(lp.length>0){status="VULNERABLE";detail=`Paths expostos: ${lp.map(p=>`${p.path}[${p.status}]`).join(", ")}`;fix="Desativa directory listing (Options -Indexes no Apache, autoindex off no Nginx).";}
        else{status="OK";detail="Nenhum diretório com listagem detetada.";} break;}
      case "W17": {
        const bp=paths.exposed?.filter(p=>[".bak",".sql",".zip",".tar",".old",".backup",".dump"].some(e=>p.path.includes(e)))||[];
        if(bp.length>0){status="VULNERABLE";detail=`Backups expostos: ${bp.map(p=>`${p.path}[${p.status}]`).join(", ")}`;fix="Remove ficheiros de backup do webroot.";}
        else{status="OK";detail="Nenhum ficheiro de backup encontrado.";} break;}
      case "W18":
        if(!h.cacheControl){status="WARNING";detail="Cache-Control ausente.";fix="Adiciona Cache-Control: no-store para endpoints sensíveis.";}
        else{status="OK";detail=`Cache-Control: ${h.cacheControl}`;} break;
      case "W19":
        if(subdomains.sensitive?.length>0){status="WARNING";detail=`Subdomínios sensíveis: ${subdomains.sensitive.map(s=>s.sub).join(", ")}`;fix="Verifica CNAMEs de serviços desativados.";}
        else{status="OK";detail=`${subdomains.count||0} subdomínios, nenhum sensível.`;} break;
      case "A01": {
        const ap=paths.exposed?.filter(p=>["/admin","/admin/","/wp-admin","/phpmyadmin","/panel","/dashboard","/manager","/console","/control"].includes(p.path))||[];
        if(ap.length>0){status="VULNERABLE";detail=`Admin exposto: ${ap.map(p=>`${p.path}[${p.status}]`).join(", ")}`;fix="Protege admin com autenticação forte e restrição por IP.";}
        else{status="OK";detail="Nenhum painel de administração exposto.";} break;}
      case "P01":
        if(jsSecrets.found){status="VULNERABLE";detail=`${jsSecrets.count} secret(s) em JS: ${jsSecrets.findings?.map(f=>`[${f.type}] ${f.source}`).join(", ")}`;fix="Move chaves para variáveis de ambiente. Roga as chaves expostas.";}
        else{status="OK";detail=`${jsSecrets.jsFilesScanned||0} ficheiros JS escaneados — nenhuma chave encontrada.`;} break;
      case "P05":
        if(!rateLimit.rateLimited){status="VULNERABLE";detail="Rate limiting ausente nos endpoints testados.";fix="Implementa rate limiting por IP e por token na API.";}
        else{status="OK";detail="Rate limiting detetado.";} break;
      case "I01": {
        const dp=ports.dangerous||[];
        if(dp.length>0){status="VULNERABLE";detail=`Portas perigosas: ${dp.map(p=>`${p.port}/${p.svc}`).join(", ")}`;fix="Fecha portas desnecessárias. Restringe DB/Redis/etc. a localhost.";}
        else if((ports.open?.length||0)>3){status="WARNING";detail=`${ports.open.length} portas abertas: ${ports.open.map(p=>`${p.port}/${p.svc}`).join(", ")}`;fix="Fecha portas não utilizadas com firewall.";}
        else{status="OK";detail=`Portas: ${ports.open?.map(p=>`${p.port}/${p.svc}`).join(", ")||"só HTTP/HTTPS"}.`;} break;}
      default:
        status="WARNING";detail=`${c.name} — requer testes ativos ou acesso ao código-fonte.`;fix="Usa ferramentas especializadas (OWASP ZAP, Burp Suite) para este vetor.";
    }
    return { id:c.id, severity:c.sev, name:c.name, status, detail, fix };
  });

  const vc=findings.filter(f=>f.status==="VULNERABLE"&&f.severity==="CRITICAL").length;
  const vh=findings.filter(f=>f.status==="VULNERABLE"&&f.severity==="HIGH").length;
  const vm=findings.filter(f=>f.status==="VULNERABLE"&&f.severity==="MEDIUM").length;
  const score=Math.max(0,100-(vc*15)-(vh*8)-(vm*3));
  const vl=findings.filter(f=>f.status==="VULNERABLE").map(f=>f.name);
  const summary=vl.length===0
    ?`${probeData.hostname} — Nenhuma vulnerabilidade crítica detetada. Score: ${score}/100. CDN: ${cdn.detected||"Nenhum"}. SSL: ${ssl.ok?"OK":"Falhou"}.`
    :`${probeData.hostname} — ${vl.length} vulnerabilidades detetadas: ${vl.slice(0,5).join(", ")}${vl.length>5?` e mais ${vl.length-5}`:""}. Score: ${score}/100.`;
  return { score, summary, findings };
}

export default function App() {
  const [section, setSection]           = useState("scanner");
  const [tab, setTab]                   = useState("url");
  const [url, setUrl]                   = useState("");
  const [contract, setContract]         = useState("");
  const [sourceCode, setSourceCode]     = useState("");
  const [sourceLang, setSourceLang]     = useState("javascript");
  const [loading, setLoading]           = useState(false);
  const [loadingMsg, setLoadingMsg]     = useState("");
  const [results, setResults]           = useState(null);
  const [rawProbe, setRawProbe]         = useState(null);
  const [error, setError]               = useState("");
  const [expanded, setExpanded]         = useState(null);
  const [filterSev, setFilterSev]       = useState("ALL");
  const [toolCat, setToolCat]           = useState("ALL");

  const checks = tab === "url" ? URL_CHECKS : tab === "contract" ? CONTRACT_CHECKS : CODE_CHECKS;

  async function runScan() {
    if (tab === "url" && !url.trim()) { setError("Insere uma URL ou IP para escanear."); return; }
    if (tab === "contract" && !contract.trim()) { setError("Cola o código Solidity para auditar."); return; }
    if (tab === "source" && !sourceCode.trim()) { setError("Cola o código fonte para auditar."); return; }

    setError(""); setLoading(true); setResults(null); setRawProbe(null); setFilterSev("ALL");

    let probeData = null;

    // ── STEP 1: real network probe (URL only) ──────────────────────────────
    if (tab === "url") {
      setLoadingMsg("PASSO 1/2 — A TESTAR REDE EM TEMPO REAL...");
      try {
        const res = await fetch(`http://localhost:3001/api/probe?target=${encodeURIComponent(url)}`);
        probeData = await res.json();
        if (probeData?.error) {
          setError(`Erro no scan: ${probeData.error}`);
          setLoading(false); return;
        }
        setRawProbe(probeData);
      } catch {
        setError("Backend não está a correr. Abre um terminal em C:\\Users\\Loja\\inczerodayshield e corre: npm run dev");
        setLoading(false); return;
      }
    }

    // ── STEP 2: URL tab — análise determinística local (sem API) ──────────
    if (tab === "url") {
      setLoadingMsg("PASSO 2/2 — A GERAR RELATÓRIO...");
      setResults(analyzeProbe(probeData, checks));
      setLoading(false); setLoadingMsg(""); return;
    }

    // ── STEP 2: contract/source — análise estática local ─────────────────
    if (tab === "source") {
      setLoadingMsg("A ANALISAR CÓDIGO FONTE...");
      setResults(analyzeCode(sourceCode, checks, false));
      setLoading(false); setLoadingMsg(""); return;
    }
    if (tab === "contract") {
      setLoadingMsg("A ANALISAR CONTRATO SOLIDITY...");
      setResults(analyzeCode(contract, checks, true));
      setLoading(false); setLoadingMsg(""); return;
    }

    // ── FALLBACK: IA (mantido para compatibilidade futura) ────────────────
    setLoadingMsg("A ANALISAR COM IA...");

    const probeSection = probeData ? `
╔══════════════════════════════════════════════╗
  DADOS REAIS RECOLHIDOS — ${probeData.hostname}
  Timestamp: ${probeData.timestamp}
╚══════════════════════════════════════════════╝

── SERVIDOR ──
HTTP Status: ${probeData.http?.status} | Reachable: ${probeData.http?.reachable}
Server header: ${probeData.http?.server || "AUSENTE"}
X-Powered-By: ${probeData.http?.poweredBy || "AUSENTE"}
CDN/Proxy: ${probeData.cdn?.detected || "Não detetado"}
Cloudflare: ${probeData.cdn?.cloudflare} | Vercel: ${probeData.cdn?.vercel}

── SECURITY HEADERS (valores reais) ──
Strict-Transport-Security: ${probeData.headers?.hsts || "AUSENTE ← VULNERÁVEL"}
Content-Security-Policy:   ${probeData.headers?.csp ? "PRESENTE" : "AUSENTE ← VULNERÁVEL"}
X-Frame-Options:           ${probeData.headers?.xFrameOptions || "AUSENTE ← VULNERÁVEL"}
X-Content-Type-Options:    ${probeData.headers?.xContentTypeOptions || "AUSENTE ← VULNERÁVEL"}
Referrer-Policy:           ${probeData.headers?.referrerPolicy || "AUSENTE"}
Permissions-Policy:        ${probeData.headers?.permissionsPolicy || "AUSENTE"}
Access-Control-Allow-Origin: ${probeData.headers?.corsOrigin || "AUSENTE"}
Cache-Control:             ${probeData.headers?.cacheControl || "AUSENTE"}
Set-Cookie:                ${probeData.headers?.setCookie ? "PRESENTE" : "nenhum"}

── SSL/TLS (dados reais) ──
Protocolo: ${probeData.ssl?.protocol || "N/A"} ${probeData.ssl?.isWeakProto ? "← PROTOCOLO FRACO!" : ""}
Cipher:    ${probeData.ssl?.cipher || "N/A"} ${probeData.ssl?.isWeakCipher ? "← CIPHER FRACO!" : ""}
Validade:  ${probeData.ssl?.expiry || "N/A"} (${probeData.ssl?.daysLeft ?? "?"} dias restantes) ${probeData.ssl?.daysLeft < 30 ? "← EXPIRA EM BREVE!" : ""}
Self-signed: ${probeData.ssl?.selfSigned ? "SIM ← VULNERÁVEL" : "NÃO"}
Emissor:   ${probeData.ssl?.issuer || "N/A"}
SAN:       ${probeData.ssl?.san || "N/A"}

── HTTP→HTTPS REDIRECT ──
HTTP status: ${probeData.redirect?.httpStatus || "N/A"}
Redireciona para HTTPS: ${probeData.redirect?.redirectsToHTTPS ? "SIM" : "NÃO ← VULNERÁVEL"}

── DNS (dados reais) ──
SPF:   ${probeData.dns?.hasSPF  ? "PRESENTE — " + probeData.dns.spfRecord  : "AUSENTE ← VULNERÁVEL"}
DKIM:  ${probeData.dns?.hasDKIM  ? "PRESENTE" : "AUSENTE ← VULNERÁVEL"}
DMARC: ${probeData.dns?.hasDMARC ? "PRESENTE — " + probeData.dns.dmarcRecord : "AUSENTE ← VULNERÁVEL"}
MX:    ${probeData.dns?.mx?.join(", ") || "nenhum"}
IPs A: ${probeData.dns?.a?.join(", ") || "N/A"}
NS:    ${probeData.dns?.ns?.join(", ") || "N/A"}

── SCAN DE PORTAS TCP (${probeData.ports?.scanned} portas testadas) ──
PORTAS ABERTAS: ${probeData.ports?.open?.length === 0 ? "nenhuma detetada" :
  probeData.ports?.open?.map(p => `${p.port}/${p.svc}`).join(", ")}
PORTAS PERIGOSAS ABERTAS: ${probeData.ports?.dangerous?.length === 0 ? "nenhuma" :
  probeData.ports?.dangerous?.map(p => `${p.port}/${p.svc} ← CRÍTICO!`).join(", ")}

── PATHS EXPOSTOS (${probeData.paths?.exposed?.length} encontrados) ──
${probeData.paths?.exposed?.length === 0 ? "Nenhum path sensível exposto" :
  probeData.paths?.exposed?.map(e => `EXPOSTO [${e.status}]: ${e.path} ← VULNERÁVEL`).join("\n")}
Paths protegidos (403/401): ${probeData.paths?.forbidden?.map(e => e.path).join(", ") || "nenhum"}

── RATE LIMITING TEST (${probeData.rateLimit?.tested} requests simultâneos) ──
Rate limited: ${probeData.rateLimit?.rateLimited ? "SIM (proteção ativa)" : "NÃO ← VULNERÁVEL A HTTP FLOOD"}
Status recebidos: ${probeData.rateLimit?.statuses?.join(", ")}

── SLOWLORIS TEST ──
Vulnerável: ${probeData.slowloris?.vulnerable ? "SIM ← VULNERÁVEL" : "NÃO"}
Detalhe: ${probeData.slowloris?.detail || "N/A"}

── HTTP METHODS ──
Allow header: ${probeData.httpMethods?.allowHeader || "não retornado"}
PUT: ${probeData.httpMethods?.PUT || "N/A"} | DELETE: ${probeData.httpMethods?.DELETE || "N/A"} | TRACE: ${probeData.httpMethods?.TRACE || "N/A"}

── JS SECRETS SCAN (${probeData.jsSecrets?.jsFilesScanned || 0} ficheiros JS escaneados) ──
Secrets encontrados: ${probeData.jsSecrets?.count || 0}
${probeData.jsSecrets?.findings?.length > 0
  ? probeData.jsSecrets.findings.map(f => `SECRETO [${f.type}] em ${f.source}: ${f.sample}`).join("\n")
  : "Nenhum secret detetado nos ficheiros JS públicos"}

── CORS BYPASS TEST ──
Vulnerável: ${probeData.cors?.vulnerable ? "SIM ← VULNERÁVEL" : "NÃO"}
${probeData.cors?.vulnerableOrigins?.length > 0
  ? probeData.cors.vulnerableOrigins.map(o => `Origem aceite: ${o.origin} | ACAO: ${o.acao} | Credentials: ${o.allowCredentials}`).join("\n")
  : "Nenhuma origem maliciosa aceite"}

── SUBDOMÍNIOS ENCONTRADOS (${probeData.subdomains?.count || 0}) ──
${probeData.subdomains?.count === 0 ? "Nenhum subdomínio resolvido" :
  probeData.subdomains?.found?.map(s => `${s.sub} [${s.ips?.join(",")}] HTTP:${s.status}`).join("\n")}
Subdomínios sensíveis: ${probeData.subdomains?.sensitive?.length === 0 ? "nenhum" :
  probeData.subdomains?.sensitive?.map(s => `${s.sub} ← CRÍTICO`).join(", ")}

── OPEN REDIRECT TEST ──
Vulnerável: ${probeData.openRedirect?.vulnerable ? "SIM ← VULNERÁVEL" : "NÃO"}
${probeData.openRedirect?.params?.length > 0
  ? probeData.openRedirect.params.map(p => `Param ?${p.param}= → redireciona para ${p.location}`).join("\n")
  : "Nenhum open redirect detetado"}

── TECH STACK DETETADO ──
${probeData.techStack?.length === 0 ? "Sem tecnologias identificadas"
  : probeData.techStack?.map(t => `${t.cat}: ${t.tech}`).join(" | ")}

════════════════════════════════════════════════` : "";

    const prompt = tab === "url"
      ? `Você é o melhor especialista mundial em segurança ofensiva e defensiva: infraestrutura web, redes, DDoS/DoS, OWASP, cloud e análise de portas.

${probeSection}

Com base EXCLUSIVAMENTE nos dados reais acima, analisa cada um dos ${checks.length} checks de segurança:
${checks.map(c => `- ${c.id} [${c.sev}] ${c.name}: ${c.desc}`).join("\n")}

IMPORTANTE:
- Usa os dados reais recolhidos — não inventes nem simules
- Para checks onde os dados reais são conclusivos (ex: header HSTS ausente), marca como VULNERABLE
- Para checks que precisam de acesso direto ao servidor (portas internas, SSH, etc.), marca como WARNING com base no que é típico para este tipo de infraestrutura
- Sê específico e técnico — referencia valores reais dos headers e certificados

Responde APENAS JSON válido sem markdown:
{
  "score": <0-100>,
  "summary": "<resumo executivo técnico baseado nos dados reais>",
  "findings": [{
    "id":"<ID>","severity":"<CRITICAL|HIGH|MEDIUM|LOW|INFO>","name":"<nome>",
    "status":"<VULNERABLE|WARNING|OK>",
    "detail":"<explicação baseada nos dados reais recolhidos>",
    "fix":"<correção concreta e acionável>"
  }]
}`
      : tab === "contract"
      ? `Você é o melhor auditor de smart contracts Solidity + bytecode EVM do mundo. Analisa com modelo mental de Slither, Mythril e Ghidra.

CÓDIGO:
${contract}

Analisa TODOS os ${checks.length} vetores (incluindo bytecode/Ghidra G*):
${checks.map(c => `- ${c.id} [${c.sev}] ${c.name}: ${c.desc}`).join("\n")}

Para VULNERABLE/WARNING: indica função/linha específica do código.

Responde APENAS JSON válido:
{
  "score": <0-100>,
  "summary": "<resumo técnico executivo>",
  "findings": [{
    "id":"<ID>","severity":"<CRITICAL|HIGH|MEDIUM|LOW|INFO>","name":"<nome>",
    "status":"<VULNERABLE|WARNING|OK>",
    "detail":"<detalhe técnico com linha/função se aplicável>",
    "fix":"<código ou correção concreta>"
  }]
}`
      : `Você é o melhor especialista mundial em segurança ofensiva de código. Analisa como um pentester experiente, com o modelo mental de Semgrep, Bandit, CodeQL e revisão manual.

LINGUAGEM: ${sourceLang.toUpperCase()}

CÓDIGO FONTE:
\`\`\`${sourceLang}
${sourceCode}
\`\`\`

Analisa TODOS os ${checks.length} vetores de vulnerabilidade:
${checks.map(c => `- ${c.id} [${c.sev}] ${c.name}: ${c.desc}`).join("\n")}

REGRAS:
- Para VULNERABLE: indica linha exata, valor do input, e payload de prova de conceito (PoC)
- Para WARNING: indica onde pode existir vulnerabilidade dependendo do contexto
- Para OK: confirma que a verificação foi feita e não encontraste nada
- Se encontrares vulnerabilidades NÃO listadas nos checks, adiciona-as como findings extra com id "EX01", "EX02", etc.
- Fornece correção de código concreta (patch diff ou substituição)

Responde APENAS JSON válido:
{
  "score": <0-100, onde 100 é código completamente seguro>,
  "summary": "<resumo técnico executivo — quais as vulnerabilidades críticas encontradas e superfície de ataque>",
  "findings": [{
    "id":"<ID>","severity":"<CRITICAL|HIGH|MEDIUM|LOW|INFO>","name":"<nome>",
    "status":"<VULNERABLE|WARNING|OK>",
    "detail":"<linha exacta, payload PoC, contexto de exploração>",
    "fix":"<patch de código concreto e testável>"
  }]
}`;

    try {
      const res = await fetch("http://localhost:3001/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt }),
      });
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      const text = data.content?.map(i => i.text || "").join("") || "";
      const parsed = JSON.parse(text.replace(/```json|```/g, "").trim());
      setResults(parsed);
    } catch (e) {
      setError(`Erro: ${e.message}`);
    }
    setLoading(false); setLoadingMsg("");
  }

  const counts = results ? {
    CRITICAL: results.findings.filter(f => f.severity==="CRITICAL" && f.status==="VULNERABLE").length,
    HIGH:     results.findings.filter(f => f.severity==="HIGH"     && f.status==="VULNERABLE").length,
    MEDIUM:   results.findings.filter(f => f.severity==="MEDIUM"   && f.status!=="OK").length,
    LOW:      results.findings.filter(f => f.severity==="LOW").length,
  } : null;

  const filtered = results?.findings.filter(f => filterSev==="ALL" || f.severity===filterSev) || [];
  const toolCats = [...new Set(GITHUB_TOOLS.map(t => t.cat))];

  const S = { // styles
    bg:    { background:"#050510", color:"#e0e0f0", fontFamily:"'Courier New',Courier,monospace", minHeight:"100vh", padding:"20px 16px" },
    card:  { background:"#0a0a18", border:"1px solid #1a1a2e", borderRadius:8, padding:"12px 14px" },
    input: { width:"100%", padding:"12px 14px", background:"#0d0d1a", border:"1px solid #1a1a3a",
             borderRadius:8, color:"#e0e0f0", fontFamily:"monospace", boxSizing:"border-box", outline:"none" },
    btn:   (bg, border, color) => ({
      padding:"12px 0", border: border || "none", borderRadius:8, cursor:"pointer",
      fontFamily:"monospace", fontWeight:900, fontSize:12, letterSpacing:2,
      background: bg, color: color || "#fff",
    }),
  };

  return (
    <div style={S.bg}>

      {/* ── HEADER ── */}
      <div style={{ textAlign:"center", marginBottom:24 }}>
        <div style={{ fontSize:10, letterSpacing:6, color:"#0a84ff", marginBottom:5 }}>INC NETWORK</div>
        <h1 style={{ margin:0, fontSize:26, fontWeight:900, letterSpacing:2,
          background:"linear-gradient(135deg,#0a84ff,#30d158)",
          WebkitBackgroundClip:"text", WebkitTextFillColor:"transparent" }}>
          ZERODAY SHIELD
        </h1>
        <div style={{ fontSize:10, color:"#444", marginTop:4, letterSpacing:3 }}>
          v2.0 — TESTES REAIS — {URL_CHECKS.length + CONTRACT_CHECKS.length} CHECKS — NMAP · GHIDRA · DDoS · OWASP
        </div>
      </div>

      {/* ── NAV ── */}
      <div style={{ display:"flex", gap:6, maxWidth:700, margin:"0 auto 20px" }}>
        {[{k:"scanner",l:"SCANNER"},{k:"tools",l:"TOOLS & GITHUB"}].map(s => (
          <button key={s.k} onClick={() => setSection(s.k)}
            style={{ ...S.btn(section===s.k?"#0a84ff":"#0d0d1a", section===s.k?"none":"1px solid #1a1a3a",
              section===s.k?"#fff":"#555"), flex:1, fontSize:11 }}>
            {s.l}
          </button>
        ))}
      </div>

      {/* ════════════════ SCANNER ════════════════ */}
      {section === "scanner" && (
        <>
          {/* tabs */}
          <div style={{ display:"flex", gap:6, maxWidth:700, margin:"0 auto 14px" }}>
            {[
              {k:"url",      l:`SERVIDOR / IP  (${URL_CHECKS.length})`},
              {k:"source",   l:`CÓDIGO FONTE  (${CODE_CHECKS.length})`},
              {k:"contract", l:`SOLIDITY  (${CONTRACT_CHECKS.length})`},
            ].map(t => (
              <button key={t.k} onClick={() => { setTab(t.k); setResults(null); setError(""); }}
                style={{ ...S.btn(tab===t.k?"#0a84ff":"#0d0d1a", tab===t.k?"none":"1px solid #1a1a3a",
                  tab===t.k?"#fff":"#555"), flex:1, fontSize:11 }}>
                {t.l}
              </button>
            ))}
          </div>

          {/* input */}
          <div style={{ maxWidth:700, margin:"0 auto 14px" }}>
            {tab === "url" ? (
              <>
                <label style={{ fontSize:10, color:"#0a84ff", letterSpacing:2, display:"block", marginBottom:6 }}>
                  URL / IP / DOMÍNIO ALVO
                </label>
                <div style={{ display:"flex", gap:8, marginBottom:6 }}>
                  <input value={url} onChange={e => setUrl(e.target.value)}
                    onKeyDown={e => e.key==="Enter" && runScan()}
                    placeholder="https://incnetwork.online  ou  185.123.45.67"
                    style={{ ...S.input, fontSize:14, flex:1 }} />
                  <button onClick={() => setUrl("https://incnetwork.online")}
                    style={{ ...S.btn("#0d1a0d","1px solid #30d15840","#30d158"), padding:"12px 10px", fontSize:10, whiteSpace:"nowrap" }}>
                    TESTAR INC
                  </button>
                </div>
                <div style={{ fontSize:10, color:"#333", letterSpacing:1 }}>
                  Testa headers, SSL, DNS, portas, paths, JS secrets, CORS, subdomínios, open redirect, tech stack
                </div>
              </>
            ) : tab === "source" ? (
              <>
                <label style={{ fontSize:10, color:"#30d158", letterSpacing:2, display:"block", marginBottom:6 }}>
                  AUDITORIA DE CÓDIGO FONTE — {CODE_CHECKS.length} CHECKS
                </label>
                <div style={{ display:"flex", gap:6, marginBottom:8, flexWrap:"wrap" }}>
                  {["javascript","typescript","python","php","java","go","rust","solidity","bash","sql"].map(lang => (
                    <button key={lang} onClick={() => setSourceLang(lang)} style={{
                      padding:"3px 8px", borderRadius:3, cursor:"pointer", fontFamily:"monospace", fontSize:10,
                      border: sourceLang===lang?"1px solid #30d158":"1px solid #1a1a2e",
                      background: sourceLang===lang?"#001a08":"#0d0d1a",
                      color: sourceLang===lang?"#30d158":"#555",
                    }}>{lang}</button>
                  ))}
                </div>
                <textarea value={sourceCode} onChange={e => setSourceCode(e.target.value)}
                  placeholder={"// Cola aqui o código a auditar (qualquer linguagem)\n// O scanner identifica: SQLi, XSS, RCE, SSRF, secrets, IDOR, path traversal...\n\nconst query = `SELECT * FROM users WHERE id = ${req.params.id}`;\n// ↑ SQL Injection óbvio — exemplo de vulnerabilidade"}
                  rows={14} style={{ ...S.input, fontSize:12, resize:"vertical", lineHeight:1.6 }} />
                <div style={{ fontSize:10, color:"#333", marginTop:4, letterSpacing:1 }}>
                  25 vetores · SQLi · RCE · XSS · SSRF · Path Traversal · Secrets · IDOR · ReDoS · Race Condition
                </div>
              </>
            ) : (
              <>
                <label style={{ fontSize:10, color:"#0a84ff", letterSpacing:2, display:"block", marginBottom:6 }}>
                  CÓDIGO SOLIDITY
                </label>
                <textarea value={contract} onChange={e => setContract(e.target.value)}
                  placeholder={"// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract INCNetwork {\n  // cole aqui\n}"}
                  rows={10} style={{ ...S.input, fontSize:12, resize:"vertical" }} />
              </>
            )}

            {error && (
              <div style={{ marginTop:8, padding:"10px 14px", background:"#1a0008",
                border:"1px solid #ff2d5540", borderRadius:6, color:"#ff2d55", fontSize:12 }}>
                {error}
              </div>
            )}

            <button onClick={runScan} disabled={loading}
              style={{ ...S.btn(
                loading ? "#0d0d1a" : "linear-gradient(135deg,#0a84ff,#0060df)",
                loading ? "1px solid #1a1a3a" : "none",
                loading ? "#555" : "#fff"
              ), width:"100%", marginTop:10, padding:"14px 0", fontSize:13 }}>
              {loading ? loadingMsg || "A PROCESSAR..." : tab === "source" ? `AUDITAR CÓDIGO — ${checks.length} VETORES` : `INICIAR SCAN REAL — ${checks.length} CHECKS`}
            </button>
          </div>

          {/* checks list */}
          {!results && !loading && (
            <div style={{ maxWidth:700, margin:"0 auto" }}>
              <div style={{ display:"flex", flexWrap:"wrap", gap:5, marginBottom:12, justifyContent:"center" }}>
                {Object.entries(CATEGORIES)
                  .filter(([k]) => tab==="url" ? !["C","G","V"].includes(k) : tab==="source" ? k==="V" : ["C","G"].includes(k))
                  .map(([k,v]) => (
                    <span key={k} style={{ fontSize:10, color:v.color, border:`1px solid ${v.color}40`,
                      borderRadius:4, padding:"2px 8px" }}>{v.label}</span>
                  ))}
              </div>
              <div style={{ display:"flex", flexDirection:"column", gap:3 }}>
                {checks.map(c => (
                  <div key={c.id} style={{ display:"flex", alignItems:"center", gap:10,
                    padding:"6px 10px", background:"#0a0a18", borderRadius:5,
                    border:`1px solid ${catColor(c.id)}15` }}>
                    <span style={{ fontSize:10, color:catColor(c.id), width:30, flexShrink:0 }}>{c.id}</span>
                    <SeverityBadge sev={c.sev} />
                    <span style={{ fontSize:11, color:"#666", flex:1 }}>{c.name}</span>
                    <span style={{ fontSize:9, color:catColor(c.id), minWidth:70, textAlign:"right" }}>
                      {CATEGORIES[c.id[0]]?.label}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* loading */}
          {loading && (
            <div style={{ textAlign:"center", padding:40 }}>
              <div style={{ color:"#0a84ff", fontSize:13, letterSpacing:3 }}>{loadingMsg}</div>
              <div style={{ color:"#444", fontSize:11, marginTop:8 }}>
                {tab==="url" ? "A testar headers, SSL, DNS, JS secrets, subdomínios..." : tab==="source" ? `A analisar ${checks.length} vetores no código fonte (SQLi, RCE, XSS, SSRF...)` : `A analisar ${checks.length} vetores de ataque no contrato...`}
              </div>
            </div>
          )}

          {/* raw probe data (collapsible) */}
          {rawProbe && results && (
            <div style={{ maxWidth:700, margin:"0 auto 16px" }}>
              <details>
                <summary style={{ cursor:"pointer", fontSize:10, color:"#333", letterSpacing:2, padding:"8px 0" }}>
                  DADOS BRUTOS RECOLHIDOS DO SERVIDOR (clica para ver)
                </summary>
                <pre style={{ fontSize:10, color:"#555", background:"#0a0a18", padding:12,
                  borderRadius:6, overflow:"auto", maxHeight:300 }}>
                  {JSON.stringify(rawProbe, null, 2)}
                </pre>
              </details>
            </div>
          )}

          {/* results */}
          {results && (
            <div style={{ maxWidth:700, margin:"0 auto" }}>
              <div style={{ ...S.card, borderRadius:12, padding:24, marginBottom:16, textAlign:"center" }}>
                <div style={{ fontSize:10, color:"#444", letterSpacing:3, marginBottom:14 }}>SECURITY SCORE</div>
                <ScoreRing score={results.score} />
                <p style={{ color:"#777", fontSize:12, marginTop:14, lineHeight:1.7 }}>{results.summary}</p>
                <div style={{ display:"flex", justifyContent:"center", gap:20, marginTop:14 }}>
                  {Object.entries(counts).map(([sev, n]) => (
                    <div key={sev} style={{ textAlign:"center" }}>
                      <div style={{ fontSize:24, fontWeight:900, color:SEVERITIES[sev].color }}>{n}</div>
                      <div style={{ fontSize:9, color:"#444", letterSpacing:1 }}>{SEVERITIES[sev].label.toUpperCase()}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* filter */}
              <div style={{ display:"flex", gap:5, marginBottom:10, flexWrap:"wrap" }}>
                {["ALL","CRITICAL","HIGH","MEDIUM","LOW","INFO"].map(s => (
                  <button key={s} onClick={() => setFilterSev(s)} style={{
                    padding:"4px 10px", borderRadius:4, cursor:"pointer", fontFamily:"monospace",
                    fontSize:10, fontWeight:700,
                    border: filterSev===s ? `1px solid ${SEVERITIES[s]?.color||"#0a84ff"}` : "1px solid #1a1a2e",
                    background: filterSev===s ? (SEVERITIES[s]?.bg||"#001020") : "#0d0d1a",
                    color: filterSev===s ? (SEVERITIES[s]?.color||"#0a84ff") : "#555",
                  }}>
                    {s==="ALL" ? `TODOS (${results.findings.length})` : `${SEVERITIES[s].label} (${results.findings.filter(f=>f.severity===s).length})`}
                  </button>
                ))}
              </div>

              {/* findings */}
              <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
                {filtered.map(f => {
                  const exp = expanded===f.id;
                  const sc = f.status==="VULNERABLE"?"#ff2d55":f.status==="WARNING"?"#ffd60a":"#30d158";
                  const si = f.status==="VULNERABLE"?"✗":f.status==="WARNING"?"!":"✓";
                  return (
                    <div key={f.id} onClick={() => setExpanded(exp?null:f.id)}
                      style={{ ...S.card, border:`1px solid ${exp?(SEVERITIES[f.severity]?.color+"60"||"#333"):"#1a1a2e"}`, cursor:"pointer" }}>
                      <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                        <span style={{ fontSize:14, color:sc, width:16, fontWeight:900 }}>{si}</span>
                        <span style={{ fontSize:10, color:catColor(f.id), width:30 }}>{f.id}</span>
                        <SeverityBadge sev={f.severity} />
                        <span style={{ fontSize:12, color:"#ccc", flex:1 }}>{f.name}</span>
                        <span style={{ fontSize:10, color:"#444" }}>{exp?"▲":"▼"}</span>
                      </div>
                      {exp && (
                        <div style={{ marginTop:12, paddingTop:12, borderTop:"1px solid #1a1a2e" }}>
                          <div style={{ fontSize:12, color:"#aaa", lineHeight:1.7, marginBottom:10 }}>{f.detail}</div>
                          {f.fix && (
                            <div style={{ background:"#001a08", border:"1px solid #30d15830", borderRadius:6, padding:"10px 12px" }}>
                              <div style={{ fontSize:10, color:"#30d158", letterSpacing:2, marginBottom:5 }}>CORREÇÃO</div>
                              <div style={{ fontSize:11, color:"#88cc99", lineHeight:1.7, whiteSpace:"pre-wrap" }}>{f.fix}</div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>

              <button onClick={() => { setResults(null); setRawProbe(null); setUrl(""); setContract(""); setSourceCode(""); setFilterSev("ALL"); }}
                style={{ ...S.btn("#0d0d1a","1px solid #1a1a3a","#555"), width:"100%", marginTop:16, padding:"12px 0" }}>
                NOVO SCAN
              </button>
            </div>
          )}
        </>
      )}

      {/* ════════════════ TOOLS ════════════════ */}
      {section === "tools" && (
        <div style={{ maxWidth:700, margin:"0 auto" }}>
          <div style={{ fontSize:10, color:"#444", letterSpacing:3, marginBottom:14, textAlign:"center" }}>
            {GITHUB_TOOLS.length} FERRAMENTAS — GITHUB
          </div>
          <div style={{ display:"flex", flexWrap:"wrap", gap:5, marginBottom:14 }}>
            {["ALL",...toolCats].map(c => (
              <button key={c} onClick={() => setToolCat(c)} style={{
                padding:"4px 10px", borderRadius:4, cursor:"pointer", fontFamily:"monospace",
                fontSize:10, fontWeight:700,
                border: toolCat===c?"1px solid #0a84ff":"1px solid #1a1a2e",
                background: toolCat===c?"#000d1a":"#0d0d1a",
                color: toolCat===c?"#0a84ff":"#555",
              }}>{c}</button>
            ))}
          </div>
          <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
            {GITHUB_TOOLS.filter(t => toolCat==="ALL"||t.cat===toolCat).map(t => (
              <div key={t.name} style={{ ...S.card }}>
                <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:4 }}>
                  <span style={{ fontSize:13, color:"#e0e0f0", fontWeight:700 }}>{t.name}</span>
                  <span style={{ fontSize:9, color:"#0a84ff", border:"1px solid #0a84ff40", borderRadius:3, padding:"1px 6px" }}>{t.cat}</span>
                  <span style={{ fontSize:9, color:"#ffd60a", marginLeft:"auto" }}>★ {t.stars}</span>
                </div>
                <div style={{ fontSize:11, color:"#555", marginBottom:6 }}>{t.desc}</div>
                <a href={t.url} target="_blank" rel="noopener noreferrer"
                  style={{ fontSize:10, color:"#0a84ff", textDecoration:"none" }}>{t.url}</a>
              </div>
            ))}
          </div>

          {/* nmap cheatsheet */}
          <div style={{ ...S.card, borderRadius:12, marginTop:20 }}>
            <div style={{ fontSize:11, color:"#ff9f0a", letterSpacing:3, marginBottom:12 }}>NMAP — COMANDOS ESSENCIAIS</div>
            {[
              ["nmap -sV -sC -A -p- TARGET",           "Scan completo — versões, scripts, OS, todas as portas"],
              ["nmap -sU --top-ports 200 TARGET",       "UDP — DNS, NTP, SNMP, SSDP"],
              ["nmap --script vuln TARGET",             "Scan de vulnerabilidades com NSE scripts"],
              ["nmap --script smb-vuln-ms17-010 TARGET","Detectar EternalBlue (WannaCry)"],
              ["nmap -p 6379 --script redis-info TARGET","Redis sem autenticação"],
              ["masscan -p1-65535 TARGET --rate=10000", "Scan ultra-rápido de todas as portas TCP"],
            ].map(([cmd, desc]) => (
              <div key={cmd} style={{ marginBottom:10 }}>
                <code style={{ fontSize:11, color:"#30d158", display:"block", marginBottom:2 }}>{cmd}</code>
                <span style={{ fontSize:10, color:"#555" }}>{desc}</span>
              </div>
            ))}
          </div>

          {/* ghidra cheatsheet */}
          <div style={{ ...S.card, borderRadius:12, marginTop:12 }}>
            <div style={{ fontSize:11, color:"#64d2ff", letterSpacing:3, marginBottom:12 }}>GHIDRA / EVM BYTECODE</div>
            {[
              ["pyevmasm -d BYTECODE",                       "Disassemble bytecode EVM para opcodes"],
              ["slither . --print human-summary",            "Análise estática completa do contrato"],
              ["mythril analyze CONTRACT.sol",               "Symbolic execution — reentrancy, overflow"],
              ["echidna-test CONTRACT.sol --test-mode assertion","Fuzzing de invariantes"],
              ["cast storage ADDR SLOT --rpc-url RPC",       "Leitura direta de slots de storage on-chain"],
              ["cast decompile BYTECODE",                    "Decompile de bytecode EVM com Foundry"],
            ].map(([cmd, desc]) => (
              <div key={cmd} style={{ marginBottom:10 }}>
                <code style={{ fontSize:11, color:"#64d2ff", display:"block", marginBottom:2 }}>{cmd}</code>
                <span style={{ fontSize:10, color:"#555" }}>{desc}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
