// =============================================================================
// LPTS - Banco de Regras YARA
// Cada regra representa uma heuristica deterministica para deteccao de ameacas
// em pacotes .deb. O motor YARA faz pattern-matching sobre os bytes brutos dos
// arquivos extraidos, sem necessidade de execucao (analise estatica).
//
// Estrutura de uma regra YARA:
//   - meta:      metadados descritivos (nao afetam a deteccao)
//   - strings:   padroes a serem buscados (texto ASCII, hex ou regex)
//   - condition: logica booleana que define quando a regra dispara
//
// Modificadores utilizados:
//   "ascii"   - restringe a busca a strings codificadas em ASCII
//   "nocase"  - torna a busca case-insensitive
//   { }       - sequencias hexadecimais (bytes literais)
//   / /       - expressoes regulares
// =============================================================================


// Detecta padroes usados para estabelecer conexoes reversas (reverse shells),
// permitindo que um atacante controle a maquina comprometida remotamente.
// Inclui variantes em bash, netcat, socat, Python, Perl e a tecnica classica
// de mkfifo para redirecionar stdin/stdout via pipe nomeado.
// Condicao: qualquer um dos padroes ja indica atividade suspeita.
rule reverse_shell
{
    meta:
        descricao = "Detecta padroes comuns de reverse shell"
        severidade = "critica"

    strings:
        $bash_i     = "/bin/bash -i" ascii
        $dev_tcp    = "/dev/tcp/" ascii
        $nc_exec    = "nc -e /bin/" ascii
        $ncat_exec  = "ncat -e /bin/" ascii
        $socat      = "socat exec:" ascii nocase
        $python_rev = "socket.socket" ascii
        $perl_rev   = "IO::Socket::INET" ascii
        $mkfifo     = "mkfifo /tmp/" ascii

    condition:
        any of them
}


// Detecta o anti-padrao "curl | bash", onde um script remoto e baixado e
// executado diretamente sem inspecao. Tecnica muito comum em instaladores
// maliciosos disfarçados de pacotes legitimos.
// Condicao: exige a presenca simultanea de uma ferramenta de download (curl/wget)
// E um pipe para shell, reduzindo falsos positivos.
rule download_and_execute
{
    meta:
        descricao = "Detecta padroes de download e execucao direta"
        severidade = "critica"

    strings:
        $curl_pipe  = "curl" ascii
        $wget_pipe  = "wget" ascii
        $pipe_bash  = "| bash" ascii
        $pipe_sh    = "| sh" ascii
        $pipe_dash  = "| /bin/sh" ascii
        $pipe_bash2 = "| /bin/bash" ascii

    condition:
        ($curl_pipe or $wget_pipe) and
        ($pipe_bash or $pipe_sh or $pipe_dash or $pipe_bash2)
}


// Detecta tentativas de leitura de arquivos que armazenam credenciais e chaves
// criptograficas, como /etc/shadow (hashes de senhas), chaves SSH privadas,
// credenciais AWS e keyrings GPG.
// Condicao: exige pelo menos 2 matches para reduzir falsos positivos, ja que
// um binario legitimo pode referenciar /etc/passwd isoladamente.
rule credential_harvesting
{
    meta:
        descricao = "Detecta acesso a arquivos sensiveis de credenciais"
        severidade = "alta"

    strings:
        $shadow  = "/etc/shadow" ascii
        $passwd  = "/etc/passwd" ascii
        $ssh_key = "/.ssh/id_rsa" ascii
        $ssh_dir = "/.ssh/authorized_keys" ascii
        $aws     = "/.aws/credentials" ascii
        $gnupg   = "/.gnupg/" ascii

    condition:
        2 of them
}


// Detecta mecanismos que permitem ao malware sobreviver a reinicializacoes,
// incluindo agendamento via crontab, registro de servicos systemd/SysVinit,
// injecao em arquivos de perfil do usuario (.bashrc/.profile) e uso de
// LD_PRELOAD para forcar o carregamento de bibliotecas maliciosas.
// Condicao: qualquer um dos padroes ja e suficiente.
rule persistence_mechanism
{
    meta:
        descricao = "Detecta tecnicas de persistencia no sistema"
        severidade = "alta"

    strings:
        $crontab     = "crontab" ascii
        $cron_dir    = "/etc/cron" ascii
        $systemd_svc = "/etc/systemd/system/" ascii
        $init_d      = "/etc/init.d/" ascii
        $rc_local    = "/etc/rc.local" ascii
        $bashrc      = ".bashrc" ascii
        $profile     = ".profile" ascii
        $ld_preload  = "LD_PRELOAD" ascii

    condition:
        any of them
}


// Detecta binarios ELF empacotados com UPX. O empacotador comprime o binario
// original e insere um stub de descompressao, dificultando a analise estatica
// do codigo real. Verifica o magic ELF (7f 45 4c 46) no offset 0 e a
// assinatura "UPX!" em qualquer posicao posterior.
rule upx_packed_elf
{
    meta:
        descricao = "Detecta binarios ELF empacotados com UPX"
        severidade = "media"

    strings:
        $elf       = { 7f 45 4c 46 }
        $upx_magic = "UPX!" ascii

    condition:
        $elf at 0 and $upx_magic
}


// Detecta binarios ELF que utilizam tecnicas anti-analise: ptrace para detectar
// debuggers, /proc/self/status para ler TracerPid, memfd_create para execucao
// fileless (payloads em memoria sem tocar disco), dlopen para carregamento
// dinamico e mprotect para tornar regioes de memoria executaveis (shellcode).
// Condicao: exige o magic ELF no inicio e pelo menos 3 tecnicas simultaneas,
// pois funcoes como dlopen e mprotect sao comuns em software legitimo isoladamente.
rule suspicious_elf_techniques
{
    meta:
        descricao = "Detecta tecnicas anti-analise em binarios ELF"
        severidade = "alta"

    strings:
        $elf         = { 7f 45 4c 46 }
        $ptrace      = "ptrace" ascii
        $proc_self   = "/proc/self/" ascii
        $proc_status = "/proc/self/status" ascii
        $tracerpid   = "TracerPid" ascii
        $memfd       = "memfd_create" ascii
        $dlopen      = "dlopen" ascii
        $mprotect    = "mprotect" ascii

    condition:
        $elf at 0 and 3 of ($ptrace, $proc_self, $proc_status, $tracerpid, $memfd, $dlopen, $mprotect)
}


// Detecta o uso de decodificacao base64 em scripts. Atacantes codificam
// comandos maliciosos em base64 para evitar deteccao por ferramentas que
// analisam apenas strings em texto plano. Cobre o utilitario nativo do Linux,
// funcoes de decodificacao em Python/Perl e o OpenSSL.
// Condicao: qualquer variante de decodificacao ja e suficiente.
rule base64_payload
{
    meta:
        descricao = "Detecta decodificacao de payloads base64 em scripts"
        severidade = "media"

    strings:
        $b64_decode1 = "base64 -d" ascii
        $b64_decode2 = "base64 --decode" ascii
        $python_b64  = "b64decode" ascii
        $perl_b64    = "decode_base64" ascii
        $openssl_b64 = "openssl enc -base64 -d" ascii

    condition:
        any of them
}


// Detecta envio silencioso de dados para servidores externos, combinando
// tres indicadores: um endereco IPv4 hardcoded (regex), uma ferramenta de
// rede em modo silencioso (curl -s, wget -q, nc) e supressao total de output
// via redirecionamento para /dev/null. A condicao composta de tres fatores
// reduz drasticamente falsos positivos.
rule network_exfiltration
{
    meta:
        descricao = "Detecta indicadores de exfiltracao de dados via rede"
        severidade = "alta"

    strings:
        $ip_pattern  = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/ ascii
        $hidden_curl = "curl -s" ascii
        $wget_quiet  = "wget -q" ascii
        $nc_send     = "nc " ascii
        $dev_null    = "> /dev/null 2>&1" ascii

    condition:
        $ip_pattern and
        ($hidden_curl or $wget_quiet or $nc_send) and
        $dev_null
}


// Detecta indicadores de cryptojacking, onde o atacante utiliza recursos
// computacionais da vitima para minerar criptomoedas. Cobre o protocolo
// Stratum (comunicacao miner-pool), o minerador XMRig, dominios de pools,
// enderecos de carteira Monero (regex de 95 caracteres) e termos comuns
// em configuracoes de mineradores.
// Condicao: exige 2 indicadores simultaneos para evitar falsos positivos
// com software legitimo que mencione termos como "mining" em outro contexto.
rule crypto_miner
{
    meta:
        descricao = "Detecta indicadores de mineracao de criptomoedas"
        severidade = "critica"

    strings:
        $stratum    = "stratum+tcp://" ascii
        $xmrig      = "xmrig" ascii nocase
        $monero     = "monero" ascii nocase
        $pool       = "pool." ascii
        $wallet     = /[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ ascii
        $hashrate   = "hashrate" ascii nocase
        $mining     = "mining" ascii nocase

    condition:
        2 of them
}
