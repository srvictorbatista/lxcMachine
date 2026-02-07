#### Para instalar o script (root é obrigatório). Use:
``` 
	(dpkg -s lxc >/dev/null 2>&1 || { apt update -y >/dev/null 2>/dev/stderr && apt install lxc -y >/dev/null 2>/dev/stderr; }) && curl -sSL https://raw.githubusercontent.com/srvictorbatista/lxcMachine/refs/heads/main/lxc_machine.sh -o ./lxc_machine.sh && chmod +x ./lxc_machine.sh && ./lxc_machine.sh start
``` 
<p>&nbsp;</p>

Retorno esperado:
```````

Start (implementando LXC no Boot):
 [OK] Unit criada e habilitada: lxc-machine-boot.service
 [OK] Ordem de boot garantida: storage preparado antes do LXC


```````

Isto confirma que todos os recursos já estão configurados e disponiveis, para uso imediato. <BR>
Basta enviar "```` LXC ````" ou "```` lxc ````" ao terminal, para criar sua primeira maquina. <BR>
\* **Não use espaço ao nomear um novo servidor**❗

Por questões de segurança; Este script e seus recursos, só estarão disponíveis ao root e ususários elevados. Recomando não alterar esta política.




