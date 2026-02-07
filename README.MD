#### Para instalar o script (root é obrigatório). Verificando se LXC esta presente, use:
``` 
	(dpkg -s lxc >/dev/null 2>&1 || { apt update -y >/dev/null 2>/dev/stderr && apt install lxc -y >/dev/null 2>/dev/stderr; }) && curl -sSL https://raw.githubusercontent.com/srvictorbatista/lxcMachine/refs/heads/main/lxc_machine.sh -o ./lxc_machine.sh && chmod +x ./lxc_machine.sh && ./lxc_machine.sh start
``` 

Retorno esperado:
````

Start (implementando LXC no Boot):
 [OK] Unit criada e habilitada: lxc-machine-boot.service
 [OK] Ordem de boot garantida: storage preparado antes do LXC


````

Isto confirma que todos os recursos já estão disponiveis, para uso imediato.




