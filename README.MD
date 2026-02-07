### Para instalar o script em / (root é obrigatório). Verificando se LXC esta presente, use:
``` 
	(dpkg -s lxc >/dev/null 2>&1 || { apt update -y && apt install lxc -y; }) && curl -sSL https://raw.githubusercontent.com/srvictorbatista/lxcMachine/refs/heads/main/lxc_machine.sh -o ./lxc_machine.sh && chmod +x ./lxc_machine.sh && ./lxc_machine.sh start
``` 