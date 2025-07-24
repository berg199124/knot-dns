#!/bin/bash

##################################################################################
#                                                                                
#  ESTE SCRIPT FOI PREPARADO PARA RODAR EM DEBIAN 12 COM 16GB DE RAM E 8 VCPU    
#  OBJETIVO: INSTALAR E OTIMIZAR O KNOT RESOLVER PARA ALTA PERFORMANCE DNS       
#  AUTOR: LYNMIKER LOURÊNÇO                                                     
#                                                                                
##################################################################################

set -e

echo "[+] Atualizando sistema..."
apt-get update && apt-get upgrade -y

echo "[+] Instalando pré-requisitos..."
apt-get install -y apt-transport-https ca-certificates wget curl nano gnupg2 software-properties-common lsb-release git sudo nano bat htop

echo "[+] Parando o resolvedor local do sistema (systemd-resolved)..."
systemctl stop systemd-resolved || true
systemctl disable systemd-resolved || true
rm -f /etc/resolv.conf
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 8.8.4.4" >> /etc/resolv.conf

echo "[+] Criando usuário knot-resolver..."
/sbin/useradd -r -M -s /usr/sbin/nologin knot-resolver || true

echo "[+] Criando cache em tmpfs..."
mkdir -p /var/cache/knot-resolver
echo "tmpfs /var/cache/knot-resolver tmpfs rw,size=8336M,uid=knot-resolver,gid=knot-resolver,nosuid,nodev,noexec,mode=0700 0 0" | tee -a /etc/fstab
mount -a

echo "[+] Adicionando repositório oficial do Knot Resolver..."
wget -O /usr/share/keyrings/cznic-labs-pkg.gpg https://pkg.labs.nic.cz/gpg
echo "deb [signed-by=/usr/share/keyrings/cznic-labs-pkg.gpg] https://pkg.labs.nic.cz/knot-resolver jammy main" > /etc/apt/sources.list.d/cznic-labs-knot-resolver.list 
apt update

echo "[+] Instalando Knot Resolver e módulos..."
echo "deb http://deb.debian.org/debian bookworm-backports main" | tee /etc/apt/sources.list.d/backports.list
apt-get update
apt-get install -y -t bookworm-backports libbpf0
cd /tmp
wget http://ftp.debian.org/debian/pool/main/libb/libbpf/libbpf0_1.2.0-2_amd64.deb
dpkg -i libbpf0_1.2.0-2_amd64.deb
apt-get install -f
rm /etc/apt/sources.list.d/knot-resolver.list || rm /etc/apt/sources.list.d/*.list
apt-get update
apt-get install -y knot-resolver knot-resolver-module-http knot-dnsutils

echo "[+] Ajustando arquivos de configuração do sistema..."

# sysctl tuning
cat <<EOF >> /etc/sysctl.conf

# Tuning para alto desempenho DNS
fs.file-max = 2097152
net.core.netdev_max_backlog = 16384
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_syncookies = 1
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
net.ipv4.neigh.default.gc_thresh1 = 4096
net.ipv4.neigh.default.gc_thresh2 = 8192
net.ipv4.neigh.default.gc_thresh3 = 16384
EOF

cp /sbin/sysctl /bin/
sysctl -p

# Limits tuning
echo "* soft nofile 1048576" >> /etc/security/limits.conf
echo "* hard nofile 1048576" >> /etc/security/limits.conf

sed -i 's/^#DefaultLimitNOFILE=.*/DefaultLimitNOFILE=1048576/' /etc/systemd/system.conf
sed -i 's/^#DefaultLimitNOFILE=.*/DefaultLimitNOFILE=1048576/' /etc/systemd/user.conf

echo "[+] Criando configuração padrão para o kresd..."
rm /etc/knot-resolver/kresd.conf

cat <<EOF > /etc/knot-resolver/kresd.conf
-- SPDX-License-Identifier: CC0-1.0
-- vim:syntax=lua:set ts=4 sw=4:
-- Refer to manual: https://knot-resolver.readthedocs.org/en/stable/

-- Carga de módulos extras úteis
modules = {
        'hints > iterate',  -- Allow loading /etc/hosts or custom root hints
        'stats',            -- Track internal statistics
        'view',             -- Habilita configurações de segurança
        'http',             -- Para exportar metricas
        'daf',              -- DNS Application Firewall
}

-- Configuração de rede
net.listen('0.0.0.0', 1053, { kind = 'dns' })
net.listen('0.0.0.0', 853, { kind = 'tls' })
net.listen('0.0.0.0', 8453, { kind = 'webmgmt' })

-- Tunning de perfomance
cache.size = cache.fssize() - 10*MB

-- Lista de origens permitidas na querie
-- Redes Privadas
view:addr('10.0.0.0/8', policy.all(policy.PASS))
view:addr('172.16.0.0/12', policy.all(policy.PASS))
view:addr('192.168.0.0/16', policy.all(policy.PASS))
view:addr('100.64.0.0/10', policy.all(policy.PASS))
view:addr('127.0.0.1/32', policy.all(policy.PASS))

-- Drop do restante
view:addr('0.0.0.0/0', policy.all(policy.DROP))

EOF

echo "[+] Aplicando tuning por unidade kresd..."
#Do 1 ate o 7
#nano /etc/systemd/system/kresd.target.wants/kresd\@1.service
#[Service]
#LimitNOFILE=1048576

echo 'MAXCONN=100000' >> /etc/pihole/pihole-FTL.conf
echo 'FTL_MAX_CONCURRENT_QUERIES=1000000' >> /etc/pihole/pihole-FTL.conf

echo "[+] Habilitando serviços kresd para múltiplos núcleos (1..7)..."
systemctl daemon-reexec
systemctl daemon-reload
systemctl enable kresd@{1..7}
systemctl start kresd@{1..7}

echo "[✔] Instalação e configuração do Knot Resolver concluídas com sucesso!"


###TUNNING EXTRA###

#sudo nano /etc/security/limits.conf
#*               soft    nofile          65536
#*               hard    nofile          65536

#sudo nano  /etc/pihole/pihole.toml
#size = 100000 ### CHANGED, default = 10000

#nano /etc/systemd/system/pihole-FTL.service
#[Service]
#LimitNOFILE=65536


##integrar o Pi-hole ao Knot Resolver##
curl -sSL https://install.pi-hole.net | bash

#Escolha a opcao customizer
#PIHOLE_DNS_1=127.0.0.1#1053


systemctl daemon-reexec
systemctl daemon-reload
systemctl restart kresd@{1..7}
systemctl restart pihole-FTL

#TESTE RESOLVER DNS
dig @127.0.0.1 -p 1053 google.com
dig @127.0.0.1 -p 53 google.com

