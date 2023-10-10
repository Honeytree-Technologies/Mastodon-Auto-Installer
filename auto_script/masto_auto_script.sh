#!/bin/bash
# Display the script header, providing basic information about the script.
echo "######################################################################"
echo "#                                                                    #"
echo "#            Mastodon Installation and Hardening Script              #"
echo "#                                                                    #"
echo "#              Created by Honeytree Technologies, LLC                #"
echo "#                        www.honeytreetech.com                       #"
echo "#                                                                    #"
echo "#                    Mastodon: honeytree.social                      #"
echo "#                    Email: info@honeytreetech.com                   #"
echo "#                                                                    #"
echo "######################################################################"

# Pause the script for 3 seconds to allow the user to read the header
sleep 3

# Display more detailed information about what each option does
echo "########################################################################"
echo "##### THIS IS IMPORTANT, PLEASE READ CAREFULLY BEFORE SELECTING    #####"
echo "#####                                                              #####"
echo "#####  This will install Mastodon on fresh server.                 #####"
echo "#####                                                              #####"
echo "##### Installing on an operating Mastodon server will wipe data.   #####"
echo "#####                                                              #####"
echo "########################################################################"

# Pause the script for 3 seconds to allow the user to read the warning
sleep 3

# Function to generate a random character
function random_char() {
  local chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
  echo -n "${chars:RANDOM%${#chars}:1}"
}

# Function to generate a random string of a given length
function random_string() {
  local length=$1
  local result=""
  for ((i = 0; i < length; i++)); do
    result="${result}$(random_char)"
  done
  echo -n "$result"
}

# Function to validate if the port number is within the specified range
validate_port() {
    local port=$1
    local excluded_ports=("80" "443" "3000")

    if [[ $port =~ ^[0-9]+$ && $port -ge 0 && $port -le 65536 ]]; then
        for excluded_port in "${excluded_ports[@]}"; do
            if [ "$port" -eq "$excluded_port" ]; then
                return 2  # Excluded port
            fi
        done
        return 0  # Valid port number
    else
        return 1  # Invalid port number
    fi
}

while true; do
  read -p "Enter admin user name: " admin_user
  if [ -n "$admin_user" ]; then
    break
  else
    echo "Admin name cannot be empty. Please enter admin name."
  fi
done

while true; do
  read -p "Enter admin email: " admin_email
  if [ -n "$admin_email" ]; then
    break
  else
    echo "Admin email cannot be empty. Please enter admin email."
  fi
done

while true; do
  read -p "Enter valid domain name: " domain_name
  if [ -n "$domain_name" ]; then
    break
  else
    echo "Domain cannot be empty. Please enter domain."
  fi
done

while true; do
  read -p "Enter the postgres db size in mb (Default: 256mb): " db_size
  # set default value if value not present
  if [ -z ${db_size} ] ; then
    db_size=256
  fi
  # Check if input is numeric
  if [[ "${db_size}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
      break  # Exit the loop if input is numeric
  else
      echo "Invalid input. Please enter numerical value."
  fi
done
echo "Your db_size is, $db_size"

# choice for elastic search service
while true; do
  read -p "Do you want elasticsearch service (yes/no): " choice
  case "$choice" in
    [Yy]*)
      es_status=true
      break
      ;;
    [Nn]*)
      es_status=false
      break
      ;;
    *)
      echo "Invalid input. Please enter 'yes' or 'no'."
      ;;
  esac
done

while true; do
  read -p "Enter SMTP SERVER: " smtp_server
  if [ -n "$smtp_server" ]; then
    break
  else
    echo "SMTP SERVER cannot be empty. Please enter smtp server."
  fi
done

while true; do
  read -p "Enter SMTP PORT: " smtp_port
  if [ -n "$smtp_port" ]; then

    break
  else
    echo "SMTP PORT cannot be empty. Please enter smtp port."
  fi
done

while true; do
  read -p "Enter SMTP LOGIN: " smtp_login
  if [ -n "$smtp_login" ]; then
    break
  else
    echo "SMTP LOGIN cannot be empty. Please enter smtp_login."
  fi
done

while true; do
  read -p "Enter SMTP_PASSWORD: " smtp_password
  if [ -n "$smtp_password" ]; then
    break
  else
    echo "SMTP_PASSWORD cannot be empty. Please enter smtp password."
  fi
done

while true; do
  read -p "Enter SMTP FROM ADDRESS: " smtp_from_address
  if [ -n "$smtp_from_address" ]; then
    break
  else
    echo "SMTP FROM ADDRESS cannot be empty. Please enter smtp from address."
  fi
done


read -p "Enter the DB USER NAME (Default: postgres): " db_user
if [ -z ${db_user} ] ; then
  db_user=postgres
fi

temp_password="pass_$(random_string 16)"
read -p "Enter the DB PASSWORD (Default: ${temp_password}): " db_password
if [ -z ${db_password} ] ; then
  db_password=${temp_password}
fi
echo "your db password is ${db_password}"
temp_db="masto_$(random_string 8)"
read -p "Enter the DB NAME (Default: ${temp_db}): " db_name
if [ -z ${db_name} ] ; then
  db_name=${temp_db}
fi
echo "Your db name is ${db_name}"

read -p "Enter the ELASTIC SEARCH USER (Default: elastic): " es_user
if [ -z ${es_user} ] ; then
  es_user=elastic
fi
e_temp_password="pass_$(random_string 16)"
read -p "Enter the ELASTIC SEARCH PASSWORD (Default: ${e_temp_password}): " es_password
if [ -z ${es_password} ] ; then
  es_password=${e_temp_password}
fi

# Prompt the user until a valid port is entered
while true; do
  read -p "Enter a port number (1-65535, excluding 80, 443, and 3000): " port
  # Validate the input
  validate_port "$port"
  case $? in
    0)
      echo "SSH  port will be: $port"
      ssh_port=$port
      break  # Exit the loop as a valid port has been entered
      ;;
    1)
      echo "Invalid port number. Please enter a valid port number between 1 and 65535."
      ;;
    2)
      echo "Invalid port number. Port $port is excluded. Please choose a different port."
      ;;
  esac
done

# Remove old docker container if docker already present 
if docker -v &>/dev/null; then
  sudo docker rm -f $(docker ps -a -q)
fi

# install new version of docker
sudo apt-get update -y
sudo apt-get install -y ca-certificates curl gnupg lsb-release
if test -f /usr/share/keyrings/docker-archive-keyring.gpg; then
 sudo rm /usr/share/keyrings/docker-archive-keyring.gpg
fi
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update -y
sudo apt-get install -y  docker-ce docker-ce-cli containerd.io docker-compose-plugin

# assign work directory
work_dir=~/mastodon
# Remove old work directory if present
sudo rm -rf ${work_dir}
# Make new work directory
mkdir ${work_dir}

# create blank a enviromental files for Mastodon
touch ${work_dir}/.env.es
touch ${work_dir}/.env.mastodon
touch ${work_dir}/docker-compose.yml
touch ${work_dir}/.env.db

# add content in the docker-compose file
cat <<docker_content >>${work_dir}/docker-compose.yml
version: '3'

networks:

  external_network:

  internal_network:

    internal: true

services:

  db:

    restart: always

    image: postgres:14-alpine

    shm_size: ${db_size}mb 

    networks:

      - internal_network

    healthcheck:

      test: [ 'CMD', 'pg_isready', '-U', 'postgres' ]

    volumes:

      - ./data/postgres:/var/lib/postgresql/data

    environment:

      - 'POSTGRES_HOST_AUTH_METHOD=trust'

    env_file:

      - .env.db

  redis:

    restart: always

    image: redis:7-alpine

    networks:

      - internal_network

    healthcheck:

      test: [ 'CMD', 'redis-cli', 'ping' ]

    volumes:

      - ./data/redis:/data

  es:

    restart: always

    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.8

    environment:

      - "ES_JAVA_OPTS=-Xms512m -Xmx512m -Des.enforce.bootstrap.checks=true"

      - "xpack.license.self_generated.type=basic"

      - "xpack.security.enabled=false"

      - "xpack.watcher.enabled=false"

      - "xpack.graph.enabled=false"

      - "xpack.ml.enabled=false"

      - "bootstrap.memory_lock=true"

      - "cluster.name=mastodon-es"

      - "discovery.type=single-node"

      - "thread_pool.write.queue_size=1000"

    env_file:

      - .env.es

    networks:

      - external_network

      - internal_network

    healthcheck:

      test:

        [

          "CMD-SHELL",

          "curl --silent --fail localhost:9200/_cluster/health || exit 1"

        ]

    volumes:

      - /opt/mastodon/data/elasticsearch:/usr/share/elasticsearch/data

    ulimits:

      memlock:

        soft: -1

        hard: -1

      nofile:

        soft: 65536

        hard: 65536

    ports:

      - '127.0.0.1:9200:9200'



  console:

    image: tootsuite/mastodon:latest

    env_file: .env.mastodon

    command: /bin/bash

    restart: "no"

    depends_on:

      - db

      - redis

    networks:

      - internal_network

      - external_network

    volumes:

      - ./data/public/system:/mastodon/public/system

  web:

    image: tootsuite/mastodon:latest

    restart: always

    env_file: .env.mastodon

    command: bash -c "rm -f /mastodon/tmp/pids/server.pid; bundle exec rails s -p 3000"

    networks:

      - internal_network

      - external_network

    healthcheck:

      # prettier-ignore

      test:

        [

          'CMD-SHELL',

          'wget -q --spider --proxy=off localhost:3000/health || exit 1'

        ]

    ports:

      - '127.0.0.1:3000:3000'

    depends_on:

      - db

      - redis

      - es

    volumes:

      - ./data/public/system:/mastodon/public/system



  streaming:

    image: tootsuite/mastodon:latest

    restart: always

    env_file: .env.mastodon

    command: node ./streaming

    networks:

      - external_network

      - internal_network

    healthcheck:

      # prettier-ignore

      test:

        [

          'CMD-SHELL',

          'wget -q --spider --proxy=off localhost:4000/api/v1/streaming/health || exit 1'

        ]

    ports:

      - '127.0.0.1:4000:4000'

    depends_on:

      - db

      - redis

  sidekiq:

    image: tootsuite/mastodon:latest

    restart: always

    env_file: .env.mastodon

    command: bundle exec sidekiq

    networks:

      - external_network

      - internal_network

    volumes:

      - ./data/public/system:/mastodon/public/system

    healthcheck:

      test: [ 'CMD-SHELL', "ps aux | grep '[s]idekiq 6' || false" ]

    depends_on:

      - db

      - redis
docker_content

# Add content in the.env.db file
cat <<db_env >> ${work_dir}/.env.db
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
db_env

# Add content in the .env.es file
cat <<es_env >> ${work_dir}/.env.es
ELASTIC_PASSWORD=password
es_env

#Generate secret keys
secret1=$(docker compose -f ${work_dir}/docker-compose.yml run --rm console bundle exec rake secret)
secret2=$(docker compose -f ${work_dir}/docker-compose.yml run --rm console bundle exec rake secret)
keys=$(docker compose -f ${work_dir}/docker-compose.yml run --rm console bundle exec rake mastodon:webpush:generate_vapid_key)
vapid_private_key=$(echo "$keys" | grep -o 'VAPID_PRIVATE_KEY=[^ ]*' | cut -d'=' -f2)=
vapid_public_key=$(echo "$keys" | grep -o 'VAPID_PUBLIC_KEY=[^ ]*' | cut -d'=' -f2)=

# Add content in the .env.mastodon
cat <<mastodon_env >> ${work_dir}/.env.mastodon
LOCAL_DOMAIN=${domain_name}
REDIS_HOST=redis
REDIS_PORT=6379
DB_HOST=db
DB_USER=${db_user}
DB_NAME=${db_name}
DB_PASS=${db_password}
DB_PORT=5432
ES_ENABLED=${es_status}
ES_HOST=es
ES_PORT=9200
ES_USER=${es_user}
ES_PASS=${es_password}
SECRET_KEY_BASE=${secret1}
OTP_SECRET=${secret2}
VAPID_PRIVATE_KEY=${vapid_private_key}
VAPID_PUBLIC_KEY=${vapid_public_key}
SMTP_SERVER=${smtp_server}
SMTP_PORT=${smtp_port}
SMTP_LOGIN=${smtp_login}
SMTP_PASSWORD=${smtp_password}
SMTP_FROM_ADDRESS=${smtp_from_address}
S3_ENABLED=false
S3_BUCKET=<YOUR_OBJECT_STORAGE_BUCKET>
AWS_ACCESS_KEY_ID=<YOUR_OBJECT_STORAGE_ACCESS_KEY>
AWS_SECRET_ACCESS_KEY=<YOUR_OBJECT_STORAGE_SECRET_KEY>
S3_ALIAS_HOST=<YOUR_OBJECT_STORAGE_URL>
IP_RETENTION_PERIOD=31556952
SESSION_RETENTION_PERIOD=31556952
mastodon_env

#  start the PostgreSQL container
docker compose -f ${work_dir}/docker-compose.yml up -d db

#  Start the Elasticsearch container and make data directory.
if [ "$es_status" = true ]; then
 sudo mkdir -p ${work_dir}/data/elasticsearch
 sudo chown -R 1000:1000 ${work_dir}/data/elasticsearch
 docker compose -f ${work_dir}/docker-compose.yml up -d es
fi

# increase the max_map_count
sudo sysctl -w vm.max_map_count=262144



# Make Database setup 
docker compose -f ${work_dir}/docker-compose.yml run --rm console bundle exec rake db:setup

# Start Mastadon application.
docker compose -f ${work_dir}/docker-compose.yml up -d

# Setting up the nginx 

if nginx -v &>/dev/null; then
  echo "Nginx is already install installed"
  rm /etc/nginx/sites-available/mastodon
  rm /etc/nginx/sites-enabled/mastodon
else
  sudo apt-get update
  sudo apt-get install -y nginx
fi

# make the nginx file for the application 
touch /etc/nginx/sites-available/mastodon
cat <<nginx_content >>/etc/nginx/sites-available/mastodon
server {

    server_name ${domain_name};



    proxy_set_header Host \$host;

    proxy_set_header X-Real-IP \$remote_addr;

    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;

    proxy_set_header X-Forwarded-Proto \$scheme;

    proxy_set_header Proxy "";

    proxy_http_version 1.1;

    proxy_set_header Upgrade \$http_upgrade;

    proxy_set_header Connection "upgrade";



        location / {

            proxy_pass http://localhost:3000;

            proxy_pass_header Server;



            proxy_buffering on;

            proxy_redirect off;

        }



        location ^~ /api/v1/streaming {



            proxy_pass http://localhost:4000;

            proxy_buffering off;

            proxy_redirect off;

        }

}
nginx_content

#  Link to sites-enabled to enable the virtual host.
sudo ln -s /etc/nginx/sites-available/mastodon /etc/nginx/sites-enabled/

#  Reload the nginx service.
sudo systemctl restart nginx

# Config ufw firewall to allow Nginx ports. Skip if your server doesn't have ufw.
sudo ufw allow 'Nginx Full'

# Secure Mastodon with Let's Encrypt SSL
sudo apt-get install -y certbot python3-certbot-nginx

# Generate the ssl certificate for domain
sudo certbot --nginx -d ${domain_name}

systemctl restart nginx

# Enable toolctl toolctl in docker container
docker compose -f ${work_dir}/docker-compose.yml run --rm console bin/tootctl

# Generate Admin password
admin_password=$(docker compose -f ${work_dir}/docker-compose.yml run --rm console bin/tootctl accounts create ${admin_user} --email ${admin_email} --confirmed --role Admin | awk '/password:/{print }')

# Remove Media files
docker compose -f ${work_dir}/docker-compose.yml run --rm console bin/tootctl media remove
# Remove Preview cards
docker compose -f ${work_dir}/docker-compose.yml run --rm console bin/tootctl preview_cards remove

# make cron job for Remove Media files and Remove Preview cards
cat <<make_job >>${work_dir}/auto-cleanup.sh 
#!/bin/sh

docker compose -f ${work_dir}/docker-compose.yml run --rm console bin/tootctl media remove

docker compose -f ${work_dir}/docker-compose.yml run --rm console bin/tootctl preview_cards remove
make_job

# Give permission to crontab 
sudo chmod +x ${work_dir}/auto-cleanup.sh

echo "0 0 * * * ${work_dir}/auto-cleanup.sh" | crontab -

# change ssh port
sudo cp /etc/ssh/ssh_config /etc/ssh/ssh_config_copy
sudo rm /etc/ssh/ssh_config

cat <<ssh_content >> /etc/ssh/ssh_config
Host *
#   ForwardAgent no
#   ForwardX11 no
#   ForwardX11Trusted yes
#   PasswordAuthentication yes
#   HostbasedAuthentication no
#   GSSAPIAuthentication no
#   GSSAPIDelegateCredentials no
#   GSSAPIKeyExchange no
#   GSSAPITrustDNS no
#   BatchMode no
#   CheckHostIP yes
#   AddressFamily any
#   ConnectTimeout 0
#   StrictHostKeyChecking ask
#   IdentityFile ~/.ssh/id_rsa
#   IdentityFile ~/.ssh/id_dsa
#   IdentityFile ~/.ssh/id_ecdsa
#   IdentityFile ~/.ssh/id_ed25519
   Port ${ssh_port}
#   Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc
#   MACs hmac-md5,hmac-sha1,umac-64@openssh.com
#   EscapeChar ~
#   Tunnel no
#   TunnelDevice any:any
#   PermitLocalCommand no
#   VisualHostKey no
#   ProxyCommand ssh -q -W %h:%p gateway.example.com
#   RekeyLimit 1G 1h
#   UserKnownHostsFile ~/.ssh/known_hosts.d/%k
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes
ssh_content

sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config_copy
sudo rm /etc/ssh/sshd_config

cat <<sshd_content >> /etc/ssh/sshd_config
PermitRootLogin yes


# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

Include /etc/ssh/sshd_config.d/*.conf

Port ${ssh_port}
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
#LogLevel INFO

# Authentication:

#LoginGraceTime 2m
#PermitRootLogin prohibit-password
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

#PubkeyAuthentication yes

# Expect .ssh/authorized_keys2 to be disregarded by default in future.
#AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
#PasswordAuthentication yes
#PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
KbdInteractiveAuthentication no

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the KbdInteractiveAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via KbdInteractiveAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and KbdInteractiveAuthentication to 'no'.
UsePAM yes

#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
X11Forwarding yes
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
PrintMotd no
#PrintLastLog yes
#TCPKeepAlive yes
#PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS no
#PidFile /run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
#Banner none

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

# override default of no subsystems
Subsystem sftp  /usr/lib/openssh/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
# X11Forwarding no
# AllowTcpForwarding no
# PermitTTY no
# ForceCommand cvs server
sshd_content

#  restart sshd service
systemctl reload ssh
systemctl reload sshd
systemctl restart ssh
systemctl restart sshd

# Turn on automatic security updates.
sudo dpkg-reconfigure -plow unattended-upgrades --unseen-only

# set up a firewall with ufw.
sudo apt-get install ufw
sudo ufw default allow outgoing
sudo ufw default deny incoming
sudo ufw allow ${ssh_port}/tcp comment 'SSH'
sudo ufw allow http comment 'HTTP'
sudo ufw allow https comment 'HTTPS'
 yes | sudo ufw enable

# Install Fail2Ban
sudo apt-get install -y fail2ban
rm /etc/fail2ban/jail.local
touch /etc/fail2ban/jail.local

# make fail2ban configuration
cat <<fail2ban_ban >> /etc/fail2ban/jail.local
#
# WARNING: heavily refactored in 0.9.0 release.  Please review and
#          customize settings for your setup.
#
# Changes:  in most of the cases you should not modify this
#           file, but provide customizations in jail.local file,
#           or separate .conf files under jail.d/ directory, e.g.:
#
# HOW TO ACTIVATE JAILS:
#
# YOU SHOULD NOT MODIFY THIS FILE.
#
# It will probably be overwritten or improved in a distribution update.
#
# Provide customizations in a jail.local file or a jail.d/customisation.local.
# For example to change the default bantime for all jails and to enable the
# ssh-iptables jail the following (uncommented) would appear in the .local file.
# See man 5 jail.conf for details.
#
# [DEFAULT]
# bantime = 1h
#
# [sshd]
# enabled = true
#
# See jail.conf(5) man page for more information



# Comments: use '#' for comment lines and ';' (following a space) for inline comments


[INCLUDES]

#before = paths-distro.conf
before = paths-debian.conf

# The DEFAULT allows a global definition of the options. They can be overridden
# in each jail afterwards.

[DEFAULT]

#
# MISCELLANEOUS OPTIONS
#

# "bantime.increment" allows to use database for searching of previously banned ip's to increase a 
# default ban time using special formula, default it is banTime * 1, 2, 4, 8, 16, 32...
#bantime.increment = true

# "bantime.rndtime" is the max number of seconds using for mixing with random time 
# to prevent "clever" botnets calculate exact time IP can be unbanned again:
#bantime.rndtime = 

# "bantime.maxtime" is the max number of seconds using the ban time can reach (doesn't grow further)
#bantime.maxtime = 

# "bantime.factor" is a coefficient to calculate exponent growing of the formula or common multiplier,
# default value of factor is 1 and with default value of formula, the ban time 
# grows by 1, 2, 4, 8, 16 ...
#bantime.factor = 1

# "bantime.formula" used by default to calculate next value of ban time, default value below,
# the same ban time growing will be reached by multipliers 1, 2, 4, 8, 16, 32...
#bantime.formula = ban.Time * (1<<(ban.Count if ban.Count<20 else 20)) * banFactor
#
# more aggressive example of formula has the same values only for factor "2.0 / 2.885385" :
#bantime.formula = ban.Time * math.exp(float(ban.Count+1)*banFactor)/math.exp(1*banFactor)

# "bantime.multipliers" used to calculate next value of ban time instead of formula, coresponding 
# previously ban count and given "bantime.factor" (for multipliers default is 1);
# following example grows ban time by 1, 2, 4, 8, 16 ... and if last ban count greater as multipliers count, 
# always used last multiplier (64 in example), for factor '1' and original ban time 600 - 10.6 hours
#bantime.multipliers = 1 2 4 8 16 32 64
# following example can be used for small initial ban time (bantime=60) - it grows more aggressive at begin,
# for bantime=60 the multipliers are minutes and equal: 1 min, 5 min, 30 min, 1 hour, 5 hour, 12 hour, 1 day, 2 day
#bantime.multipliers = 1 5 30 60 300 720 1440 2880

# "bantime.overalljails" (if true) specifies the search of IP in the database will be executed 
# cross over all jails, if false (dafault), only current jail of the ban IP will be searched
#bantime.overalljails = false

# --------------------

# "ignoreself" specifies whether the local resp. own IP addresses should be ignored
# (default is true). Fail2ban will not ban a host which matches such addresses.
#ignoreself = true

# "ignoreip" can be a list of IP addresses, CIDR masks or DNS hosts. Fail2ban
# will not ban a host which matches an address in this list. Several addresses
# can be defined using space (and/or comma) separator.
#ignoreip = 127.0.0.1/8 ::1

# External command that will take an tagged arguments to ignore, e.g. <ip>,
# and return true if the IP is to be ignored. False otherwise.
#
# ignorecommand = /path/to/command <ip>
ignorecommand =

# "bantime" is the number of seconds that a host is banned.
bantime  = 10m

# A host is banned if it has generated "maxretry" during the last "findtime"
# seconds.
findtime  = 10m

# "maxretry" is the number of failures before a host get banned.
maxretry = 5

# "maxmatches" is the number of matches stored in ticket (resolvable via tag <matches> in actions).
maxmatches = %(maxretry)s

# "backend" specifies the backend used to get files modification.
# Available options are "pyinotify", "gamin", "polling", "systemd" and "auto".
# This option can be overridden in each jail as well.
#
# pyinotify: requires pyinotify (a file alteration monitor) to be installed.
#              If pyinotify is not installed, Fail2ban will use auto.
# gamin:     requires Gamin (a file alteration monitor) to be installed.
#              If Gamin is not installed, Fail2ban will use auto.
# polling:   uses a polling algorithm which does not require external libraries.
# systemd:   uses systemd python library to access the systemd journal.
#              Specifying "logpath" is not valid for this backend.
#              See "journalmatch" in the jails associated filter config
# auto:      will try to use the following backends, in order:
#              pyinotify, gamin, polling.
#
# Note: if systemd backend is chosen as the default but you enable a jail
#       for which logs are present only in its own log files, specify some other
#       backend for that jail (e.g. polling) and provide empty value for
#       journalmatch. See https://github.com/fail2ban/fail2ban/issues/959#issuecomment-74901200
backend = auto

# "usedns" specifies if jails should trust hostnames in logs,
#   warn when DNS lookups are performed, or ignore all hostnames in logs
#
# yes:   if a hostname is encountered, a DNS lookup will be performed.
# warn:  if a hostname is encountered, a DNS lookup will be performed,
#        but it will be logged as a warning.
# no:    if a hostname is encountered, will not be used for banning,
#        but it will be logged as info.
# raw:   use raw value (no hostname), allow use it for no-host filters/actions (example user)
usedns = warn

# "logencoding" specifies the encoding of the log files handled by the jail
#   This is used to decode the lines from the log file.
#   Typical examples:  "ascii", "utf-8"
#
#   auto:   will use the system locale setting
logencoding = auto

# "enabled" enables the jails.
#  By default all jails are disabled, and it should stay this way.
#  Enable only relevant to your setup jails in your .local or jail.d/*.conf
#
# true:  jail will be enabled and log files will get monitored for changes
# false: jail is not enabled
enabled = false


# "mode" defines the mode of the filter (see corresponding filter implementation for more info).
mode = normal

# "filter" defines the filter to use by the jail.
#  By default jails have names matching their filter name
#
filter = %(__name__)s[mode=%(mode)s]


#
# ACTIONS
#

# Some options used for actions

# Destination email address used solely for the interpolations in
# jail.{conf,local,d/*} configuration files.
destemail = root@localhost

# Sender email address used solely for some actions
sender = root@<fq-hostname>

# E-mail action. Since 0.8.1 Fail2Ban uses sendmail MTA for the
# mailing. Change mta configuration parameter to mail if you want to
# revert to conventional 'mail'.
mta = sendmail

# Default protocol
protocol = tcp

# Specify chain where jumps would need to be added in ban-actions expecting parameter chain
chain = <known/chain>

# Ports to be banned
# Usually should be overridden in a particular jail
port = 0:65535

# Format of user-agent https://tools.ietf.org/html/rfc7231#section-5.5.3
fail2ban_agent = Fail2Ban/%(fail2ban_version)s

#
# Action shortcuts. To be used to define action parameter

# Default banning action (e.g. iptables, iptables-new,
# iptables-multiport, shorewall, etc) It is used to define
# action_* variables. Can be overridden globally or per
# section within jail.local file
banaction = ufw
banaction_allports = ufw

# The simplest action to take: ban only
action_ = %(banaction)s[port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]

# ban & send an e-mail with whois report to the destemail.
action_mw = %(action_)s
            %(mta)s-whois[sender="%(sender)s", dest="%(destemail)s", protocol="%(protocol)s", chain="%(chain)s"]

# ban & send an e-mail with whois report and relevant log lines
# to the destemail.
action_mwl = %(action_)s
             %(mta)s-whois-lines[sender="%(sender)s", dest="%(destemail)s", logpath="%(logpath)s", chain="%(chain)s"]

# See the IMPORTANT note in action.d/xarf-login-attack for when to use this action
#
# ban & send a xarf e-mail to abuse contact of IP address and include relevant log lines
# to the destemail.
action_xarf = %(action_)s
             xarf-login-attack[service=%(__name__)s, sender="%(sender)s", logpath="%(logpath)s", port="%(port)s"]

# ban IP on CloudFlare & send an e-mail with whois report and relevant log lines
# to the destemail.
action_cf_mwl = cloudflare[cfuser="%(cfemail)s", cftoken="%(cfapikey)s"]
                %(mta)s-whois-lines[sender="%(sender)s", dest="%(destemail)s", logpath="%(logpath)s", chain="%(chain)s"]

# Report block via blocklist.de fail2ban reporting service API
# 
# See the IMPORTANT note in action.d/blocklist_de.conf for when to use this action.
# Specify expected parameters in file action.d/blocklist_de.local or if the interpolation
# action_blocklist_de used for the action, set value of blocklist_de_apikey
# in your jail.local globally (section [DEFAULT]) or per specific jail section (resp. in 
# corresponding jail.d/my-jail.local file).
#
action_blocklist_de  = blocklist_de[email="%(sender)s", service="%(__name__)s", apikey="%(blocklist_de_apikey)s", agent="%(fail2ban_agent)s"]

# Report ban via badips.com, and use as blacklist
#
# See BadIPsAction docstring in config/action.d/badips.py for
# documentation for this action.
#
# NOTE: This action relies on banaction being present on start and therefore
# should be last action defined for a jail.
#
action_badips = badips.py[category="%(__name__)s", banaction="%(banaction)s", agent="%(fail2ban_agent)s"]
#
# Report ban via badips.com (uses action.d/badips.conf for reporting only)
#
action_badips_report = badips[category="%(__name__)s", agent="%(fail2ban_agent)s"]

# Report ban via abuseipdb.com.
#
# See action.d/abuseipdb.conf for usage example and details.
#
action_abuseipdb = abuseipdb

# Choose default action.  To change, just override value of 'action' with the
# interpolation to the chosen action shortcut (e.g.  action_mw, action_mwl, etc) in jail.local
# globally (section [DEFAULT]) or per specific section
action = %(action_)s


#
# JAILS
#

#
# SSH servers
#

[sshd]

# To use more aggressive sshd modes set filter parameter "mode" in jail.local:
# normal (default), ddos, extra or aggressive (combines all).
# See "tests/files/logs/sshd" or "filter.d/sshd.conf" for usage example and details.
#mode   = normal
port    = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s


[dropbear]

port     = ssh
logpath  = %(dropbear_log)s
backend  = %(dropbear_backend)s


[selinux-ssh]

port     = ssh
logpath  = %(auditd_log)s


#
# HTTP servers
#

[apache-auth]

port     = http,https
logpath  = %(apache_error_log)s


[apache-badbots]
# Ban hosts which agent identifies spammer robots crawling the web
# for email addresses. The mail outputs are buffered.
port     = http,https
logpath  = %(apache_access_log)s
bantime  = 48h
maxretry = 1


[apache-noscript]

port     = http,https
logpath  = %(apache_error_log)s


[apache-overflows]

port     = http,https
logpath  = %(apache_error_log)s
maxretry = 2


[apache-nohome]

port     = http,https
logpath  = %(apache_error_log)s
maxretry = 2


[apache-botsearch]

port     = http,https
logpath  = %(apache_error_log)s
maxretry = 2


[apache-fakegooglebot]

port     = http,https
logpath  = %(apache_access_log)s
maxretry = 1
ignorecommand = %(ignorecommands_dir)s/apache-fakegooglebot <ip>


[apache-modsecurity]

port     = http,https
logpath  = %(apache_error_log)s
maxretry = 2


[apache-shellshock]

port    = http,https
logpath = %(apache_error_log)s
maxretry = 1


[openhab-auth]

filter = openhab
banaction = %(banaction_allports)s
logpath = /opt/openhab/logs/request.log


[nginx-http-auth]

port    = http,https
logpath = %(nginx_error_log)s

# To use 'nginx-limit-req' jail you should have ngx_http_limit_req_module 
# and define limit_req and limit_req_zone as described in nginx documentation
# http://nginx.org/en/docs/http/ngx_http_limit_req_module.html
# or for example see in 'config/filter.d/nginx-limit-req.conf'
[nginx-limit-req]
port    = http,https
logpath = %(nginx_error_log)s

[nginx-botsearch]

port     = http,https
logpath  = %(nginx_error_log)s
maxretry = 2


# Ban attackers that try to use PHP's URL-fopen() functionality
# through GET/POST variables. - Experimental, with more than a year
# of usage in production environments.

[php-url-fopen]

port    = http,https
logpath = %(nginx_access_log)s
          %(apache_access_log)s


[suhosin]

port    = http,https
logpath = %(suhosin_log)s


[lighttpd-auth]
# Same as above for Apache's mod_auth
# It catches wrong authentifications
port    = http,https
logpath = %(lighttpd_error_log)s


#
# Webmail and groupware servers
#

[roundcube-auth]

port     = http,https
logpath  = %(roundcube_errors_log)s
# Use following line in your jail.local if roundcube logs to journal.
#backend = %(syslog_backend)s


[openwebmail]

port     = http,https
logpath  = /var/log/openwebmail.log


[horde]

port     = http,https
logpath  = /var/log/horde/horde.log


[groupoffice]

port     = http,https
logpath  = /home/groupoffice/log/info.log


[sogo-auth]
# Monitor SOGo groupware server
# without proxy this would be:
# port    = 20000
port     = http,https
logpath  = /var/log/sogo/sogo.log


[tine20]

logpath  = /var/log/tine20/tine20.log
port     = http,https


#
# Web Applications
#
#

[drupal-auth]

port     = http,https
logpath  = %(syslog_daemon)s
backend  = %(syslog_backend)s

[guacamole]

port     = http,https
logpath  = /var/log/tomcat*/catalina.out
#logpath  = /var/log/guacamole.log

[monit]
#Ban clients brute-forcing the monit gui login
port = 2812
logpath  = /var/log/monit
           /var/log/monit.log


[webmin-auth]

port    = 10000
logpath = %(syslog_authpriv)s
backend = %(syslog_backend)s


[froxlor-auth]

port    = http,https
logpath  = %(syslog_authpriv)s
backend  = %(syslog_backend)s


#
# HTTP Proxy servers
#
#

[squid]

port     =  80,443,3128,8080
logpath = /var/log/squid/access.log


[3proxy]

port    = 3128
logpath = /var/log/3proxy.log


#
# FTP servers
#


[proftpd]

port     = ftp,ftp-data,ftps,ftps-data
logpath  = %(proftpd_log)s
backend  = %(proftpd_backend)s


[pure-ftpd]

port     = ftp,ftp-data,ftps,ftps-data
logpath  = %(pureftpd_log)s
backend  = %(pureftpd_backend)s


[gssftpd]

port     = ftp,ftp-data,ftps,ftps-data
logpath  = %(syslog_daemon)s
backend  = %(syslog_backend)s


[wuftpd]

port     = ftp,ftp-data,ftps,ftps-data
logpath  = %(wuftpd_log)s
backend  = %(wuftpd_backend)s


[vsftpd]
# or overwrite it in jails.local to be
# logpath = %(syslog_authpriv)s
# if you want to rely on PAM failed login attempts
# vsftpd's failregex should match both of those formats
port     = ftp,ftp-data,ftps,ftps-data
logpath  = %(vsftpd_log)s


#
# Mail servers
#

# ASSP SMTP Proxy Jail
[assp]

port     = smtp,465,submission
logpath  = /root/path/to/assp/logs/maillog.txt


[courier-smtp]

port     = smtp,465,submission
logpath  = %(syslog_mail)s
backend  = %(syslog_backend)s


[postfix]
# To use another modes set filter parameter "mode" in jail.local:
mode    = more
port    = smtp,465,submission
logpath = %(postfix_log)s
backend = %(postfix_backend)s


[postfix-rbl]

filter   = postfix[mode=rbl]
port     = smtp,465,submission
logpath  = %(postfix_log)s
backend  = %(postfix_backend)s
maxretry = 1


[sendmail-auth]

port    = submission,465,smtp
logpath = %(syslog_mail)s
backend = %(syslog_backend)s


[sendmail-reject]
# To use more aggressive modes set filter parameter "mode" in jail.local:
# normal (default), extra or aggressive
# See "tests/files/logs/sendmail-reject" or "filter.d/sendmail-reject.conf" for usage example and details.
#mode    = normal
port     = smtp,465,submission
logpath  = %(syslog_mail)s
backend  = %(syslog_backend)s


[qmail-rbl]

filter  = qmail
port    = smtp,465,submission
logpath = /service/qmail/log/main/current


# dovecot defaults to logging to the mail syslog facility
# but can be set by syslog_facility in the dovecot configuration.
[dovecot]

port    = pop3,pop3s,imap,imaps,submission,465,sieve
logpath = %(dovecot_log)s
backend = %(dovecot_backend)s


[sieve]

port   = smtp,465,submission
logpath = %(dovecot_log)s
backend = %(dovecot_backend)s


[solid-pop3d]

port    = pop3,pop3s
logpath = %(solidpop3d_log)s


[exim]
# see filter.d/exim.conf for further modes supported from filter:
#mode = normal
port   = smtp,465,submission
logpath = %(exim_main_log)s


[exim-spam]

port   = smtp,465,submission
logpath = %(exim_main_log)s


[kerio]

port    = imap,smtp,imaps,465
logpath = /opt/kerio/mailserver/store/logs/security.log


#
# Mail servers authenticators: might be used for smtp,ftp,imap servers, so
# all relevant ports get banned
#

[courier-auth]

port     = smtp,465,submission,imap,imaps,pop3,pop3s
logpath  = %(syslog_mail)s
backend  = %(syslog_backend)s


[postfix-sasl]

filter   = postfix[mode=auth]
port     = smtp,465,submission,imap,imaps,pop3,pop3s
# You might consider monitoring /var/log/mail.warn instead if you are
# running postfix since it would provide the same log lines at the
# "warn" level but overall at the smaller filesize.
logpath  = %(postfix_log)s
backend  = %(postfix_backend)s


[perdition]

port   = imap,imaps,pop3,pop3s
logpath = %(syslog_mail)s
backend = %(syslog_backend)s


[squirrelmail]

port = smtp,465,submission,imap,imap2,imaps,pop3,pop3s,http,https,socks
logpath = /var/lib/squirrelmail/prefs/squirrelmail_access_log


[cyrus-imap]

port   = imap,imaps
logpath = %(syslog_mail)s
backend = %(syslog_backend)s


[uwimap-auth]

port   = imap,imaps
logpath = %(syslog_mail)s
backend = %(syslog_backend)s


#
#
# DNS servers
#


# !!! WARNING !!!
#   Since UDP is connection-less protocol, spoofing of IP and imitation
#   of illegal actions is way too simple.  Thus enabling of this filter
#   might provide an easy way for implementing a DoS against a chosen
#   victim. See
#    http://nion.modprobe.de/blog/archives/690-fail2ban-+-dns-fail.html
#   Please DO NOT USE this jail unless you know what you are doing.
#
# IMPORTANT: see filter.d/named-refused for instructions to enable logging
# This jail blocks UDP traffic for DNS requests.
# [named-refused-udp]
#
# filter   = named-refused
# port     = domain,953
# protocol = udp
# logpath  = /var/log/named/security.log

# IMPORTANT: see filter.d/named-refused for instructions to enable logging
# This jail blocks TCP traffic for DNS requests.

[named-refused]

port     = domain,953
logpath  = /var/log/named/security.log


[nsd]

port     = 53
action_  = %(default/action_)s[name=%(__name__)s-tcp, protocol="tcp"]
           %(default/action_)s[name=%(__name__)s-udp, protocol="udp"]
logpath = /var/log/nsd.log


#
# Miscellaneous
#

[asterisk]

port     = 5060,5061
action_  = %(default/action_)s[name=%(__name__)s-tcp, protocol="tcp"]
           %(default/action_)s[name=%(__name__)s-udp, protocol="udp"]
logpath  = /var/log/asterisk/messages
maxretry = 10


[freeswitch]

port     = 5060,5061
action_  = %(default/action_)s[name=%(__name__)s-tcp, protocol="tcp"]
           %(default/action_)s[name=%(__name__)s-udp, protocol="udp"]
logpath  = /var/log/freeswitch.log
maxretry = 10


# enable adminlog; it will log to a file inside znc's directory by default.
[znc-adminlog]

port     = 6667
logpath  = /var/lib/znc/moddata/adminlog/znc.log


# To log wrong MySQL access attempts add to /etc/my.cnf in [mysqld] or
# equivalent section:
# log-warnings = 2
#
# for syslog (daemon facility)
# [mysqld_safe]
# syslog
#
# for own logfile
# [mysqld]
# log-error=/var/log/mysqld.log
[mysqld-auth]

port     = 3306
logpath  = %(mysql_log)s
backend  = %(mysql_backend)s


# Log wrong MongoDB auth (for details see filter 'filter.d/mongodb-auth.conf')
[mongodb-auth]
# change port when running with "--shardsvr" or "--configsvr" runtime operation
port     = 27017
logpath  = /var/log/mongodb/mongodb.log


# Jail for more extended banning of persistent abusers
# !!! WARNINGS !!!
# 1. Make sure that your loglevel specified in fail2ban.conf/.local
#    is not at DEBUG level -- which might then cause fail2ban to fall into
#    an infinite loop constantly feeding itself with non-informative lines
# 2. Increase dbpurgeage defined in fail2ban.conf to e.g. 648000 (7.5 days)
#    to maintain entries for failed logins for sufficient amount of time
[recidive]

logpath  = /var/log/fail2ban.log
banaction = %(banaction_allports)s
bantime  = 1w
findtime = 1d


# Generic filter for PAM. Has to be used with action which bans all
# ports such as iptables-allports, shorewall

[pam-generic]
# pam-generic filter can be customized to monitor specific subset of 'tty's
banaction = %(banaction_allports)s
logpath  = %(syslog_authpriv)s
backend  = %(syslog_backend)s


[xinetd-fail]

banaction = iptables-multiport-log
logpath   = %(syslog_daemon)s
backend   = %(syslog_backend)s
maxretry  = 2


# stunnel - need to set port for this
[stunnel]

logpath = /var/log/stunnel4/stunnel.log


[ejabberd-auth]

port    = 5222
logpath = /var/log/ejabberd/ejabberd.log


[counter-strike]

logpath = /opt/cstrike/logs/L[0-9]*.log
tcpport = 27030,27031,27032,27033,27034,27035,27036,27037,27038,27039
udpport = 1200,27000,27001,27002,27003,27004,27005,27006,27007,27008,27009,27010,27011,27012,27013,27014,27015
action_  = %(default/action_)s[name=%(__name__)s-tcp, port="%(tcpport)s", protocol="tcp"]
           %(default/action_)s[name=%(__name__)s-udp, port="%(udpport)s", protocol="udp"]

[softethervpn]
port     = 500,4500
protocol = udp
logpath  = /usr/local/vpnserver/security_log/*/sec.log

[gitlab]
port    = http,https
logpath = /var/log/gitlab/gitlab-rails/application.log

[grafana]
port    = http,https
logpath = /var/log/grafana/grafana.log

[bitwarden]
port    = http,https
logpath = /home/*/bwdata/logs/identity/Identity/log.txt

[centreon]
port    = http,https
logpath = /var/log/centreon/login.log

# consider low maxretry and a long bantime
# nobody except your own Nagios server should ever probe nrpe
[nagios]

logpath  = %(syslog_daemon)s     ; nrpe.cfg may define a different log_facility
backend  = %(syslog_backend)s
maxretry = 1


[oracleims]
# see "oracleims" filter file for configuration requirement for Oracle IMS v6 and above
logpath = /opt/sun/comms/messaging64/log/mail.log_current
banaction = %(banaction_allports)s

[directadmin]
logpath = /var/log/directadmin/login.log
port = 2222

[portsentry]
logpath  = /var/lib/portsentry/portsentry.history
maxretry = 1

[pass2allow-ftp]
# this pass2allow example allows FTP traffic after successful HTTP authentication
port         = ftp,ftp-data,ftps,ftps-data
# knocking_url variable must be overridden to some secret value in jail.local
knocking_url = /knocking/
filter       = apache-pass[knocking_url="%(knocking_url)s"]
# access log of the website with HTTP auth
logpath      = %(apache_access_log)s
blocktype    = RETURN
returntype   = DROP
action       = %(action_)s[blocktype=%(blocktype)s, returntype=%(returntype)s,
                        actionstart_on_demand=false, actionrepair_on_unban=true]
bantime      = 1h
maxretry     = 1
findtime     = 1


[murmur]
# AKA mumble-server
port     = 64738
action_  = %(default/action_)s[name=%(__name__)s-tcp, protocol="tcp"]
           %(default/action_)s[name=%(__name__)s-udp, protocol="udp"]
logpath  = /var/log/mumble-server/mumble-server.log


[screensharingd]
# For Mac OS Screen Sharing Service (VNC)
logpath  = /var/log/system.log
logencoding = utf-8

[haproxy-http-auth]
# HAProxy by default doesn't log to file you'll need to set it up to forward
# logs to a syslog server which would then write them to disk.
# See "haproxy-http-auth" filter for a brief cautionary note when setting
# maxretry and findtime.
logpath  = /var/log/haproxy.log

[slapd]
port    = ldap,ldaps
logpath = /var/log/slapd.log

[domino-smtp]
port    = smtp,ssmtp
logpath = /home/domino01/data/IBM_TECHNICAL_SUPPORT/console.log

[phpmyadmin-syslog]
port    = http,https
logpath = %(syslog_authpriv)s
backend = %(syslog_backend)s


[zoneminder]
# Zoneminder HTTP/HTTPS web interface auth
# Logs auth failures to apache2 error log
port    = http,https
logpath = %(apache_error_log)s

[traefik-auth]
# to use 'traefik-auth' filter you have to configure your Traefik instance,
# see filter.d/traefik-auth.conf for details and service example.
port    = http,https
logpath = /var/log/traefik/access.log

[scanlogd]
logpath = %(syslog_local0)s
banaction = %(banaction_allports)s
fail2ban_ban


# Restart the fail2ban service.
sudo systemctl restart fail2ban
echo "Congratulations your setup is done"
echo "Admin email:  ${admin_email}  and  password: ${admin_password}"
echo "Database user:  ${db_user}  ,  password: ${db_password}  and name ${db_name}"
echo "Elasticsearch user name:  ${es_user}  and  password: ${es_password}"
echo "The Mastodon instance can be accessed on https://${domain_name}"
echo "Now SSH port is ${ssh_port}"