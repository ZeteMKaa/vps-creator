#!/bin/bash
#
#	Auto create script for VPS
# 
#

# Setting local variables
tput clear
ACTION="[\e[00;33m-\e[00m]"
QUESTION="[\e[00;31m+\e[00m]"
RED="\e[00;31m"
RESET="\e[00m"
echo -e "\n$ACTION Fixing some things to run the script ..."
apt update &> /dev/null
apt install pv -y &> /dev/null

# Changing default root password
echo -e "\n$QUESTION Did you already change the root password? [y/n] " | pv -qL 40
read response
response=${response,,}    # tolower
if [[ "$response" =~ ^(yes|y)$ ]]
then
	echo -e "\n$ACTION Ok moving on ..."| pv -qL 40
else
	passwd root
	echo -e "\n$ACTION Password for root user is changed"| pv -qL 40
fi

function _setbash {
	# Pimping root shell
	echo -e "\n$ACTION Tweaking bash"| pv -qL 40

	cat << EOF >> /root/.bashrc
	# Normal Colors
	# ANSI color codes
	RS="\[\033[0m\]"    # reset
	HC="\[\033[1m\]"    # hicolor
	UL="\[\033[4m\]"    # underline
	INV="\[\033[7m\]"   # inverse background and foreground
	FBLK="\[\033[30m\]" # foreground black
	FRED="\[\033[31m\]" # foreground red
	FGRN="\[\033[32m\]" # foreground green
	FYEL="\[\033[33m\]" # foreground yellow
	FBLE="\[\033[34m\]" # foreground blue
	FMAG="\[\033[35m\]" # foreground magenta
	FCYN="\[\033[36m\]" # foreground cyan
	FWHT="\[\033[37m\]" # foreground white
	BBLK="\[\033[40m\]" # background black
	BRED="\[\033[41m\]" # background red
	BGRN="\[\033[42m\]" # background green
	BYEL="\[\033[43m\]" # background yellow
	BBLE="\[\033[44m\]" # background blue
	BMAG="\[\033[45m\]" # background magenta
	BCYN="\[\033[46m\]" # background cyan
	BWHT="\[\033[47m\]" # background white
EOF

	echo -e	'export PS1="${FRED}[${FWHT}\t${FRED}]-[${FWHT}\u@\h${FRED}]-[${FWHT}\w${FRED}]${RS}\\$ "' >> /root/.bashrc
	
	#echo -e 'export PS1="\033[1m\\t\033[0m-\033[1m[\[\e[38;5;31m\]\u\[\e[m\]\033[1m]@\033[1m[\[\e[38;5;31m\]\h\[\e[m\]\033[1m]-\033[1m\w\033[0m# "' >> /root/.bashrc
	echo -e 'export EDITOR=/usr/bin/vim' >> /root/.bashrc
	echo -e "alias ll='ls -lah'" >> /root/.bashrc
	echo -e '
	 extract () {
		if [ -f $1 ] ; then
		  case $1 in
			*.tar.bz2)   tar xjf $1     ;;
			*.tar.gz)    tar xzf $1     ;;
			*.bz2)       bunzip2 $1     ;;
			*.rar)       unrar e $1     ;;
			*.gz)        gunzip $1      ;;
			*.tar)       tar xf $1      ;;
			*.tbz2)      tar xjf $1     ;;
			*.tgz)       tar xzf $1     ;;
			*.zip)       unzip $1       ;;
			*.Z)         uncompress $1  ;;
			*.7z)        7z x $1        ;;
			*)     echo "'$1' cannot be extracted via extract()" ;;
			 esac
		 else
			 echo "'$1' is not a valid file"
		 fi
	}

	machine()
	{
		echo -e "\nMachine information:" ; uname -a
		echo -e "\nUsers logged on:" ; w -h
		echo -e "\nCurrent date :" ; date
		echo -e "\nMachine status :" ; uptime
		echo -e "\nMemory status :" ; free -h
		echo -e "\nFilesystem status :"; df -h
	}
	' >> /root/.bashrc
}

function _setvim {
	# Setting vim tweaks
	echo -e "\n$ACTION Tweaking vim"| pv -qL 40

	echo -e "syntax on" > /root/.vimrc
	echo -e "colorscheme desert" >> /root/.vimrc
	echo -e "set mouse-=a" >> /root/.vimrc
}

# Setting some additonal settings
function _settz {
# Configure correct timezone
echo -e "\n$ACTION Setting correct timezone"| pv -qL 40
timedatectl set-timezone Europe/Amsterdam
}

function _sethostname {
	# Setting hostname 
	echo -e "\n$ACTION Setting hostname"| pv -qL 40
	EXT_IP=`dig +short myip.opendns.com @resolver1.opendns.com`
	echo -e "\n$QUESTION What is the hostname of this machine?"| pv -qL 40
	read NAME
	echo -e "\n$QUESTION What is the DNS of this machine?"| pv -qL 40
	read DNS
	echo -e "$NAME.$DNS" > /etc/hostname
	echo -e "127.0.0.1\tlocalhost\r\n$EXT_IP\t$NAME.$DNS\t$NAME" >> /etc/hosts
	HOST_DOMAIN=$NAME.$DNS
}

function _setufw {
	# Setting UFW
	echo -e "\n$ACTION Creating default UFW config"| pv -qL 40
	ufw default deny incoming &> /dev/null
	ufw default allow outgoing &> /dev/null
	ufw allow 80/tcp &> /dev/null
	ufw allow 443/tcp &> /dev/null
	ufw allow 'OpenSSH' &> /dev/null
	ufw enable
	echo -e "\n$ACTION Firewall is active"| pv -qL 40
}

function _installlemp {
# Installing LEMP stack with PHP7
	echo -e "\n$ACTION Updating repo and installing LEMP instance ..."| pv -qL 40
	apt update &> /dev/null 
	apt install nginx php7.0-cli php7.0-curl php7.0-dev php7.0-zip php7.0-fpm php7.0-gd php7.0-xml php7.0-xmlrpc php7.0-mysql php7.0-mcrypt php7.0-mbstring php7.0-opcache mariadb-server mariadb-client -y &> /dev/null
}

function _installpackages {
	# Installing additonal tools
	echo -e "\n$ACTION Installing additonal tooling ..."| pv -qL 40
	apt install locate curl fail2ban build-essential dnsutils letsencrypt htop git -y &> /dev/null
}

function _installupgrade {
	# Updating the system
	echo -e "\n$ACTION Updating the system ..."| pv -qL 40
	apt upgrade -y &> /dev/null
}

function _createuser {
	# Creating new user and adding to groups
	echo -e "\n$QUESTION What name should I give your new user?"| pv -qL 40
	read NEW_USERNAME
	useradd -m -G adm,sudo,www-data -s /bin/bash -u 1337 $NEW_USERNAME
	echo -e "\n$ACTION User $NEW_USERNAME created"| pv -qL 40
	passwd $NEW_USERNAME
	echo -e "\n$ACTION Also applying the pimping to the new user"| pv -qL 40
	cp ~/.bashrc /home/$NEW_USERNAME/.bashrc
	cp ~/.vimrc /home/$NEW_USERNAME/.vimrc
	chown $NEW_USERNAME:$NEW_USERNAME /home/$NEW_USERNAME/.bashrc
	chown $NEW_USERNAME:$NEW_USERNAME /home/$NEW_USERNAME/.vimrc
	userdel ubuntu
}

function _securessh {
	# Securing SSH
	echo -e "\n$ACTION Securing SSH"| pv -qL 40

	sed -i "/Port 22/c\Port 13322" /etc/ssh/sshd_config
	echo -e "\n$ACTION Changed the SSH port to 13322"| pv -qL 40
	echo -e "\n$ACTION Changing UFW to allow SSH to port 13322"| pv -qL 40
	ufw allow 13322/tcp &> /dev/null
	ufw delete 'OpenSSH' &> /dev/null
	ufw reload &> /dev/null

	sed -i "/PermitRootLogin yes/c\PermitRootLogin no" /etc/ssh/sshd_config
	echo -e "\n$ACTION Preventing the root user from using SSH"| pv -qL 40

	echo -e "\n$ACTION Reloading SSH"| pv -qL 40
	service ssh restart &> /dev/null
}

function _setfail2ban {
# Setting up fail2ban
	echo -e "\n$ACTION Setting up fail2ban"| pv -qL 40
	echo -e "\n$QUESTION Where do you want me to deliver the alert emails?"| pv -qL 40
	read EMAIL
	sed -i '/action   = iptables\[name=SSH, port=ssh, protocol=tcp\]/c\action   = iptables\[name=SSH, port=13322, protocol=tcp\]' /etc/fail2ban/jail.conf
	sed -i '/bantime  = 600/c\bantime = -1' /etc/fail2ban/jail.conf
	sed -i "/destemail = root@localhost/c\destemail = $EMAIL" /etc/fail2ban/jail.conf
	sed -i '/action = %(action_)s/c\action = %(action_mwl)s' /etc/fail2ban/jail.conf
	service fail2ban restart
}

function _setnginx {
	# Tweaking Nginx
	echo -e "\n$QUESTION Will your domain be $(cat /etc/hostname)?"| pv -qL 40
	read response
	response=${response,,}    # tolower
	if [[ "$response" =~ ^(yes|y)$ ]]
		then
			echo -e "\n$ACTION Ok moving on ..."| pv -qL 40
			HOST_DOMAIN=`cat /etc/hostname`
		else
			echo -e "\n$QUESTION What is your domain?"| pv -qL 40
			read HOST_DOMAIN
	fi

	# Creating web dir
	echo -e "\n$ACTION Creating web root"| pv -qL 40
	mkdir -p /var/www/$HOST_DOMAIN/.well-known/acme-challenge
		
	# Creating test file
	echo -e "\n$ACTION Creating test file as index.php in the webroot"| pv -qL 40
	echo -e "<?php phpinfo() ?>" > /var/www/${HOST_DOMAIN}/index.php
	chown -R $NEW_USERNAME:www-data /var/www/$HOST_DOMAIN

	# Letsencrypt config
	echo -e "\n$ACTION Downloading acme.sh for Letsencrypt ..."| pv -qL 40
	git clone https://github.com/Neilpang/acme.sh.git /opt/acme.sh &> /dev/null

	echo -e "\n$ACTION Installing acme.sh ..."| pv -qL 40
	bash /opt/acme.sh/acme.sh --install &> /dev/null

	echo -e "\n$ACTION Generating certificates ..."| pv -qL 40
	service nginx stop
	bash /opt/acme.sh/acme.sh --issue --standalone -d ${HOST_DOMAIN} --keylength ec-256 &> /dev/null

	# Installing Nginx configuration with SSL
	cat << EOF > /etc/nginx/sites-available/default

server{
	listen 80;
	return 301 https://\$server_name\$request_uri;
	#server_name ${HOST_DOMAIN};
	#root /var/www/${HOST_DOMAIN};
	#index index.php index.html;
	}

server{
	listen 443 ssl http2;
	server_name ${HOST_DOMAIN};
	root /var/www/${HOST_DOMAIN};
	index index.php index.html;#

	# SSL config
	ssl_protocols TLSv1.2;
	ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256';
	ssl_prefer_server_ciphers On;
	ssl_ecdh_curve secp384r1;
	ssl_certificate /root/.acme.sh/${HOST_DOMAIN}_ecc/fullchain.cer;
	ssl_certificate_key /root/.acme.sh/${HOST_DOMAIN}_ecc/${HOST_DOMAIN}.key;
	ssl_session_cache shared:SSL:128m;
	ssl_stapling on;
	ssl_stapling_verify on;#

	# Headers
	add_header Strict-Transport-Security "max-age=31557600; includeSubDomains";
	add_header X-Frame-Options DENY;
	add_header X-Content-Type-Options nosniff;
	add_header Referrer-Policy "no-referrer";
	add_header X-XSS-Protection "1; mode=block";
	add_header Access-Control-Allow-Origin null;#
	resolver 8.8.8.8 8.8.4.4 valid=300s;
	resolver_timeout 5s;#

	# Location config
	location ~ \.php$ {
		include snippets/fastcgi-php.conf;
		fastcgi_pass unix:/run/php/php7.0-fpm.sock;
	}#
	location ~ /\.ht {
		deny all;
	}#
	location '/.well-known/acme-challenge' {
		alias /var/www/${HOST_DOMAIN}/.well-known/acme-challenge;
	}
	location = / {try_files $uri $uri/ /index.php$is_args$args;}
	location = /favicon.ico { log_not_found off; access_log off; }
	location = /robots.txt { log_not_found off; access_log off; allow all; }
	location ~* \.(css|gif|ico|jpeg|jpg|js|png)$ {
		expires max;
		log_not_found off;
	}
}

EOF


	# starting nginx

	#sed -i '/	    return 301 https://;/c\	    return 301 https://${server_name}${request_uri};' /etc/nginx/sites-available/default
	sed -i '/        # server_tokens off;/c\        server_tokens off;' /etc/nginx/nginx.conf
	service nginx start
}

function _securemysql {
	# Securing MySQL/MariaDB
	echo -e "\n$ACTION Creating a secure password"| pv -qL 40
	SECPASS=`</dev/urandom tr -dc '!@#$%_A-Z-a-z-0-9' | head -c16; echo ""`
	echo $SECPASS
	echo -e "\n$ACTION Please copy the password if you need one"| pv -qL 40
	sleep 5
	echo -e "\n$ACTION Performing MySQL hardening"| pv -qL 40
	mysql --user=root <<_EOF_
UPDATE mysql.user SET Password=PASSWORD('${SECPASS}') WHERE User='root';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
_EOF_
}

function _setsecure {
	# Securing PHP
	echo -e "\n$ACTION Performing PHP hardening"| pv -qL 40
	sed -i '/;cgi.fix_pathinfo=1/c\cgi.fix_pathinfo=0' /etc/php/7.0/fpm/php.ini
	systemctl restart php7.0-fpm
}

function _installwp {
	# Install Wordpress
	echo -e "\n$ACTION Starting to install Wordpress"| pv -qL 40

	# Fixing database
	echo -e "\n$ACTION Prepping database"| pv -qL 40
	SECPASS2=`</dev/urandom tr -dc '!@#$%_A-Z-a-z-0-9' | head -c16; echo ""`
	echo $SECPASS2
	echo -e "\n$QUESTION Name of new database?"| pv -qL 40
	read DB_NAME
	echo -e "\n$QUESTION Name of DB user?"| pv -qL 40
	read DB_USER
mysql --user=root -p <<_EOF_
  CREATE DATABASE ${DB_NAME} DEFAULT CHARACTER SET utf8 COLLATE utf8_unicode_ci;
  GRANT ALL ON ${DB_NAME}.* TO '${DB_USER}'@'localhost' IDENTIFIED BY '${SECPASS2}';
  FLUSH PRIVILEGES;
_EOF_

	echo -e "
	# MySQL root
	User = root
	Pass = ${SECPASS}

	# MySQL Wordpress
	User = ${DB_USER}
	Pass = ${SECPASS2}
	DB = ${DB_NAME}

	" > /root/mysql_details


	# Downloading and installing Wordpress
	echo -e "\n$ACTION Downloading and installing Wordpress"| pv -qL 40
	cd /tmp
	curl -O https://wordpress.org/latest.tar.gz &> /dev/null
	tar xzvf latest.tar.gz &> /dev/null
	cp /tmp/wordpress/wp-config-sample.php /tmp/wordpress/wp-config.php
	mkdir /tmp/wordpress/wp-content/upgrade
	cp -a /tmp/wordpress/. /var/www/$HOST_DOMAIN
	chown -R $NEW_USERNAME:www-data /var/www/$HOST_DOMAIN
	find /var/www/$HOST_DOMAIN -type d -exec chmod g+s {} \; &> /dev/null
	chmod g+w /var/www/$HOST_DOMAIN/wp-content
	chmod -R g+w /var/www/$HOST_DOMAIN/wp-content/themes
	chmod -R g+w /var/www/$HOST_DOMAIN/wp-content/plugins

	# Configuring Wordpress
	SALT=`curl -s https://api.wordpress.org/secret-key/1.1/salt/`

	cat << EOF > /var/www/$HOST_DOMAIN/wp-config.php

<?php
define('DB_NAME', '${DB_NAME}');
define('DB_USER', '${DB_USER}');
define('DB_PASSWORD', '${SECPASS2}');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8');
define('DB_COLLATE', '');
${SALT}
$table_prefix  = 'wp_';
define('WP_DEBUG', false);
if ( !defined('ABSPATH') )
        define('ABSPATH', dirname(__FILE__) . '/');
require_once(ABSPATH . 'wp-settings.php');
define('FS_METHOD', 'direct');

EOF
}

_setbash
_setvim
_settz
_sethostname
_setufw
_installlemp
_installpackages
_installupgrade
_createuser
_securessh
_setfail2ban
_setnginx
_securemysql
_setsecure
_installwp
