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

# Pimping root shell
echo -e "\n$ACTION Tweaking bash"| pv -qL 40

echo -e 'export PS1="\033[1m\t\033[0m-\033[1m[\[\e[38;5;31m\]\u\[\e[m\]\033[1m]@\033[1m[\[\e[38;5;31m\]\h\[\e[m\]\033[1m]-\033[1m\w\033[0m#"' >> /root/.bashrc
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


# Setting vim tweaks
echo -e "\n$ACTION Tweaking vim"| pv -qL 40

echo -e ":syntax on" > /root/.vimrc
echo -e ":color desert" >> /root/.vimrc

# Setting some additonal settings

# Configure correct timezone
echo -e "\n$ACTION Setting correct timezone"| pv -qL 40
timedatectl set-timezone Europe/Amsterdam

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

# Setting UFW
echo -e "\n$ACTION Creating default UFW config"| pv -qL 40
ufw default deny incoming &> /dev/null
ufw default allow outgoing &> /dev/null
ufw allow 80/tcp &> /dev/null
ufw allow 443/tcp &> /dev/null
ufw allow 'OpenSSH' &> /dev/null
ufw enable
echo -e "\n$ACTION Firewall is active"| pv -qL 40

# Installing LEMP stack with PHP7
echo -e "\n$ACTION Updating repo and installing LEMP instance ..."| pv -qL 40
apt update &> /dev/null 
apt install nginx php7.0-cli php7.0-curl php7.0-dev php7.0-zip php7.0-fpm php7.0-gd php7.0-xml php7.0-mysql php7.0-mcrypt php7.0-mbstring php7.0-opcache mariadb-server mariadb-client -y &> /dev/null

# Installing additonal tools
echo -e "\n$ACTION Installing additonal tooling ..."| pv -qL 40
apt install locate curl fail2ban build-essential dnsutils letsencrypt htop expect git -y &> /dev/null

# Updating the system
echo -e "\n$ACTION Updating the system ..."| pv -qL 40
apt upgrade -y &> /dev/null

# Old setup for Apache
#apt install mariadb-server mariadb-client apache2 locate curl fail2ban build-essential dnsutils php7.0-mysql php7.0-curl php7.0-gd php7.0-intl php-pear php-imagick php7.0-imap php7.0-mcrypt php-memcache  php7.0-pspell php7.0-recode php7.0-sqlite3 php7.0-tidy php7.0-xmlrpc php7.0-xsl php7.0-mbstring php-gettext php-apcu python-letsencrypt-apache

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

# Setting up fail2ban
echo -e "\n$ACTION Setting up fail2ban"| pv -qL 40
echo -e "\n$QUESTION Where do you want me to deliver the alert emails?"| pv -qL 40
read EMAIL
sed -i '/action   = iptables\[name=SSH, port=ssh, protocol=tcp\]/c\action   = iptables\[name=SSH, port=13322, protocol=tcp\]' /etc/fail2ban/jail.conf
sed -i '/bantime  = 600/c\bantime = -1' /etc/fail2ban/jail.conf
sed -i "/destemail = root@localhost/c\destemail = $email" /etc/fail2ban/jail.conf
sed -i '/action = %(action_)s/c\action = %(action_mwl)s' /etc/fail2ban/jail.conf
service fail2ban restart

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
	mkdir /var/www/$HOST_DOMAIN 
	mkdir /var/www/$HOST_DOMAIN/.well-known
	mkdir /var/www/$HOST_DOMAIN/.well-known/acme-challenge
    # Creating test file
    echo -e "\n$ACTION Creating test file as index.php in the webroot"| pv -qL 20
    echo -e "
    <?php
            phpinfo()
    ?>" > /var/www/${HOST_DOMAIN}/index.php
	chown -R $NEW_USERNAME:www-data /var/www/$HOST_DOMAIN

	# Letsencrypt config
	echo -e "\n$ACTION Downloading certbot for Letsencrypt ..."| pv -qL 40
	git clone https://github.com/certbot/certbot /opt/letsencrypt &> /dev/null

	echo -e "\n$ACTION Creating certificate configuration file"| pv -qL 40
	mkdir /etc/letsencrypt
	mkdir /etc/letsencrypt/configs/
	cat << EOF > /etc/letsencrypt/configs/$HOST_DOMAIN.conf
	domains = ${HOST_DOMAIN}
	rsa-key-size = 2048
	email = ${EMAIL}
	authenticator = webroot
	webroot-path = /var/www/${HOST_DOMAIN}/
EOF
	echo -e "\n$ACTION Generating certificates ..."| pv -qL 40
	/opt/letsencrypt/letsencrypt-auto certonly --agree-tos -c /etc/letsencrypt/configs/${HOST_DOMAIN}.conf 

	# Creating crontab
	echo -e "\n$ACTION Creating cronjob for certificate renew"| pv -qL 40
	mkdir /var/log/letsencrypt
	cat << EOF > /etc/cron.d/cert-renew
	/opt/letsencrypt/certbot-auto --config /etc/letsencrypt/configs/${HOST_DOMAIN}.conf certonly

	if [ $? -ne 0 ]
	 then
	        ERRORLOG=`tail /var/log/letsencrypt/letsencrypt.log`
	        echo -e "The Let's Encrypt cert has not been renewed! \n \n" \
	                 $ERRORLOG
	 else
	        service nginx force-reload
	fi
	exit 0
EOF
	(crontab -l 2>/dev/null; echo "0 0 1 JAN,MAR,MAY,JUL,SEP,NOV * /etc/cron.d/cert-renew") | crontab -


	# Replacing default Nginx config 
	mv /etc/nginx/sites-available/default /etc/nginx/sites-available/default.old
	cat << EOF > /etc/nginx/sites-available/default

	server{
	    listen 80;
	    #	return 301;
	    server_name ${HOST_DOMAIN};
	    root /var/www/${HOST_DOMAIN};
	    index index.php index.html;
	    }

#	server{
#	    listen 443 ssl http2;
#	    server_name ${HOST_DOMAIN};
#	    root /var/www/${HOST_DOMAIN};
#	    index index.php index.html;#

#	    # SSL config
#	    ssl_protocols TLSv1.2;
#	    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256';
#	    ssl_prefer_server_ciphers On;
#	    ssl_ecdh_curve secp384r1;
#	    #ssl_certificate /etc/letsencrypt/live/${HOST_DOMAIN}/fullchain.pem;
#	    #ssl_certificate_key /etc/letsencrypt/live/${HOST_DOMAIN}/privkey.pem;
#	    #ssl_trusted_certificate /etc/letsencrypt/live/${HOST_DOMAIN}/chain.pem;
#	    ssl_session_cache shared:SSL:128m;
#	    ssl_stapling on;
#	    ssl_stapling_verify on;#

#	    # Headers
#	    add_header Strict-Transport-Security "max-age=31557600; includeSubDomains";
#	    add_header X-Frame-Options DENY;
#	    add_header X-Content-Type-Options nosniff;
#	    add_header Referrer-Policy "no-referrer";
#	    add_header X-XSS-Protection "1; mode=block";
#	    add_header Access-Control-Allow-Origin null;#

#	    # Your favorite resolver may be used instead of the Google one below
#	    resolver 8.8.8.8 8.8.4.4 valid=300s;
#	    resolver_timeout 5s;#

#	    # Location config
#	    location ~ \.php$ {
#	        include snippets/fastcgi-php.conf;
#	        fastcgi_pass unix:/run/php/php7.0-fpm.sock;
#	    }#

#	    location ~ /\.ht {
#	        deny all;
#	    }#

#	    location '/.well-known/acme-challenge' {
#	        alias /var/www/${HOST_DOMAIN}/.well-known/acme-challenge;
#	    }
#	}

EOF


	service nginx restart

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

# Securing PHP
echo -e "\n$ACTION Performing PHP hardening"| pv -qL 40
sed -i '/;cgi.fix_pathinfo=1/c\cgi.fix_pathinfo=0' /etc/php/7.0/fpm/php.ini
systemctl restart php7.0-fpm

# Restoring SSL connection on Nginx

	cat << EOF > /etc/nginx/sites-available/default

	server{
	    listen 80;
	    	return 301;
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
	    ssl_certificate /etc/letsencrypt/live/${HOST_DOMAIN}/fullchain.pem;
	    ssl_certificate_key /etc/letsencrypt/live/${HOST_DOMAIN}/privkey.pem;
	    ssl_trusted_certificate /etc/letsencrypt/live/${HOST_DOMAIN}/chain.pem;
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
	    # Your favorite resolver may be used instead of the Google one below
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
	}

EOF


