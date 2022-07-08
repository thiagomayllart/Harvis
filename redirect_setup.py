import io
import sys
import time
import namecheap_handler
import apivoid_handler
import config
import paramiko
import os
import requests
import json
import logging
import backup_handle

redirectors_config = {}

#edit config at will
config_redirect_apache = """

SSLEngine On
SLLProxyEngine On
ProxyRequest Off

SSLProxyCheckPeerCN off
SSLProxyCheckPeerName off

ProxyPass /en-us/index.html https:://{1}/en-us/index.html
ProxyPassReverse /en-us/index.html https:://{1}/en-us/index.html
ProxyPass /en-us/docs.html https:://{1}/en-us/docs.html
ProxyPassReverse /en-us/docs.html https:://{1}/en-us/docs.html
ProxyPass /en-us/test.html https:://{1}/en-us/test.html
ProxyPassReverse /en-us/test.html https:://{1}/en-us/test.html

ProxyPass / https://{2}/
ProxyPassReverse https://{2}/
"""

def sftp_exists(sftp, path):
    try:
        sftp.stat(path)
        return True
    except FileNotFoundError:
        return False


def setup_redirector(type, domain, c2):
    global redirectors_config
    config_VirtualHost = config.config_VirtualHost
    config_default_ssl_conf_new = config.config_default_ssl_conf.replace("{1}", domain)
    config_htaccess_dic_new = config.config_htaccess_dic[type].replace("{1}", config.agent_profiles[type]["URI"])
    config_htaccess_dic_new = config_htaccess_dic_new.replace("{2}",c2["ip"])
    config_htaccess_dic_new = config_htaccess_dic_new.replace("{3}",config.domain_front_redirector[type])
    redirectors_config[type] = {"config_default_ssl_conf":config_default_ssl_conf_new,"config_htaccess_dic":config_htaccess_dic_new,"config_VirtualHost":config_VirtualHost}

def run_comm(ssh,cmd):
    time.sleep(5)
    outdata = ""
    errdata = ""
    worked = False
    while worked == False:
        chan = ssh.get_transport().open_session()
        chan.exec_command(cmd)
        chan.set_combine_stderr(True)

        contents = io.StringIO()
        error = io.StringIO()
        exit_status = 0

        while not chan.exit_status_ready():
            if chan.recv_ready():
                data = chan.recv(1024)
                exit_status = chan.recv_exit_status()
                while data:
                    contents.write(data.decode())
                    data = chan.recv(1024)
                    exit_status = chan.recv_exit_status()

        outdata = contents.getvalue()
        errdata = error.getvalue()
        if exit_status == 0:
            worked = True
        else:
            check_critical(outdata)
            time.sleep(5)
    logging.info(outdata)
    logging.info(errdata)
    return (outdata, errdata)

def check_critical(outdata):
    if "Too many certificates" in outdata:
        print("[+] Domain can't be used:")
        print("Error: ")
        print(outdata)
        backup_handle.delete_backup()
        print("[+] Choose another domain and run Harvis again")
        sys.exit()


def install_redir(ssh):
    print("Installing requirements")
    #run_comm(ssh,"apt-get update && apt-get install apache2 -y && a2enmod ssl rewrite proxy proxy_http && a2ensite "
    #             "default-ssl.conf && a2enmod proxy_connect && service apache2 stop && service apache2 start && sudo "
    #             "apt-get update -y && sudo apt-get install software-properties-common && sudo add-apt-repository "
    #             "universe && sudo apt-get update -y && apt-get install certbot python3-certbot-apache -y")
    run_comm(ssh,"apt-get update -y")
    run_comm(ssh,"apt-get install apache2 -y")
    run_comm(ssh,"a2enmod ssl rewrite proxy proxy_http")
    run_comm(ssh,"a2ensite default-ssl.conf")
    run_comm(ssh,"a2enmod proxy_connect")
    run_comm(ssh,"service apache2 stop")
    run_comm(ssh,"service apache2 start")
    run_comm(ssh,"sudo apt-get update -y")
    run_comm(ssh,"sudo apt-get install software-properties-common")
    run_comm(ssh,"sudo add-apt-repository universe")
    run_comm(ssh,"sudo apt-get update -y")
    run_comm(ssh,"apt-get install certbot python3-certbot-apache -y")
    print("Requirements Installed")

def check_propagation(redirects, type, domain):
    worked = False
    propagated = False
    while worked == False:
        try:
            propagated = apivoid_handler.check_propagation(domain, redirects[type]["ip"])
            worked = True
        except:
            time.sleep(5)
            pass
    return propagated

def full_setup(ssh,c2, redirects, type, domain, pkey, ip,subdomain):
    print("Certificates set")
    print("Finishing redirector setup")
    sftp = ssh.open_sftp()
    f = sftp.open("ssl_config.sh", "wb")
    f.write("(echo \"A\"; echo \"Y\"; echo \"3\"; echo \"2\";) | certbot -d " +subdomain+"."+ domain +","+domain+" --apache --register-unsafely-without-email")
    f.close()

    run_comm(ssh,"chmod +x ssl_config.sh")
    outdata, errdata = run_comm(ssh,"sh ssl_config.sh")
    #depending on the type you can set different redirector rules to each one
    setup_redirector(type, domain, c2)

    try:
        f_read = sftp.open("/etc/apache2/sites-enabled/default-ssl.conf", "r")
        file_lines = f_read.readlines()
        filedata = f_read.read().decode("utf-8")
        f_read.close()
        line1 =""
        line2 =""
        for i in file_lines:
            if "SSLCertificateFile" in i and "/etc" in i:
                line1 = i
            if "SSLCertificateKeyFile" in i and "/etc" in i:
                line2 = i

        filedata = "".join(file_lines)
        if sftp_exists(sftp,"/etc/letsencrypt/live/"+domain):
            newfile = filedata.replace(line1+line2,redirectors_config[type]["config_default_ssl_conf"])
        else:
            newfile = filedata.replace(line1 + line2, redirectors_config[type]["config_default_ssl_conf"].replace(domain,subdomain+"."+domain))


        f = sftp.open("/etc/apache2/sites-enabled/default-ssl.conf", "wb")
        f.write(newfile.encode(encoding='UTF-8'))
        f.close()
    except:
        pass #000 file exists already


    try:
        f_read = sftp.open("/etc/apache2/sites-enabled/000-default-le-ssl.conf", "r")
        file_lines = f_read.readlines()
        f_read.close()
        line1 = ""
        for i in file_lines:
            if ":443>" in i:
                line1 = i
                break

        filedata = "".join(file_lines)
        newfile = filedata.replace(line1, line1 + "\n" +redirectors_config[type]["config_VirtualHost"])

        f = sftp.open("/etc/apache2/sites-enabled/000-default-le-ssl.conf", "wb")
        f.write(newfile.encode(encoding='UTF-8'))
        f.close()
    except:
        pass  # 000 file exists already

    f = sftp.open("/var/www/html/.htaccess", "wb")
    f.write(redirectors_config[type]["config_htaccess_dic"].encode(encoding='UTF-8'))
    f.close()


    f_read = sftp.open("/etc/apache2/apache2.conf", "r")
    file_lines = f_read.readlines()
    filedata = f_read.read().decode("utf-8")
    f_read.close()
    line1 = ""
    line2 = ""
    original = "<Directory /var/www/>\n\tOptions Indexes FollowSymLinks\n\tAllowOverride None\n\tRequire all granted\n</Directory>"
    replacement = "<Directory /var/www/>\n\tOptions Indexes FollowSymLinks\n\tAllowOverride All\n\tRequire all granted\n</Directory>"


    filedata = "".join(file_lines)
    newfile = filedata.replace(original, replacement)

    f = sftp.open("/etc/apache2/apache2.conf", "wb")
    f.write(newfile.encode(encoding='UTF-8'))
    f.close()

    sftp.close()
    run_comm(ssh,"service apache2 restart")
    return firewall_rules(c2["ip"],redirects[type]["id"],redirects[type]["domain"])


def firewall_rules(c2_ip,redirect_id,domain):
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + config.digital_ocean_token,
    }
    data = {"name": "redirector"+domain.replace(".",""), "inbound_rules": [
        {
            "protocol": "tcp",
            "ports": "443",
            "sources": {
                "addresses": [
                    "0.0.0.0/0"
                ]
            }
        },
        {
            "protocol": "tcp",
            "ports": "22",
            "sources": {
                "addresses": [
                    c2_ip
                ]
            }
        }
    ]
        , "droplet_ids": [
            redirect_id
        ]
            }
    response = requests.post('https://api.digitalocean.com/v2/firewalls', headers=headers, json=data)
    id = firewall_id(response)
    return id

def setDNSInfo(domain,ip,subdomain):
    namecheap_handler.set_redirect_records(domain,ip,subdomain)

def firewall_id(response):
    dict = json.loads(response.content)
    id = dict["firewall"]["id"]
    return id
