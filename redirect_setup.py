import time
import namecheap_handler
import apivoid_handler
import config
import paramiko
import os

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


def setup_redirector(type, domain, c2_list):
    global redirectors_config
    config_VirtualHost = config.config_VirtualHost
    config_default_ssl_conf_new = config.config_default_ssl_conf.replace("{1}", domain)
    config_htaccess_dic_new = config.config_htaccess_dic[type].replace("{1}", config.agent_profiles[type]["URI"])
    config_htaccess_dic_new = config_htaccess_dic_new.replace("{2}",c2_list[type]["ip"])
    config_htaccess_dic_new = config_htaccess_dic_new.replace("{3}",config.domain_front_redirector[type])
    redirectors_config[type] = {"config_default_ssl_conf":config_default_ssl_conf_new,"config_htaccess_dic":config_htaccess_dic_new,"config_VirtualHost":config_VirtualHost}

def install_redir(ssh):
    print("Installing requirements")
    (stdin, stdout, stderr) = ssh.exec_command("apt-get update -y && apt-get upgrade -y",get_pty=True)
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("apt-get install apache2 -y",get_pty=True)
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("a2enmod ssl rewrite proxy proxy_http",get_pty=True)
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("a2ensite default-ssl.conf",get_pty=True)
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("a2enmod proxy_connect",get_pty=True)
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("service apache2 stop",get_pty=True)
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("service apache2 start",get_pty=True)
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("sudo apt-get update -y",get_pty=True)
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("sudo apt-get install software-properties-common",get_pty=True)
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("sudo add-apt-repository universe",get_pty=True)
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("sudo add-apt-repository ppa:certbot/certbot -y",get_pty=True)
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("sudo apt-get update -y", get_pty=True)
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("apt-get install certbot python3-certbot-apache -y",get_pty=True)
    ssh_stdout = stdout.read()
    print("Requirements Installed")

def check_propagation(ssh,c2_list, redirects, type, domain, pkey, ip):
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

def full_setup(ssh,c2_list, redirects, type, domain, pkey, ip,subdomain):
    print("Setting SSL certificates... this might take a while...")
    sftp = ssh.open_sftp()
    f = sftp.open("ssl_config.sh", "wb")
    f.write("(echo \"A\"; echo \"Y\"; echo \"3\"; echo \"2\";) | certbot -d " +subdomain+"."+ domain +","+domain+" --apache --register-unsafely-without-email")
    f.close()

    print("Waiting DNS propagations! We will check every hour")
    (stdin, stdout, stderr) = ssh.exec_command("chmod +x ssl_config.sh",get_pty=True)
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("sh ssl_config.sh", get_pty=True)
    ssh_stdout = stdout.read().decode("utf-8")
    while "failed" in ssh_stdout:
        (stdin, stdout, stderr) = ssh.exec_command("sh ssl_config.sh",get_pty=True)
        ssh_stdout = stdout.read()
        time.sleep(900)
    #if something: break
    #else: sleep


    #depending on the type you can set different redirector rules to each one
    setup_redirector(type, domain, c2_list)

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

    if not os.path.exists(os.getcwd()+"/certificates/"):
        os.mkdir(os.getcwd()+"/certificates/")
    if not os.path.exists(os.getcwd() + "/certificates/redirectors/"):
        os.mkdir(os.getcwd()+"/certificates/redirectors/")
    if not os.path.exists(os.getcwd() + "/certificates/redirectors/"+str(type)):
        os.mkdir(os.getcwd()+"/certificates/redirectors/"+str(type))

    check_cert = False
    try:
        localpath = os.getcwd()+"/certificates/redirectors/"+str(type)+"/cert.pem"
        remotepath = "/etc/letsencrypt/live/"+subdomain+"."+domain+"/cert.pem"
        sftp.get(remotepath, localpath)
        localpath = os.getcwd()+"/certificates/redirectors/"+str(type)+"/privkey.pem"
        remotepath = "/etc/letsencrypt/live/"+subdomain+"."+domain+"/privkey.pem"
        sftp.get(remotepath, localpath)
        check_cert = True
    except Exception as e:
        print(e)
    if (check_cert == False):
        try:
            localpath = os.getcwd() + "/certificates/redirectors/" + str(type) + "/cert.pem"
            remotepath = "/etc/letsencrypt/live/" + domain + "/cert.pem"
            sftp.get(remotepath,localpath)
            localpath = os.getcwd() + "/certificates/redirectors/" + str(type) + "/privkey.pem"
            remotepath = "/etc/letsencrypt/live/" + domain + "/privkey.pem"
            sftp.get(remotepath,localpath)
        except Exception as e:
            print(e)

    sftp.close()
    ssh.exec_command("service apache2 restart")
    ssh_stdout = stdout.read()

    firewall_rules(ssh,c2_list[type]["ip"])


def firewall_rules(ssh, ip):
    (stdin, stdout, stderr) = ssh.exec_command("iptables -A PREROUTING -t nat -i eth0 -p tcp --dport 1:21 -j DNAT --to-destination $IP_C2".replace("$IP_C2",ip))
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("iptables -A PREROUTING -t nat -i eth0 -p tcp --dport 23:442 -j DNAT --to-destination $IP_C2".replace("$IP_C2",ip))
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("iptables -A PREROUTING -t nat -i eth0 -p tcp --dport 444:7442 -j DNAT --to-destination $IP_C2".replace("$IP_C2",ip))
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("iptables -A PREROUTING -t nat -i eth0 -p tcp --dport 7444:65535 -j DNAT --to-destination $IP_C2".replace("$IP_C2",ip))
    ssh_stdout = stdout.read()

    (stdin, stdout, stderr) = ssh.exec_command("iptables -A POSTROUTING -t nat -p tcp -d $IP_C2 --dport 1:21 -j MASQUERADE")
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("iptables -A POSTROUTING -t nat -p tcp -d $IP_C2 --dport 23:442 -j MASQUERADE")
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("iptables -A POSTROUTING -t nat -p tcp -d $IP_C2 --dport 444:7442 -j MASQUERADE")
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("iptables -A POSTROUTING -t nat -p tcp -d $IP_C2 --dport 7444:65535 -j MASQUERADE")
    ssh_stdout = stdout.read()

    (stdin, stdout, stderr) = ssh.exec_command("iptables -A FORWARD -p tcp -d $IP_C2 --dport 1:21 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT".replace("$IP_C2",ip))
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("iptables -A FORWARD -p tcp -d $IP_C2 --dport 23:442 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT".replace("$IP_C2",ip))
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("iptables -A FORWARD -p tcp -d $IP_C2 --dport 444:7442 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT".replace("$IP_C2",ip))
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("iptables -A FORWARD -p udp -d $IP_C2 --dport 1:65535 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT".replace("$IP_C2",ip))
    ssh_stdout = stdout.read()

def setDNSInfo(domain,ip,subdomain):
    namecheap_handler.set_redirect_records(domain,ip,subdomain)
