from bs4 import BeautifulSoup
import requests
import config
import base64


csrf_token = ""
api_key = ""

def install_c2(ssh,c2_type):
    if c2_type == 0:
        install_mythic(ssh)

def install_mythic(ssh):
    (stdin, stdout, stderr) = ssh.exec_command("git clone https://github.com/its-a-feature/Mythic")
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("cd Mythic; ./install_docker_ubuntu.sh")
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("cd Mythic; ./install_agent_from_github.sh https://github.com/MythicAgents/Apollo")
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("cd Mythic; ./start_mythic.sh")
    ssh_stdout = stdout.read()

def setup_api(ssh, ip,c2_type):
    if c2_type == 0:
        setup_mythic_api(ssh,ip)

def setup_listener(ip,type, c2_type):
    if c2_type == 0:
        setup_mythic_listener(ip,type)

def setup_mythic_api(ssh,ip):
    import requests
    global csrf_token,api_key

    url = "https://{1}:7443/login"
    url = url.replace("{1}", ip)
    headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0",
                     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                     "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close",
                     "Upgrade-Insecure-Requests": "1"}
    response = requests.get(url, headers=headers,verify=False)
    soup = BeautifulSoup(response.text)
    hidden_tags = soup.find_all("input", type="hidden")
    for tag in hidden_tags:
        if tag.attrs["name"] == "csrf_token":
            csrf_token = tag.attrs["value"]
            break

    url = "https://{1}:7443/login"
    url = url.replace("{1}", ip)
    headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0",
                     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                     "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate",
                     "Content-Type": "application/x-www-form-urlencoded",
                     "Connection": "close", "Upgrade-Insecure-Requests": "1"}

    data = {"csrf_token": csrf_token, "username": "mythic_admin",
                  "password": "mythic_password", "submit": "Sign In"}
    response = requests.post(url, headers=headers, data=data, verify=False)
    access_token = response.cookies["access_token"]

    url = "https://{1}:7443/api/v1.4/apitokens/"
    url = url.replace("{1}", ip)
    cookies = {
        "access_token": access_token}
    headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0",
                     "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate",
                     "content-type": "application/json",
                     "Authorization": "Bearer "+access_token, "Connection": "close"}
    json = {"token_type": "User"}
    response = requests.post(url, headers=headers, cookies=cookies, json=json,verify=False)
    api_key = response.json()["token_value"]

def setup_mythic_listener(ip,type):

    url = "https://{1}:7443/api/v1.4/c2profiles"
    url = url.replace("{1}", ip)
    headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0",
                     "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate",
                     "apitoken": api_key,
                     "Connection": "close"}
    response = requests.get(url, headers=headers,verify=False)
    text = response.json()
    needed_profiles = {}
    profile_config = config.c2_profiles[type]
    for i in profile_config:
        name = i["name"]
        for j in text:
            if j["name"] == name:
                needed_profiles[j["id"]] = name

    for i in needed_profiles:
        name = needed_profiles[i]

        url = "https://{1}:7443/api/v1.4/c2profiles/{2}/files/container_config_upload"
        url = url.replace("{1}", ip).replace("{2}",str(i))
        headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0",
                         "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate",
                         "content-type": "application/json",
                         "apitoken": api_key}

        code_raw = ""
        for i in profile_config:
            if i["name"] == name:
                code_raw = i["config"]
                break

        code64 = base64.b64encode(code_raw.encode("utf-8"))

        json = {
            "code": code64}
        requests.post(url, headers=headers, json=json,verify=False)

    for i in needed_profiles:

        url = "https://{1}:7443/api/v1.4/c2profiles/{2}/start"
        url = url.replace("{1}",ip).replace("{2}", str(i))

        headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0",
                         "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate",
                         "content-type": "application/json",
                         "apitoken": api_key,
                         "Connection": "close"}
        requests.get(url, headers=headers,verify=False)

def firewall_rules(ssh):
    (stdin, stdout, stderr) = ssh.exec_command("iptables -A INPUT -p tcp -s {IP_PROXY} --dport 7443 -j ACCEPT".replace("{IP_PROXY}", config.ip_allowed_to_connect_c2))
    ssh_stdout = stdout.read()
    ip = requests.get('https://api.ipify.org').text
    (stdin, stdout, stderr) = ssh.exec_command("iptables -A INPUT -p tcp -s {IP_PROXY} --dport 7443 -j ACCEPT".replace("{IP_PROXY}", ip))
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command(
        "iptables -A INPUT -p tcp -s {IP_PROXY} --dport 8080 -j ACCEPT".replace("{IP_PROXY}", ip))
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command(
        "iptables -A INPUT -p tcp -s {IP_PROXY} --dport 7443 -j ACCEPT".replace("{IP_PROXY}", config.ip_allowed_to_connect_c2))
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("iptables -A INPUT -p tcp -s 0.0.0.0/0 --dport 7443 -j DROP")
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("iptables -A INPUT -p tcp -s 0.0.0.0/0 --dport 8080 -j DROP")
    ssh_stdout = stdout.read()
