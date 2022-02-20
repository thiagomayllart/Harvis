from bs4 import BeautifulSoup
import requests
import config
import base64
import os

api_key = ""


def install_c2(ssh, c2_type):
    if c2_type == 0:
        install_mythic(ssh)


def install_mythic(ssh):
    (stdin, stdout, stderr) = ssh.exec_command("git clone https://github.com/its-a-feature/Mythic")
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("cd Mythic; ./install_docker_ubuntu.sh")
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command(
        "cd Mythic; sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http -f")
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command(
        "cd Mythic; sudo ./mythic-cli install github https://github.com/MythicC2Profiles/dynamichttp -f")
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command(
        "cd Mythic; sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo -f")
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command(
        "cd Mythic; sudo ./mythic-cli install github https://github.com/MythicAgents/poseidon -f")
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command(
        "cd Mythic; sudo ./mythic-cli install github https://github.com/MythicAgents/apfell -f")
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("cd Mythic; sudo ./mythic-cli mythic start")
    ssh_stdout = stdout.read()


def setup_certificate(ssh, type):
    sftp = ssh.open_sftp()
    localcert = os.getcwd() + "/certificates/redirectors/" + type + "/cert.pem"
    localkey = os.getcwd() + "/certificates/redirectors/" + type + "/privkey.pem"

    remote_path_cert = "/root/Mythic/C2_Profiles/http/c2_code/cert.pem"
    remote_path_key = "/root/Mythic/C2_Profiles/http/c2_code/privkey.pem"

    sftp.put(localcert, remote_path_cert)
    sftp.put(localkey, remote_path_key)

    sftp.close()


def setup_api(ssh, ip, c2_type):
    if c2_type == 0:
        return setup_mythic_api(ssh, ip)


def setup_listener(ip, type, c2_type):
    if c2_type == 0:
        setup_mythic_listener(ip, type)


def get_password(ssh):
    sftp = ssh.open_sftp()
    env = sftp.open("Mythic/.env", "r")
    lines = env.readlines()
    env.close()
    sftp.close()
    for i in lines:
        if "MYTHIC_ADMIN_PASSWORD" in i:
            password = i.split("=")[1]
            return password.replace("\n", "").replace("\n", "\"")


def setup_mythic_api(ssh, ip):
    import requests
    global api_key

    password = get_password(ssh)

    url = "https://{1}:7443/auth"
    url = url.replace("{1}", ip)
    headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
               "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close",
               "Upgrade-Insecure-Requests": "1", "Content-Type": "application/x-www-form-urlencoded"}
    data = {"username": "mythic_admin", "password": password}
    response = requests.post(url, headers=headers, data=data, verify=False)
    access_token = response.cookies["access_token"]

    url = "https://{1}:7443/api/v1.4/apitokens/"
    url = url.replace("{1}", ip)
    cookies = {
        "access_token": access_token}
    headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0",
               "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate",
               "content-type": "application/json",
               "Authorization": "Bearer " + access_token, "Connection": "close"}
    json = {"token_type": "User"}
    response = requests.post(url, headers=headers, cookies=cookies, json=json, verify=False)
    api_key = response.json()["token_value"]

    return password


def setup_mythic_listener(ip, type):
    url = "https://{1}:7443/graphql"
    url = url.replace("{1}", ip)
    headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0",
               "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate",
               "apitoken": api_key,
               "Connection": "close"}
    json_data = {"operationName": "GetC2AndPayloadType",
                 "query": "query GetC2AndPayloadType {\n  c2profile(where: {deleted: {_eq: false}}) {\n    name\n    id\n    __typename\n  }\n  payloadtype(where: {deleted: {_eq: false}, wrapper: {_eq: false}}) {\n    ptype\n    id\n    payloadtypec2profiles {\n      c2profile {\n        name\n        id\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  wrappers: payloadtype(where: {deleted: {_eq: false}, wrapper: {_eq: true}}) {\n    ptype\n    id\n    wrap_these_payload_types {\n      wrapped {\n        ptype\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n"}
    response = requests.get(url, headers=headers, json=json_data, verify=False)
    data = response.json()["data"]["c2profile"]
    needed_profiles = {}
    profile_config = config.c2_profiles[type]
    for i in profile_config:
        name = i["name"]
        for j in data:
            if j["name"] == name:
                needed_profiles[j["id"]] = name

    for i in needed_profiles:
        name = needed_profiles[i]
        url = "https://{1}:7443/graphql"
        url = url.replace("{1}", ip)
        headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0",
                   "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate",
                   "content-type": "application/json",
                   "apitoken": api_key}
        code_raw = ""
        for j in profile_config:
            if j["name"] == name:
                code_raw = j["config"]
                break

        code64 = base64.b64encode(code_raw.encode("utf-8"))

        json = {"operationName": "setProfileConfiguration",
                "query": "mutation setProfileConfiguration($id: Int!, $file_path: String!, $data: String!) {\n  uploadContainerFile(id: $id, file_path: $file_path, data: $data) {\n    status\n    error\n    filename\n    __typename\n  }\n}\n",
                "variables": {"data": code64.decode("utf-8"), "file_path": "config.json", "id": str(i)}}
        requests.post(url, headers=headers, json=json, verify=False)

    for i in needed_profiles:
        url = "https://{1}:7443/graphql"
        url = url.replace("{1}", ip)

        headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0",
                   "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate",
                   "content-type": "application/json",
                   "apitoken": api_key,
                   "Connection": "close"}
        json = {"operationName": "StartStopProfile",
                "query": "mutation StartStopProfile($id: Int!, $action: String) {\n  startStopProfile(id: $id, action: $action) {\n    status\n    error\n    output\n    __typename\n  }\n}\n",
                "variables": {"action": "stop", "id": i}}
        requests.post(url, headers=headers, json=json, verify=False)
        json = {"operationName": "StartStopProfile",
                "query": "mutation StartStopProfile($id: Int!, $action: String) {\n  startStopProfile(id: $id, action: $action) {\n    status\n    error\n    output\n    __typename\n  }\n}\n",
                "variables": {"action": "start", "id": i}}
        requests.post(url, headers=headers, json=json, verify=False)


def firewall_rules(ssh):
    (stdin, stdout, stderr) = ssh.exec_command(
        "iptables -A INPUT -p tcp -s {IP_PROXY} --dport 7443 -j ACCEPT".replace("{IP_PROXY}",
                                                                                config.ip_allowed_to_connect_c2))
    ssh_stdout = stdout.read()
    ip = requests.get('https://api.ipify.org').text
    (stdin, stdout, stderr) = ssh.exec_command(
        "iptables -A INPUT -p tcp -s {IP_PROXY} --dport 7443 -j ACCEPT".replace("{IP_PROXY}", ip))
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("iptables -A INPUT -p tcp -s 127.0.0.1 --dport 7443 -j ACCEPT")
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command(
        "iptables -A INPUT -p tcp -s {IP_PROXY} --dport 8080 -j ACCEPT".replace("{IP_PROXY}", ip))
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command(
        "iptables -A INPUT -p tcp -s {IP_PROXY} --dport 7443 -j ACCEPT".replace("{IP_PROXY}",
                                                                                config.ip_allowed_to_connect_c2))
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("iptables -A INPUT -p tcp -s 0.0.0.0/0 --dport 7443 -j DROP")
    ssh_stdout = stdout.read()
    (stdin, stdout, stderr) = ssh.exec_command("iptables -A INPUT -p tcp -s 0.0.0.0/0 --dport 8080 -j DROP")
    ssh_stdout = stdout.read()
