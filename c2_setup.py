import time

from bs4 import BeautifulSoup
import requests
import config
import base64
import os
import logging
import json
import io

api_key = ""


def install_c2(ssh, c2_type):
    if c2_type == 0:
        install_mythic(ssh)

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
            time.sleep(5)
    logging.info(outdata)
    logging.info(errdata)
    return (outdata, errdata)

def install_mythic(ssh):
    run_comm(ssh,"git clone https://github.com/its-a-feature/Mythic")
    run_comm(ssh,"cd Mythic; ./install_docker_ubuntu.sh")
    run_comm(ssh,
        "cd Mythic; sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http -f")
    run_comm(ssh,
        "cd Mythic; sudo ./mythic-cli install github https://github.com/MythicC2Profiles/dynamichttp -f")
    run_comm(ssh,
        "cd Mythic; sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo -f")
    run_comm(ssh,
        "cd Mythic; sudo ./mythic-cli install github https://github.com/MythicAgents/poseidon -f")
    run_comm(ssh,
        "cd Mythic; sudo ./mythic-cli install github https://github.com/MythicAgents/apfell -f")
    run_comm(ssh,"cd Mythic; sudo ./mythic-cli mythic start")

def setup_forward(ssh, redirector):
    run_comm(ssh,
        "chmod 400 /root/private.pem")
    ssh.exec_command(
        "ssh -i /root/private.pem -o StrictHostKeyChecking=accept-new -R 8080:127.0.0.1:80 -Nf root@"+redirector["ip"])

def setup_redirectors(ssh, redirects, type):
    setup_forward(ssh, redirects[type])

def setup_redirectors_ssh(ssh):
    sftp = ssh.open_sftp()
    sftp.put(os.getcwd()+'/private.pem',"/root/private.pem")
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
            return password.replace("\n", "").replace("\"", "").replace("\'","")


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
    json = {"username": "mythic_admin", "password": password}
    response = requests.post(url, headers=headers, json=json, verify=False)
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
    url = "https://{1}:7443/graphql/"
    url = url.replace("{1}", ip)
    headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0",
               "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate",
               "content-type": "application/json",
               "Authorization": "Bearer "+api_key,
               "Connection": "close"}
    json_data = {"operationName": "GetC2AndPayloadType",
                 "query": "query GetC2AndPayloadType {\n  c2profile(where: {deleted: {_eq: false}}) {\n    name\n    id\n    __typename\n  }\n  payloadtype(where: {deleted: {_eq: false}, wrapper: {_eq: false}}) {\n    ptype\n    id\n    payloadtypec2profiles {\n      c2profile {\n        name\n        id\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  wrappers: payloadtype(where: {deleted: {_eq: false}, wrapper: {_eq: true}}) {\n    ptype\n    id\n    wrap_these_payload_types {\n      wrapped {\n        ptype\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n"}
    worked = False
    data = []
    while worked == False:
        try:
            response = requests.post(url, headers=headers, json=json_data, verify=False)
            data = response.json()["data"]["c2profile"]
            worked = True
        except:
            time.sleep(5)
    needed_profiles = {}
    profile_config = config.c2_profiles[type]
    for i in profile_config:
        name = i["name"]
        for j in data:
            if j["name"] == name:
                needed_profiles[j["id"]] = name

    for i in needed_profiles:
        name = needed_profiles[i]
        url = "https://{1}:7443/graphql/"
        url = url.replace("{1}", ip)
        headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0",
                   "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate",
                   "content-type": "application/json",
                   "Authorization": "Bearer "+api_key}
        code_raw = ""
        for j in profile_config:
            if j["name"] == name:
                code_raw = j["config"]
                break

        code64 = base64.b64encode(code_raw.encode("utf-8"))

        json = {"operationName": "setProfileConfiguration",
                "query": "mutation setProfileConfiguration($id: Int!, $file_path: String!, $data: String!) {\n  uploadContainerFile(id: $id, file_path: $file_path, data: $data) {\n    status\n    error\n    filename\n    __typename\n  }\n}\n",
                "variables": {"data": code64.decode("utf-8"), "file_path": "config.json", "id": str(i)}}
        worked = False
        while worked == False:
            try:
                response = requests.post(url, headers=headers, json=json, verify=False)
                if response.status_code == 200:
                    worked = True
            except:
                time.sleep(5)

    for i in needed_profiles:
        url = "https://{1}:7443/graphql/"
        url = url.replace("{1}", ip)

        headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0",
                   "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate",
                   "content-type": "application/json",
                   "Authorization": "Bearer "+api_key,
                   "Connection": "close"}
        json = {"operationName": "StartStopProfile",
                "query": "mutation StartStopProfile($id: Int!, $action: String) {\n  startStopProfile(id: $id, action: $action) {\n    status\n    error\n    output\n    __typename\n  }\n}\n",
                "variables": {"action": "stop", "id": i}}
        worked = False
        while worked == False:
            try:
                response = requests.post(url, headers=headers, json=json, verify=False)
                if response.status_code == 200:
                    worked = True
            except:
                time.sleep(5)
        json = {"operationName": "StartStopProfile",
                "query": "mutation StartStopProfile($id: Int!, $action: String) {\n  startStopProfile(id: $id, action: $action) {\n    status\n    error\n    output\n    __typename\n  }\n}\n",
                "variables": {"action": "start", "id": i}}
        worked = False
        while worked == False:
            try:
                response = requests.post(url, headers=headers, json=json, verify=False)
                if response.status_code == 200:
                    worked = True
            except:
                time.sleep(5)


def firewall_rules(c2,redirects):
    redirect_ips = []
    for i in redirects:
        redirect_ips.append(redirects[i]["ip"])
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + config.digital_ocean_token,
    }
    data = {"name": "firewallc2", "inbound_rules": [
        {
            "protocol": "tcp",
            "ports": "7443",
            "sources": {
                "addresses": [
                    config.ip_allowed_to_connect_c2
                ]
            },
        },
        {
            "protocol": "tcp",
            "ports": "0",
            "sources": {
                "addresses":
                    redirect_ips

            },
        }
    ],"outbound_rules":[
        {
            "protocol": "tcp",
            "ports": "0",
            "destinations": {
                "addresses":
                    redirect_ips
            }
        }
    ]
            ,"droplet_ids": [
            c2["id"]
        ]
            }
    response = requests.post('https://api.digitalocean.com/v2/firewalls', headers=headers, json=data)
    id = firewall_id(response)
    return id


def firewall_id(response):
    dict = json.loads(response.content)
    id = dict["firewall"]["id"]
    return id

def append_rule(additional_redir):
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + config.digital_ocean_token,
    }
    response = requests.get('https://api.digitalocean.com/v2/firewalls', headers=headers)
    rule = json.loads(response.content)
    for index, item in enumerate(rule["inbound_rules"]):
        if item["ports"] == "22":
            new_item = item["sources"]["addresses"].append(additional_redir["ip"])
            rule["inbound_rules"][index] = new_item
            break
    response = requests.post('https://api.digitalocean.com/v2/firewalls', headers=headers, json=rule)
