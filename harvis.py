import requests
import time
from colors import bcolors
import threading
import random
import json
import os
import subprocess
import sys
from os import chmod
from Crypto.PublicKey import RSA
import logging
import paramiko
import config
from threading import Thread
from namecheap import Api
import redirect_setup
import c2_setup
import apivoid_handler
import namecheap_handler
import backup_handle
import backup
import json

log = {}
message_queu = {}
#action 1 = redirector issue
#action 2 = c2 issue
#aciont 3 = domain pool issue
#action 4 = API Void credit issue

domains_types = {}
domains = []
domains_in_use = []


api = None #api object
#temporary list to keep droplets
#waiting for migration
temp_c2_list = {}
temp_redirects = {}

burned_domains = []

redirects = {}
c2_list = {}

found_keys = []
digital_ocean_token = config.digital_ocean_token
threads = []
req_number = 0

backup_restored = False

c2_mythic = 1
c2_covenant = 2

key_gb = ""

def set_droplets_key():
    global key_gb
    key = RSA.generate(2048)
    with open(os.getcwd() +"/private.pem", 'wb') as content_file:
        chmod(os.getcwd() +"/private.pem", 0o600)
        content_file.write(key.exportKey('PEM'))
    pubkey = key.publickey()
    with open(os.getcwd() +"/private.key", 'wb') as content_file:
        content_file.write(pubkey.exportKey('OpenSSH'))

    f_pb_key = open(os.getcwd() +"/private.key", "r")
    public_key = f_pb_key.read()
    f_pb_key.close()

    id_droplet_gb = ""
    #you have to get the image_id of your snapshot already configured to work as a proxy
    create_ssh_key = "curl -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer "+digital_ocean_token+"' -d '{\"name\":\"Harvis\",\"public_key\":\""+str(public_key)+"\"}' \"https://api.digitalocean.com/v2/account/keys\""
    result_creation_keys = subprocess.Popen(create_ssh_key, shell=True, stdout=subprocess.PIPE).stdout
    key = result_creation_keys.read()

    key_dict = json.loads(key)
    key_gb = str(key_dict["ssh_key"]["id"])

def kill_process_like(command):
    os.system("pkill -f \"ssh -o\"")

def generate_image_from_snapshot(key_gb):
    key_gb = str(key_gb)
    worked = False
    while worked == False:
        try:
            headers = {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer '+digital_ocean_token,
            }

            data = '{"name":"Harvis","region":"nyc1","size":"s-1vcpu-1gb","image":"ubuntu-16-04-x64","ssh_keys":['+key_gb+'],"backups":false,"ipv6":true,"user_data":null,"private_networking":null,"volumes": null,"tags":["'+config.username+'"]}'
            response = requests.post('https://api.digitalocean.com/v2/droplets', headers=headers, data=data)
            status = response.status_code
            while status != 202:
                response = requests.post('https://api.digitalocean.com/v2/droplets', headers=headers, data=data)
                status = response.status_code
                time.sleep(2)
            worked = True
        except Exception as e:
            time.sleep(3)
    return response.content

def get_droplet(id_droplet):
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer '+digital_ocean_token,
    }

    response = requests.get('https://api.digitalocean.com/v2/droplets/'+str(id_droplet), headers=headers)
    status = response.status_code
    while status != 200:
        response = requests.get('https://api.digitalocean.com/v2/droplets/' + str(id_droplet), headers=headers)
        status = response.status_code
        time.sleep(2)
    return response.content


def del_droplet(id_droplet):
    id_droplet = int(id_droplet)
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer '+digital_ocean_token,
    }
    response = requests.delete('https://api.digitalocean.com/v2/droplets/' + str(id_droplet), headers=headers)
    status = response.status_code
    while status != 204:
        response = requests.delete('https://api.digitalocean.com/v2/droplets/'+str(id_droplet), headers=headers)
        status = response.status_code
        time.sleep(2)

def del_ssh(id_key):
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer '+digital_ocean_token,
    }

    response = requests.delete('https://api.digitalocean.com/v2/account/keys/'+str(id_key), headers=headers)
    status = response.status_code
    while status != 204:
        response = requests.delete('https://api.digitalocean.com/v2/account/keys/'+str(id_key), headers=headers)
        status = response.status_code
        time.sleep(2)


def status_response(droplet):
    dict = json.loads(droplet)
    status = dict["droplet"]["status"]
    if 'active' in status:
        return True
    else:
        return False

def ip_response(droplet, id_droplet):
    dict = json.loads(droplet)
    worked = False
    while worked == False:
        try:
            headers = {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + digital_ocean_token,
            }
            resp = requests.get('https://api.digitalocean.com/v2/droplets/' + str(id_droplet), headers=headers)
            resp_content = resp.content
            parsed = json.loads(resp_content)
            while not parsed["droplet"]["networks"]["v4"]:
                resp = requests.get('https://api.digitalocean.com/v2/droplets/' + str(id_droplet), headers=headers)
                resp_content = resp.content
                parsed = json.loads(resp_content)
            for i in parsed["droplet"]["networks"]["v4"]:
                if i["type"] == "public":
                    ip = i["ip_address"]
            worked = True
        except Exception as e:
            time.sleep(3)
            print(e)
    return ip

def id_response(droplet):
    dict = json.loads(droplet)
    id = dict["droplet"]["id"]
    return id

def connect_to_new_droplet(dropletip):
    remote_user = 'root'
    remote_host = dropletip
    remote_port = 22
    local_host = '127.0.0.1'
    local_port = 9092
    ssh_private_key = os.getcwd() +"private.key"
    out = "Connection refused"
    err = ""
    while "Connection refused" in out or "Connection refused" in err or "Connection reset" in out or "Connection reset" in err or "Could not resolve hostname" in err or "Could not resolve hostname" in out or "No such" in out:
        try:
            remote_host = dropletip
            out = ""
            err = ""
            ssh_connect = "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -D " + str(
                local_port) + " -Nf -i " + ssh_private_key + " " + remote_user + "@" + str(remote_host)
            proc1 = subprocess.Popen(ssh_connect, shell=True)
            out, err = proc1.communicate()
            if out == None:
                out = ""
            if err == None:
                err = ""
            time.sleep(1)
            try:
                if "Address already in use" in out:
                    ssh_kill = "ssh -o"
                    kill_process_like(ssh_kill)
            except Exception as msg:
                out = msg
        except Exception as e:
            print(e)


def create_new_droplet(type,type_droplet):
    global c2_list, redirects,key_gb
    result_creation = generate_image_from_snapshot(key_gb)
    id_droplet = id_response(result_creation)
    ip_droplet = ip_response(result_creation, id_droplet)
    droplet = {"id": id_droplet, "ip": ip_droplet, "state":"ok"}
    if type_droplet == 1:
        redirects[type] = droplet
    if type_droplet == 2:
        c2_list[type] = droplet
    if type_droplet == 3:
        #temp redirect
        temp_redirects[type] = droplet
    if type_droplet == 4:
        #temp c2
        temp_c2_list[type] = droplet

def delete_remaining_infra(key_gb):
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + digital_ocean_token,
    }

    response = requests.get('https://api.digitalocean.com/v2/droplets?tag_name='+config.username, headers=headers)
    remaining_droplets = json.loads(response.text)["droplets"]
    for i in remaining_droplets:
        del_droplet(i["id"])


def check_pool():
    global domains
    domains = set(domains) - set(burned_domains)
    if len(domains) < 3:
        full_message = "Running out of Domains! Make sure to purchase more domains"
        message_queu["action4"].append({"message":full_message})

def check_credits():
    if float(apivoid_handler.estimated_queries.replace(",",".")) < 50:
        full_message = "You are running out of credits! Buy more APIVoid credits to avoid interruptions"
        message_queu["action3"].append({"message": full_message})

def check_haul_pools():
    for i in domains_types:
        if len(domains_types[i]) < 3:
            full_message = "Running out of domains at haul: "+str(i)
            message_queu["action5"].append({"message": full_message,"haul":i})


def first_creation(type, type_droplet):
    create_new_droplet(type, type_droplet)


def config_droplet(type, type_connect,c2_type):
    logger = paramiko.util.logging.getLogger()
    hdlr = logging.FileHandler('app.log')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    worked = False
    while worked == False:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            path = os.getcwd()
            k = paramiko.RSAKey.from_private_key_file(path +'/private.pem')
            if type_connect == 1:
                ip = redirects[type]['ip']
                ssh.connect(ip, username='root', pkey=k)
                worked = True
                print("Configuring redirector")
                redirect_setup.install_redir(ssh)
                print("Setting SSL certificates... this might take a while...")
                print("Waiting DNS propagations! We will check every hour")
                domain = ""

                #TO-DOs make possible to add more types of haul

                domain = domains_types[type].pop()
                domains_in_use.append(domain)
                redirects[type]["domain"] = domain

                redirect_setup.setDNSInfo(domain,redirects[type]["ip"])
                while redirect_setup.check_propagation(ssh, c2_list, redirects, type, domain, k, ip) == False:
                    time.sleep(900)
                    ssh.close()
                    ssh_work = False
                    while ssh_work == False:
                        try:
                            ssh.connect(ip, username='root', pkey=k)
                            ssh_work = True
                        except Exception as e:
                            print(e)
                redirect_setup.full_setup(ssh, c2_list, redirects, type, domain, k, ip)
                ssh.close()
                print("Redirectors Set")
            if type_connect == 2:
                print("Setting C2's")
                ip = c2_list[type]['ip']
                ssh.connect(ip, username='root', pkey=k)
                worked = True
                c2_setup.install_c2(ssh,c2_type)
                c2_setup.setup_api(ssh, ip,c2_type)
                print("API KEY set")
                print("Setting Certificates")
                c2_setup.setup_certificate(ssh,type)
                print("Setting Listener Profile")
                c2_setup.setup_listener(ip,type,c2_type)
                print("All Profiles Set")
                print("You are ready to go. This is your infrastructure:")
                show_infra()
                c2_setup.firewall_rules(ssh)
                #run command
            if type_connect == 3:
                ip = temp_redirects[type]['ip']
                ssh.connect(ip, username='root', pkey=k)
                worked = True
                print("Configuring Temporary redirector")
                redirect_setup.install_redir(ssh)
                print("Setting SSL certificates... this might take a while...")
                print("Waiting DNS propagations! We will check every hour")
                domain = ""

                #TO-DOs make possible to add more types of haul

                domain = domains_types[type].pop()
                domains_in_use.append(domain)
                temp_redirects[type]["domain"] = domain

                redirect_setup.setDNSInfo(domain,temp_redirects[type]["ip"])
                while redirect_setup.check_propagation(ssh, c2_list, temp_redirects, type, domain, k, ip) == False:
                    time.sleep(900)
                    ssh.close()
                    ssh_work = False
                    while ssh_work == False:
                        try:
                            ssh.connect(ip, username='root', pkey=k)
                            ssh_work = True
                        except Exception as e:
                            print(e)
                redirect_setup.full_setup(ssh, c2_list, temp_redirects, type, domain, k, ip)
                ssh.close()
                print("Redirectors Set")
            if type_connect == 4:
                print("Setting Temporary C2's")
                ip = temp_c2_list[type]['ip']
                ssh.connect(ip, username='root', pkey=k)
                worked = True
                c2_setup.install_c2(ssh,c2_type)
                c2_setup.setup_api(ssh, ip,c2_type)
                print("API KEY set")
                print("Setting Listener Profile")
                c2_setup.setup_listener(ip,type,c2_type)
                print("All Profiles Set")
                print("You are ready to go. This is your infrastructure:")
                show_infra()
                c2_setup.firewall_rules(ssh)
                #run command
        except Exception as err:
            print(err)
            time.sleep(10)
            logging.debug(err)
            logging.info('Error connecting to Host')
            full_message = "Error in Droplet creation: "+str(err)
            message_queu["action6"].append({"message": full_message})

def update_operation(domains_brn, c2_brn, redirects_brn, domains_in_use, c2_list, redirects):
    #check all burned domains, c2 ips, redirect ips
    if bool(domains_brn):
        full_message = ""
        for i in domains_brn:
            full_message = full_message +"[+] Domain burned: "+i["domains"] +"\n"
            for j in i["blacklist_list"]:
                full_message = full_message +"\t Caught by: "+j["engine"]+". Reference: "+j["reference"] +"\n"
            object_burned = ""
            for k in redirects:
                if redirects[k]["domain"] == i["domains"]:
                    object_burned = redirects[k]
                    if object_burned not in burned_domains:
                        burned_domains.append(redirects[k]["domain"])
            message_already_in = False
            if object_burned:
                for m in message_queu["action1"]:
                    if m["droplet"]["ip"] == object_burned["ip"]:
                        message_already_in = True
                if message_already_in == False:
                    message_queu["action1"].append({"message":full_message, "droplet":object_burned})
                    #avoid adding same message multiple times


    """
    if bool(c2_brn):
        full_message = ""
        for i in c2_brn:
            full_message = full_message + "[+] C2 IP's burned: "+i["ips"]
            for j in i["blacklist_list"]:
                full_message = full_message + "\t Caught by: "+j["engine"]+". Reference: "+j["reference"]
            object_burned = ""
            for k in c2_list:
                if c2_list[k]["ip"] == i["ips"]:
                    object_burned = c2_list[k]
            message_queu["action2"].append({"message":full_message, "droplet":object_burned})
    """

    if bool(redirects_brn):
        full_message = ""
        for i in redirects_brn:
            full_message = full_message + "[+] Redirector IP's burned: "+i["ips"]
            for j in i["blacklist_list"]:
                full_message = full_message + "\t Caught by: "+j["engine"]+". Reference: "+j["reference"]
            object_burned = ""
            for k in redirects:
                if redirects[k]["ip"] == i["ips"]:
                    object_burned = redirects[k]
            message_queu["action1"].append({"message":full_message, "droplet":object_burned})

    check_pool()#check if domain pool is running out of domains
    check_credits()#check if credits are ending apivoid
    check_haul_pools()#check if haul pools are running out of domains




def set_and_check():
    global domains_brn, c2_brn, redirects_brn, domains_in_use, c2_list, redirects,c2_mythic, domains, domains_types, burned_domains,temp_c2_list,temp_redirects,log,message_queu,key_gb

    if(backup_restored == True):
        #create redirectors
        for i in config.names:
            first_creation(i,1)

            #create c2s
        for i in config.names:
            first_creation(i,2)

            #setup redirectors
        for i in config.names:
            config_droplet(i,1,0)

        for i in config.names:
            config_droplet(i,2,0)


    while True:
        domains_brn = apivoid_handler.check_burned_domain(domains_in_use)
        c2_brn = apivoid_handler.check_burned_c2_list(c2_list)
        redirects_brn = apivoid_handler.check_burned_redirectors(redirects)

        backup_handle.save_backup(domains_types, domains, burned_domains,temp_c2_list, temp_redirects, redirects, c2_list, domains_in_use, log, message_queu,key_gb)
        update_operation(domains_brn, c2_brn, redirects_brn, domains_in_use, c2_list, redirects)
        time.sleep(config.check_infra_state)
        message_queu_print()


def damaged_components():
    print("[+] You have components burned")
    for i in domains_types:
        if len(domains_types[i]) == 0:
            print("You have no domains in the "+i+" haul pool.")
            print("Make sure to add at least 1 domain in the haul pool before migrating.")
            return
    print("[+] Choose component to Migrate [0 = ALL]")
    if len(message_queu["action1"]) > 0 or len(message_queu["action2"])>0:
        #find redirectors burned first
        redirects_tmp_list = []
        c2_tmp_list = []
        for i in message_queu["action1"]:
            redirects_tmp_list.append(i["droplet"]["ip"])
        for i in message_queu["action2"]:
            c2_tmp_list.append(i["droplet"]["ip"])

        #tag components with burned
        for i in redirects:
            if redirects[i]["ip"] in redirects_tmp_list:
                redirects[i]["state"] = "burned"

        for i in c2_tmp_list:
            if c2_tmp_list[i]["ip"] in c2_tmp_list:
                c2_tmp_list[i]["state"] = "burned"

        for index,key in enumerate(redirects):
            redirect_str = ""
            c2_str = ""
            if redirects[key]["state"] == "burned":
                redirect_str = str(index+1) +f") [BURNED]"
            if c2_list[key]["state"] == "burned":
                c2_str = str(index+1+len(redirects)) + ") [BURNED]"

            print("Redirect: "+redirects[key]["ip"] +f" {bcolors.WARNING}"+redirect_str +f"{bcolors.ENDC}>>>>>>> C2: " +c2_list[key]["ip"] +c2_str)

        component = input("Component: ")
        print(f"{bcolors.WARNING}This will create a temporary droplet to replace the damaged component. Do you want yo continue?{bcolors.ENDC} {bcolors.BOLD}[Y\\n]{bcolors.ENDC}")
        option = input()
        option = option.lower()
        if option == "y":
            if int(component) == 0:
                for i in message_queu["action1"][:]:
                    for k in redirects:
                        if redirects[k]["ip"] == i["droplet"]["ip"]:
                            redirects[k]["state"] = "pending_kill"
                            first_creation(k, 3)
                            config_droplet(k,3,0)

                            first_creation(k, 4)
                            config_droplet(k, 4, 0)

                            message_queu["action1"].remove(i)
                            message_queu["action7"].append(
                                {"message": "Temporary Droplet Ready. Pending discard.", "droplet": i})

                for i in message_queu["action2"][:]:
                    for k in c2_list:
                        if c2_list[k]["ip"] == i["droplet"]["ip"]:
                            c2_list[k]["state"] = "pending_kill"
                            first_creation(k, 4)
                            config_droplet(k,4,0)

                            message_queu["action2"].remove(i)
                            message_queu["action7"].append(
                                {"message": "Temporary Droplet Ready. Pending discard.", "droplet": i})
            else:
                if int(component) > len(redirects):
                    key_list = list(c2_list)
                    component_key = key_list[int(component) - 1]
                    c2_list[component_key]["state"] = "pending_kill"
                    comp_mod_ip = c2_list[component_key]["ip"]
                    first_creation(component_key, 4)
                    config_droplet(component_key, 4, 0)
                    for i in message_queu["action1"][:]:
                        if i["droplet"]["ip"] == comp_mod_ip:
                            message_queu["action7"].append({"message":"Temporary Droplet Ready. Pending discard.","droplet":i})
                            message_queu["action1"].remove(i)
                else:
                    key_list = list(redirects)
                    component_key = key_list[int(component)-1]
                    redirects[component_key]["state"] = "pending_kill"
                    comp_mod_ip = redirects[component_key]["ip"]
                    first_creation(component_key,3)
                    config_droplet(component_key, 3, 0)

                    c2_list[component_key]["state"] = "pending_kill"
                    c2_mod_ip = c2_list[component_key]["ip"]
                    first_creation(component_key,4)
                    config_droplet(component_key,4,0)


                    for i in message_queu["action1"][:]:
                        if i["droplet"]["ip"] == comp_mod_ip:
                            message_queu["action7"].append({"message":"Temporary Droplet Ready. Pending discard.","droplet":i})
                            message_queu["action1"].remove(i)
                    #get component modified from message_queue

                    #remove from message_queue
                    #add pending_kill to message queue


        else:
            pass


def discard_components():
    print("[+] You have components pending discards")
    print("[+] Choose component to Discard [0 = ALL]")
    if len(message_queu["action7"]):
        # find components to discard
        components_temp = []
        for i in message_queu["action7"]:
            components_temp.append(i["droplet"]["droplet"]["ip"])


        for index, key in enumerate(redirects):
            redirect_str = ""
            c2_str = ""
            if redirects[key]["state"] == "pending_kill":
                redirect_str = str(index + 1) + ") [PENDING DISCARD]"
            if c2_list[key]["state"] == "pending_kill":
                c2_str = str(index + 1 + len(redirects)) + ") [PENDING DISCARD]"

            print("Redirect: " + redirects[key]["ip"] + f" {bcolors.WARNING}"+redirect_str + f"{bcolors.ENDC}>>>>>>>" + c2_list[key]["ip"] + c2_str)

        component = input("Component: ")
        print("Before discarding a component, make sure to migrate your agents to the new droplet.")
        print(f"{bcolors.WARNING}Do you want to continue?[Y\\n] [This will kill all agents in the discarded component] {bcolors.ENDC}")
        option = input()
        option = option.lower()
        if option == "y":
            if int(component) == 0:
                for i in message_queu["action1"][:]:
                    for k in redirects:
                        if redirects[k]["ip"] == i["droplet"]["ip"]:
                            message_queu["action7"].remove(i)
                            del_droplet(redirects[k]["id"])
                            del_droplet(c2_list[k]["id"])
                            redirects[k] = temp_redirects[k]
                            c2_list[k] = temp_c2_list[k]
                            temp_redirects.pop(k, None)
                            temp_c2_list.pop(k, None)

                for i in message_queu["action2"][:]:
                    for k in c2_list:
                        if c2_list[k]["ip"] == i["droplet"]["ip"]:
                            message_queu["action7"].remove(i)
                            del_droplet(c2_list[k]["id"])
                            c2_list[k] = temp_c2_list[k]
                            temp_c2_list.pop(k, None)

            else:
                if int(component) > len(redirects):

                    key_list = list(c2_list)
                    component_key = key_list[int(component) - 1]
                    comp_mod_ip = c2_list[component_key]["ip"]

                    for i in message_queu["action7"][:]:
                        if i["droplet"]["ip"] == comp_mod_ip:
                            message_queu["action7"].remove(i)

                    del_droplet(c2_list[component_key]["id"])
                    c2_list[component_key] = temp_c2_list[component_key]
                    temp_c2_list.pop(component_key, None)

                else:

                    key_list = list(redirects)
                    component_key = key_list[int(component) - 1]
                    comp_mod_ip = redirects[component_key]["ip"]

                    for i in message_queu["action7"][:]:
                        if i["droplet"]["droplet"]["ip"] == comp_mod_ip:
                            message_queu["action7"].remove(i)

                    del_droplet(redirects[component_key]["id"])
                    del_droplet(c2_list[component_key]["id"])
                    redirects[component_key] = temp_redirects[component_key]
                    c2_list[component_key] = temp_c2_list[component_key]
                    temp_redirects.pop(component_key, None)
                    temp_c2_list.pop(component_key, None)

                    # get component modified from message_queue

                    # remove from message_queue
                    # add pending_kill to message queue


        else:
            pass

def show_infra():
    for i in redirects:
        print("Redirect: "+redirects[i]["ip"]+ " >>>>>>> "+"C2: "+c2_list[i]["ip"])

def set_apis():
    print("Choose API Key to set: ")
    print("1) Digital Ocean")
    print("2) Namecheap")
    print("3) APIVoid")
    option = input("Option: ")
    if int(option) == 1:
        api = input("Api key: ")
        config.digital_ocean_token = api
    if int(option) == 2:
        api = input("Api key: ")
        config.namecheap_key = api
    if int(option) == 3:
        api = input("Api key: ")
        config.apivoid_key = api

def kill_all():
    print("This will kill all your droplets and exit. Do you want to continue? [Y\\n]")
    option = input()
    option = option.lower()
    if option == "y":
        for i in redirects:
            del_droplet(i["id"])
        for i in c2_list:
            del_droplet(i["id"])
    else:
        pass


def message_queu_print():
    if "action1" in message_queu:
        for i in message_queu["action1"]:
            print(i["message"])
    if "action2" in message_queu:
        for i in message_queu["action2"]:
            print(i["message"])
    if "action3" in message_queu:
        for i in message_queu["action3"][:]:
            print(i["message"])
            message_queu["action3"].remove(i)
    if "action4" in message_queu:
        for i in message_queu["action4"][:]:
            print(i["message"])
            message_queu["action4"].remove(i)
    if "action5" in message_queu:
        for i in message_queu["action5"][:]:
            print(i["message"])
            message_queu["action5"].remove(i)
    if "action6" in message_queu:
        for i in message_queu["action6"][:]:
            print(i["message"])
            message_queu["action6"].remove(i)
    if "action7" in message_queu:
        for i in message_queu["action7"]:
            print(i["message"])

def check_backup():
    global domains_brn, c2_brn, redirects_brn, domains_in_use, c2_list, redirects, c2_mythic, domains, domains_types, burned_domains, temp_c2_list, temp_redirects, log, message_queu, key_gb

    if backup.backup_saved == 1:
        bkp = backup_handle.recover_backup()
        domains_types = bkp[0]
        domains = bkp[1]
        burned_domains = bkp[2]
        temp_c2_list = bkp[3]
        temp_redirects = bkp[4]
        redirects = bkp[5]
        c2_list = bkp[6]
        domains_in_use = bkp[7]
        log = bkp[8]
        message_queu = bkp[9]
        key_gb = bkp[10]
        apivoid_handler.get_estimated_queries()
        return False
    else:
        delete_remaining_infra(key_gb)
        set_droplets_key()
        return True

def menu():
    global api, domains_types,domains,burned_domains,temp_c2_list,temp_redirects,redirects,c2_list,domains_in_use,log,message_queu
    while True:

        backup_handle.save_backup(domains_types, domains, burned_domains,temp_c2_list, temp_redirects, redirects, c2_list, domains_in_use, log, message_queu, key_gb)

        print("[+] Choose an option:")
        print("1) Buy domain")
        print("2) Move domain to a haul")
        print("3) Remove domain from haul")
        print("4) Move priority of domains in haul")
        print("5) Print Domains")
        situational_message_6 = "[No pending migrations]"
        if len(message_queu["action1"]) > 0 or len(message_queu["action2"])> 0:
            situational_message_6 = f"{bcolors.WARNING}You have burned domains/c2's/redirectors{bcolors.ENDC}"
        print(f"6) Pending Migrations "+situational_message_6)
        situational_message_7 = "[No pending discards]"
        if len(message_queu["action7"]) > 0:
            situational_message_7 = f"{bcolors.WARNING}[You have pending discards for domains/c2's/redirectors] {bcolors.ENDC}"
        print(f"7) Pending Discards "+situational_message_7)
        print("8) Show Infra")

        try:
            command = input("Select: ")
            if command == '1':
                print("0) Back")
                domain_name = input("Insert domain name: ")
                if domain_name.strip() != "0":
                    result_call = namecheap_handler.buy_domain(domain_name)
                    if result_call == False:
                        print("[+] Domain not available")
                    else:
                        print("[+] Domain successfuly acquired")
            if command == '2':
                print("[+] Select Domains to move to a haul: ")
                actual_domains = set(domains) - set(domains_in_use) - set(burned_domains)
                if len(actual_domains) > 0:
                    for index, item in enumerate(actual_domains):
                        print(str(index) + ") "+item)
                    print("1000) Back")
                    domain_option = input("Option: ")
                    if domain_option != "1000":
                        for i in domains_types:
                            if domain_option in i:
                                print("[-] Domain is already in Haul: "+i)
                                print("[-] Remove that domain from the haul to allow moving it")
                            else:
                                print("Select Haul to move: ")
                                for j in config.names:
                                    print("[+] "+j)
                                haul_option = input("Option: ")
                                actual_domains = list(actual_domains)
                                domains_types[haul_option].append(actual_domains[int(domain_option)])
                                domains.remove(actual_domains[int(domain_option)])
                else:
                    print("[+] No available domains in pool. Buy another domain")
            if command == '3':
                print("[+] Domains by Haul:")
                for i in domains_types:
                    print("Haul "+i)
                    for j in domains_types[i]:
                        print(j)
                #remove
                pass #change priority of domains inside haul (priority of rotation)
            if command == '4':
                print("[+] Select Haul")
                for i in domains_types:
                    print("[+] "+i)
                print("[+] 1000) Back")
                haul_option = input("Haul: ")
                if haul_option != "1000":
                    print("[+] Select domain to move priority: ")
                    if bool(domains_types[haul_option]):
                        for index, item in enumerate(domains_types[haul_option]):
                            print(str(index) +") "+item)
                        domain_option = input("Option Number: ")
                        print("[+] Select position to move the domain [Position 1 = Highest priority]: ")
                        position_option = input("Position Number: ")
                        domain_item = domains_types[haul_option].pop(int(domain_option))
                        domains_types[haul_option].insert(int(position_option)-1, domain_item)
                    else:
                        print("[-] No domains in haul")
            if command == '5':
                print("[+] Select print option: ")
                print("1) All Domains in Pool")
                print("2) All Available Domains (not burned, not in use, not in a haul)")
                print("3) All Burned Domains")
                print("4) Domains in Use")
                print("5) Domains by Haul")

                option_number = input("Option Number: ")
                if int(option_number) == 1:
                    print(domains)
                if int(option_number) == 2:
                    actual_domains = set(domains) - set(domains_in_use) - set(burned_domains)
                    print(actual_domains)
                if int(option_number) == 3:
                    print(burned_domains)
                if int(option_number) == 4:
                    print(domains_in_use)
                if int(option_number) == 5:
                    for i in domains_types:
                        print("[-] Haul "+i)
                        for k in domains_types[i]:
                            print(k)
            if command == '6':
                if "No pending migrations" in situational_message_6:
                    print("You have no pending migrations")
                else:
                    damaged_components()

            if command == '7':
                if "[No pending discards]" in situational_message_7:
                    print("You have no pending discards")
                else:
                    discard_components()
            if command == '8':
                show_infra()
            if command == '9':
                pass #add c2 profiles
            if command == '10':
                pass #start migration
            if command == '11':
                pass #edit htaccess redirector
            if command == '12':
                pass #edit c2_profile
            if command == '13':
                set_apis()
            if command == '14':
                kill_all()
        except Exception as e:
            print("Error: ")
            print(e)


def restricted_menu():
    global api, domains_types, domains, burned_domains, temp_c2_list, temp_redirects, redirects, c2_list, domains_in_use, log, message_queu

    check = False
    haul_option = ""

    while check == False:

        print(f"{bcolors.OKGREEN}[+] Choose an option:{bcolors.ENDC}")
        print("1) Buy domain")
        print("2) Move domain to a haul")

        try:
            command = input(f"{bcolors.BOLD}Select: {bcolors.ENDC}")
            if command == '1':
                domain_name = input("Insert domain name: ")
                result_call = namecheap_handler.buy_domain(domain_name)
                if result_call == False:
                    print(f"{bcolors.FAIL}[+] Domain not available{bcolors.ENDC}")
                else:
                    print(f"{bcolors.OKBLUE}[+] Domain successfuly acquired{bcolors.ENDC}")
                    temp_domains = list(api.domains_getList())
                    for i in temp_domains:
                        domains.append(i['name'])
            if command == '2':
                print(f"{bcolors.BOLD}[+] Select Domains to move to a haul: {bcolors.ENDC}")
                actual_domains = set(domains) - set(domains_in_use) - set(burned_domains)
                if len(actual_domains) < len(domains_types):
                    print("[+] You don't have enough domains for each haul. Buy another domain")
                    sys.exit()
                print("[+] You are configuring the following haul's: ")
                for i in domains_types:
                    print("[+] " + i)

                print("")
                for k in domains_types:
                    actual_domains = set(domains) - set(domains_in_use) - set(burned_domains)
                    print("[+] Select one of the available domains to move to the haul "+k)

                    if len(actual_domains) > 0:
                        for index, item in enumerate(actual_domains):
                            print(str(index) + ") " + item)
                        domain_option = input("Option: ")

                        worked = False

                        while worked == False:
                            worked = True
                            for i in domains_types:
                                if domain_option in domains_types[i]:
                                    print("Domain is already present in haul" +i)
                                    print("Select another domain")
                                    domain_option = input("Option: ")
                                    worked = False


                        print("Moving domain to haul "+k)
                        actual_domains = list(actual_domains)
                        domains_types[k].append(actual_domains[int(domain_option)])
                        domains.remove(actual_domains[int(domain_option)])

        except Exception as e:
            print(e)

        check = True







def main():
    global domains_long,domains_short, domains, api,message_queu,backup_restored,domains_types
    digital_ocean_token = config.digital_ocean_token
    message_queu["action1"] = []
    message_queu["action2"] = []
    message_queu["action3"] = []
    message_queu["action4"] = []
    message_queu["action5"] = []
    message_queu["action6"] = []
    message_queu["action7"] = []

    if config.namecheap_key == "":
        print(f"{bcolors.FAIL}[+] Namecheap API Key missing{bcolors.ENDC}")
        sys.exit()
    if config.apivoid_key == "":
        print(f"{bcolors.FAIL}[+] APIVoid API Key missing{bcolors.ENDC}")
        sys.exit(0)

    api = Api(config.namecheap_username, config.namecheap_key, config.namecheap_ipaddress, sandbox=False)

    for i in config.names:
        domains_types[i] = config.names[i]

    temp_domains = list(api.domains_getList())
    backup_restored = check_backup()
    for i in temp_domains:
        domains.append(i['name'])


    check_names = True
    for i in config.names:
        if len(config.names[i]) == 0:
            check_names = False
            break
    if check_names == False:
        check_names = True
        for i in domains_types:
            if len(domains_types[i]) == 0:
                print("[+] No domains found in haul "+ i)
                check_names = False
        if check_names == False:
            restricted_menu()


    thread = Thread(target=set_and_check)
    thread.start()
    thread2 = Thread(target=menu)
    thread2.start()

    thread.join()
    thread2.join()

main()
