import json
import backup

def save_backup(domains_types, domains, burned_domains, temp_redirects, redirects, c2, domains_in_use, log, message_queu, key_gb, firewall_rules):
    domains_types_str = json.dumps(domains_types)
    domains_str = "[" + ",".join(['"{0}"'.format(x) for x in domains]) +"]"
    burned_domains_str = "[" + ",".join(['"{0}"'.format(x) for x in burned_domains]) +"]"
    temp_redirects_str = json.dumps(temp_redirects)
    redirects_str = json.dumps(redirects)
    c2_list_str = json.dumps(c2)
    domains_in_use_str = "[" + ",".join(['"{0}"'.format(x) for x in domains_in_use]) +"]"
    log_str = json.dumps(log)
    message_queu_str = json.dumps(message_queu)
    key_gb_str = key_gb
    firewall_rules_str = "[" + ",".join(['"{0}"'.format(x) for x in firewall_rules]) +"]"

    backup_file = open("backup.py","w")
    backup_file.write("domains_types = "+domains_types_str +"\n")
    backup_file.write("domains_str = "+domains_str + "\n")
    backup_file.write("burned_domains_str = "+burned_domains_str+ "\n")
    backup_file.write("temp_redirects = "+temp_redirects_str+ "\n")
    backup_file.write("redirects = "+redirects_str+ "\n")
    backup_file.write("c2 = "+c2_list_str+ "\n")
    backup_file.write("domains_in_use = "+domains_in_use_str+ "\n")
    backup_file.write("log = "+log_str+ "\n")
    backup_file.write("message_queu = "+message_queu_str+ "\n")
    backup_file.write("key_gb = "+str(key_gb_str)+ "\n")
    backup_file.write("firewall_rules = "+firewall_rules_str+ "\n")
    backup_file.write("backup_saved = 1" + "\n")
    backup_file.close()

def recover_backup():
    bkp = [backup.domains_types, backup.domains_str, backup.burned_domains_str, backup.temp_redirects, backup.redirects, backup.c2, backup.domains_in_use, backup.log, backup.message_queu, backup.key_gb, backup.firewall_rules]
    return bkp

def delete_backup():
    f = open("backup.py","w")
    f.write("backup_saved = 0")
    f.close()
