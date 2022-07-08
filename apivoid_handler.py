import config
import requests
import json

estimated_queries = None

#TODOS: make every requst handle in case of no credits/HTTP error

def get_estimated_queries():
    global estimated_queries
    r = requests.get(
        "https://endpoint.apivoid.com/threatlog/v1/pay-as-you-go/?key=" + config.apivoid_key + "&host=www.google.com")
    results = json.loads(r.text)
    estimated_queries = results["estimated_queries"]
    return

def check_propagation(domain,ip):
    global estimated_queries
    r = requests.get("https://endpoint.apivoid.com/dnspropagation/v1/pay-as-you-go/?key=" + config.apivoid_key + "&host=" + domain+ "&dns_type=A")
    results = json.loads(r.text)
    resolvers = results["data"]["propagation"]
    estimated_queries = results["estimated_queries"]
    count = 0
    for i in resolvers:
        if i["response"].replace("\n","") != ip:
            count += 1
    if count > 8:
        return False
    return True

def check_burned_domain(domains_in_use):
    global estimated_queries
    domains_brn = []
    for i in domains_in_use:
        blacklist_list = []
        blacklist = {}
        try:
            r = requests.get(
                "https://endpoint.apivoid.com/domainbl/v1/pay-as-you-go/?key=" +config.apivoid_key +"&host="+i)
            results = json.loads(r.text)
            blacklist = results["data"]["report"]["blacklists"]["engines"]
            estimated_queries = results["estimated_queries"]
        except:
            pass
       # blacklist[6]["detected"] = True
        for j in blacklist:
            if blacklist[j]["detected"] == False:
                blacklist_list.append(blacklist[j])
        if len(blacklist_list) > 0:
            domains_brn.append({"domains":i,"blacklist_list":blacklist_list})

    return domains_brn

def check_burned_redirectors(redirectors):
    global estimated_queries
    ips_brn = []
    for i in redirectors:
        r = requests.get(
            "https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key=" + config.apivoid_key + "&ip=" + redirectors[i]["ip"])
        results = json.loads(r.text)
        estimated_queries = results["estimated_queries"]
        blacklist = results["data"]["report"]["blacklists"]["engines"]
        blacklist_list = []
        for j in blacklist:
            if blacklist[j]["detected"] == True:
                blacklist_list.append(blacklist[j])
        if len(blacklist_list) > 0:
            ips_brn.append({"ips": redirectors[i]["ip"], "blacklist_list": blacklist_list})
    return ips_brn



