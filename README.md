# Harvis
Harvis is designed to automate your C2 Infrastructure, currently using Mythic C2.

## 📌 What is it?

Harvis is a python tool to help you create multiple hauls for a specific operation during a red team engagement. It can automatically create your C2 machine, redirector machine, setup SSL, .htaccess configuration, firewall rules and more. Harvis also has the purpose of automating the job of the operator of identifying burned domains/redirectors that may be caught during the operation. After identifying the burned domains it provides the possibility of rotating the infrastructure, setting up different redirectors and atributing a different domain.


## 📌 How?

:hammer: Harvis uses the Digital Ocean API to automate creation and deletion of droplets.

:hammer: The Namecheap API is used to DNS records to redirectors.

:hammer: The API Void is used to constantly verify the state of the redirectors and check if anything is blacklisted.

## Features

Harvis has several features to help you organize your available domains and redirector/C2 machines.

* **Namecheap Interaction** - Harvis enables you to buy domains directly through the command line, as long as you have credits in your account.
* **Multiple Hauls** - It is possible to create as many hauls as possible, each one having specific configurations.
* **Multiple C2 Profiles by Haul** - Harvis allows you to create multiple C2 profiles by hauls: you could two HTTP listeners in one of the C2's and 3 in the other one, each of them listening on different ports.
* **Multiple Redirector Configuration** - Each redirector can have a different .htaccess configuration, defined by the operator.
* **Customizable Firewall Rules** - Harvis comes with default firewall rules for the redirectors and C2's, however, this feature is easily customizable.
* **Priority System** - Each haul has a queue system, in a way that the new redirector will replace the blacklisted one with the domains in the queue.
* **Priority System** - Automatically replace your droplets: Harvis identifies any blacklisted redirector and print the results to the operator. It allows the operator to create a temporary droplet to replace the blacklisted one. It does not configure the migration of any active agents, since the way the agent will be migrated/spawned to connect to the new domain might be a very personal decision in an engagement. After creating the temporary droplet, it allows you to migrate any active agents and kill the older redirector.
* **Priority System** - If somehow the script crashes, all the information will be saved in the backup.py file. Restarting the script will recover all your infrastructure as it was.
* 

### Installation

```
git clone https://github.com/thiagomayllart/Harvis/
cd Harvis
pip install -r requirements
```

### Running

```
python harvis.py
```



## Configuring API Keys

Harvis can only be used with the proper API Keys from Digital Ocean, Namecheap, APIVoid.

These api keys should be added to the config.py file in the respective lines:

```
digital_ocean_token = ""
...
namecheap_key = ""
...
apivoid_key = ""
...
```

For more information regarding these API Keys, visit:

https://app.apivoid.com/
https://ap.www.namecheap.com/
https://cloud.digitalocean.com/

## First Run

Before running the script, you should apply some modifications to the config file, which describes the configuration of your infrastructure:

1. Modify the "names" variable. 

This variable holds the names of each haul you want your infrastructure you have. Theses names should be applied in the next variables. You can have as many hauls you want. You can also specify which domain should already be configure to each haul. If you don't specify the domains, you will be asked to move domains to each haul in the first run. If you don't have any available domains in your namecheap API, you can buy it directly though Harvis. It is also possible to have more than one domain in each haul: the first one will be used in the redirector and the others will already be in the backup list for further infrastructure rotations. Example:

```
names = {"short":[],"long":[],"exploitation":[],"testing":[]}
```

```
names = {"short":["domain1.com"],"long":["domain2.com","domain3.com"],"exploitation":["domain4.com"],"testing":["domain5.com"]}
```

2. Modify the "config_htaccess_dic" variable:

You can customize your htaccess rules for each haul in this variable. This variable is dictionary, so remember to add an htacces for each haul you added previously in the "names" variable like:

```
config_htaccess_dic = \
    {"short":"""
RewriteEngine On
RewriteCond %{REQUEST_URI} ^/({1})/?$ [NC]
RewriteRule ^.*$ https://{2}%{REQUEST_URI} [P]
RewriteRule ^.*$ http://{3}? [L,R=302]
""","long:"""
RewriteEngine On
RewriteCond %{REQUEST_URI} ^/({1})/?$ [NC]
RewriteRule ^.*$ https://{2}%{REQUEST_URI} [P]
RewriteRule ^.*$ http://{3}? [L,R=302]
""","exploitation":"""
RewriteEngine On
RewriteCond %{REQUEST_URI} ^/({1})/?$ [NC]
RewriteRule ^.*$ https://{2}%{REQUEST_URI} [P]
RewriteRule ^.*$ http://{3}? [L,R=302]
""","testing":"""
RewriteEngine On
RewriteCond %{REQUEST_URI} ^/({1})/?$ [NC]
RewriteRule ^.*$ https://{2}%{REQUEST_URI} [P]
RewriteRule ^.*$ http://{3}? [L,R=302]
"""
                       }
```

You can notice the presence of the fields: {1}, {2}, {3}. If you customize this variable, do not remove them. {1} are the parameters your Mythic agent will use to communicate to the C2 (it also allows customization). {2} is the IP address of your C2. {3} is the location the redirector will be redirecting (it also allows customization).

3. Modify the "agent_profiles" variable:

This variable describes the HTTP parameters that your agent will use to communicate to your C2. Mythic allows setting these parameters during the creation of the agent, so, these values should match the ones you will be configurating the agent. The first one is the GET parameter and other one is the POST parameter. Also, remeber to once again add a configuration to each haul you created previously:

```
agent_profiles = {"short":{"URI":"data|index"},"long":{"URI":"q|id"}... ...
```

4. Modify "domain_front_redirector" variable:

This variable holds the domain your redirectors will be redirecting anyone that tries to access. Add a configuration to each haul you created previously:

```
domain_front_redirector = {"short":"www.example.com","long":"www.example2.com"... ... ...

```

5. Modify "c2_profiles" variable:

With the "c2_profiles" variable you can create different listener profiles for each Haul you created. The format is exactly the same as the JSON you may find when accessing Configuring a C2 Profile in Mythic. You can also have other profiles than HTTP, however, depending on the protocol used, it may be necessary to change firewall rules in the C2 or the redirector (further explained).

Example:

```

c2_profiles = {"short":[{"name":"HTTP","config":"""{
  "instances": [
  {
    "ServerHeaders": {
      "Server": "NetDNA-cache/2.2",
      "Cache-Control": "max-age=0, no-cache",
      "Pragma": "no-cache",
      "Connection": "keep-alive",
      "Content-Type": "application/javascript; charset=utf-8"
    },
    "port": 443,
    "key_path": "privkey.pem",
    "cert_path": "cert.pem",
    "debug": true
    }
  ]
}"""}],"long":[{"name":"HTTP","config":"""{
  "instances": [
  {
    "ServerHeaders": {
      "Server": "NetDNA-cache/2.2",
      "Cache-Control": "max-age=0, no-cache",
      "Pragma": "no-cache",
      "Connection": "keep-alive",
      "Content-Type": "application/javascript; charset=utf-8"
    },
    "port": 443,
    "key_path": "privkey.pem",
    "cert_path": "cert.pem",
    "debug": true
    }
  ]
}"""}] }
```

6. Modify the "check_infra_state" variable:

This variable holds the value (in seconds) that will be used as the interval between each verification of blacklisted domains by APIVoid.

7. Modify "ip_allowed_to_connect_c2":

Replace it with the IP you will be using as the proxy to connect to your Mythic C2 panel. You can use your public IP, but it is not recommended. 

8. Replace "username":

Replace it with the username you will be using during the engagement. This variable is used to tag each droplet created in digital ocean, making the distinction between the droplets of each operator easier. It also avoids that the tool erases the droplet of another user (in case you guys are using the same API Keys).

9. Modify Firewall Rules (OPTIONAL):

If you want to modify the firewall rules for the C2/redirector, you will find them respectively at:

C2: C2_setup.py: function firewall_rules
Redirector: redirect_setup.py: firewall_rules

## Important

Harvis whitelists the IP of the machine you are deploying it as being able to access your Mythic C2 panel. It is highly recommended to use a VPC to deploy Harvis.


