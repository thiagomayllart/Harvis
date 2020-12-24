names = {"short":[]}

digital_ocean_token = ""

namecheap_username = "Harvis"
namecheap_key = ""
namecheap_ipaddress = "0.0.0.0"

apivoid_key = ""

config_apache2_conf = """
<Directory /var/www/>
        Options Indexes FollowSymLinks
        AllowOverride None
        Require all granted
</Directory>
"""

config_default_ssl_conf = """
SSLCertificateFile      /etc/letsencrypt/live/{1}/cert.pem
SSLCertificateKeyFile   /etc/letsencrypt/live/{1}/privkey.pem
"""

config_VirtualHost = """
# Enable SSL
SSLEngine On
SSLProxyEngine On
SSLProxyVerify none
SSLProxyCheckPeerCN off
SSLProxyCheckPeerName off
"""

config_htaccess_dic = \
    {"short":"""
RewriteEngine On
RewriteCond %{REQUEST_URI} ^/({1})/?$ [NC]
RewriteRule ^.*$ https://{2}%{REQUEST_URI} [P]
RewriteRule ^.*$ http://{3}? [L,R=302]
"""
                       }


agent_profiles = {"short":{"URI":"data|index"}}

domain_front_redirector = {"short":"www.example.com"}

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

check_infra_state = 3600 #secs

ip_allowed_to_connect_c2 = "127.0.0.1"

username = "hunt3r547" # =D
