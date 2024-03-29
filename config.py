names = {"short":[]}

digital_ocean_token = ""

namecheap_username = ""
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
RewriteRule ^.*$ http://127.0.0.1:8080%{REQUEST_URI} [P,L]
RewriteRule ^.*$ {3}? [L,R=302]
"""
                       }


agent_profiles = {"short":{"URI":"data|index"}}

domain_front_redirector = {"short":"https://www.example.com"}

c2_profiles = {"short":[{"name":"http","config":"""{
  "instances": [
  {
    "ServerHeaders": {
      "Server": "NetDNA-cache/2.2",
      "Cache-Control": "max-age=0, no-cache",
      "Pragma": "no-cache",
      "Connection": "keep-alive",
      "Content-Type": "application/javascript; charset=utf-8"
    },
    "port": 80,
    "key_path": "",
    "cert_path": "",
    "debug": false,
    "use_ssl": false
    }
  ]
}
"""}] }

check_infra_state = 3600 #secs

ip_allowed_to_connect_c2 = ""

username = "" # =D
