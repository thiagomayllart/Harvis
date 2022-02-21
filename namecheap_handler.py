from namecheap import Api, ApiError
import config

api = Api(config.namecheap_username, config.namecheap_key, config.namecheap_ipaddress, sandbox=False)

contact_details = dict(
    FirstName='Jack',
    LastName='Trotter',
    Address1='Ridiculously Big Mansion, Yellow Brick Road',
    City='Tokushima',
    StateProvince='Tokushima',
    PostalCode='771-0144',
    Country='Japan',
    Phone="+81.123123123",
    EmailAddress='jack.trotter@example.com'
)

def set_redirect_records(domain, ip,subdomain):
    info = api.list_records(domain)
    for i in info:
        type = i["type"]
        name = i["name"]
        address = i["address"]
        api.delete_record(domain,type, address,name)
    api.add_record(domain, 'A', ip)

    api.add_record(domain, 'A', ip, subdomain)


def buy_domain(domain_name):
    if api.domains_check(domain_name) == False:
        return False
    else:
        tld_prices = api.get_tld_prices('com', 'org', 'net', 'bz', 'xyz', 'us')
        for tld, price in tld_prices.items():
            print(
                f".{tld} pricing - Current Price: ${price.total_your_price:.2f} | Regular Price: ${price.total_regular_price:.2f}")
        print("-------------")
        check_buy = input("Do you confirm the purchase operation?[Y\\n]")
        option = check_buy.lower()
        if option == "y":
            reg = api.domains_create(
                domain_name,
                **contact_details
            )
            print("Domain registration result:", reg)
            return False
        else:
            pass
        return True
