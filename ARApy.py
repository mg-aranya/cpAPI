from pyclearpass import *
def menu():
    print("\n=== Main Menu ===")
    print("1. Print all network devices")
    print("2. Print network device by name")
    print("3. Add network device")
    print("4. Delete network device by name")
    print("5. Help")
    print("99. Exit")

def YesNo(name):
    yes = {'yes','y'}
    no = {'no','n'}
    while True:
        try:
            print("Enter 'yes' or 'no'")
            choice = input(":").lower()
            if choice in yes:
               return True
            elif choice in no:
               return False
            else:
               print("Please respond with 'yes' or 'no'")
        except KeyboardInterrupt:
            print("\nControl-C... Exiting")
            sys.exit()

def errorHandling(json_data):
    HTTPStatus = {
    "200": "OK",
    "201": "Created",
    "204": "No Content",
    "304": "Not Modified",
    "400": "Bad Request",
    "401": "Unauthorized",
    "403": "Forbidden",
    "404": "Not Found",
    "406": "Not Acceptable",
    "415": "Unsupported Media Type",
    "422": "Unprocessable Entity"
    }
    try:
        print("HTTP Status: {} {}".format(json_data['status'],json_data['detail']))
        return False
    except KeyError:
        return True

def credentials():
    login = ClearPassAPILogin(
    server="https://192.168.100.30:443/api",
    granttype="client_credentials",
    clientsecret="h6jXPUUZh/GzktMFw0Sr/Is1WeISEwAQF+k7bTFH7393",
    clientid="Client2",
    verify_ssl=False)
    return login

def format_json(data: dict) -> str:
    return json.dumps(data, indent=2)

def readcsv(file):
    with open(file, 'rt') as csvfile:
        readfile = csv.reader(csvfile, delimiter=',')
        for row in readfile:
            row[0]

def Cnew_network_device(login, description="",name=None,ip_address=None,radius_secret=None,tacacs_secret=None,vendor_name=None):
    if not name:
        name = input("Name: ").strip()
    if not description:
        description = input("Description: ").strip()
    if not ip_address:
        ip_address = input("IP-Address (With CIDR mask): ").strip()
    if not radius_secret:
        radius_secret = input("RADIUS PSK: ").strip()
    if not tacacs_secret:
        tacacs_secret = input("TACACS+ PSK: ").strip()
    if not vendor_name:
        vendor_name = input("Vendor Name: ").strip()
    body={
    "description" : description, #Description of the network device. Object Type: string
    "name" : name, #Name of the network device. Object Type: string
    "ip_address" : ip_address, #IP or Subnet Address of the network device. Object Type: string
    "radius_secret" : radius_secret, #RADIUS Shared Secret of the network device. Object Type: string
    "tacacs_secret" : tacacs_secret, #TACACS+ Shared Secret of the network device. Object Type: string
    "vendor_name" : vendor_name, #Vendor Name of the network device. Object Type: string
    "coa_capable" : True, #Flag indicating if the network device is capable of CoA. Object Type: boolean
    "coa_port" : 3799, #CoA port number of the network device. Object Type: integer
    }
    json_data = ApiPolicyElements.new_network_device(login, body)
    if errorHandling(json_data):
        print("id: {} name: {} ip_address: {}".format(json_data['id'], json_data['name'], json_data['ip_address']))
    return json_data

def Cget_network_device(login):
    json_data = ApiPolicyElements.get_network_device(login)["_embedded"]["items"]
    #print(format_json(json_data))
    for data in json_data:
        print("id: {} name: {} ip_address: {}".format(data['id'], data['name'], data['ip_address']))
    return json_data

def Cget_network_device_name_by_name(login, name=None):
    if name == None: 
        name = input("Enter name: ").strip()
    json_data = ApiPolicyElements.get_network_device_name_by_name(login,name)
    if errorHandling(json_data):
        print("id: {} name: {} ip_address: {}".format(json_data['id'], json_data['name'], json_data['ip_address']))
        return json_data
    else:
        return json_data

def Cdelete_network_device_name_by_name(login, name=None):
    if name == None:     
        name = input("Enter name of the device you want to delete: ").strip()
    try:
        json_data = Cget_network_device_name_by_name(login, name)
        if errorHandling:
            if json_data['name'] == name:
                print("Are you sure you want to delete '{}'".format(json_data['name']))
                if YesNo(name):
                    print("Deleting device id: {} name: {} ip_address: {}".format(json_data['id'], json_data['name'], json_data['ip_address']))
                    json_data = ApiPolicyElements.delete_network_device_name_by_name(login, name)
    except KeyError:
        print("Unable to find device '{}'".format(name))
        return False                      
    return json_data
