import requests  # Import JSON encoder and decoder module
import time
import json      # requests module used to send REST requests to API
from tabulate import *
from apic_em_functions_sol import *

requests.packages.urllib3.disable_warnings()  # Disable SSL warnings

def get_ticket():
    api_url = "https://devnetsbx-netacad-apicem-1.cisco.com/api/v1/ticket"
    headers = {
        "content-type": "application/json"
    }
    body_json = {
        "username": "devnetuser",
        "password": "NTgmY5UY"
    }
    resp = requests.post(api_url, json.dumps(body_json), headers=headers, verify=False)
    status = resp.status_code
    response_json = resp.json()
    serviceTicket = response_json["response"]["serviceTicket"]
    print("The service ticket number is: ", serviceTicket)
    return serviceTicket


def print_hosts():
    api_url = "https://devnetsbx-netacad-apicem-1.cisco.com/api/v1/host"
    ticket = get_ticket()
    headers = {
        "content-type": "application/json",
        "X-Auth-Token": ticket
    }

    resp = requests.get(api_url, headers=headers, verify=False)
    # This is the http request status
    print("Status of /host request: ", resp.status_code)
    # Check if the request status was 200/OK
    if resp.status_code != 200:
        raise Exception("Status code does not equal 200. Response text: " + resp.text)
    # Get the json-encoded content from response
    response_json = resp.json()  

    # Now create a list of host info to be held in host_list
    host_list = []
    i = 0
    for item in response_json["response"]:
        i += 1
        host = [
                i, 
                item["hostType"], 
                item["hostIp"] 
               ]
        host_list.append( host )

    table_header = [
                    "Number",
                    "Type",
                    "IP"
                   ]
    print( tabulate(host_list, table_header) )


def print_devices():
    # NETWORK-DEVICE API URL
    #api_url = "https://{YOUR-APICEM}.cisco.com/api/v1/network-device"
    api_url = "https://devnetsbx-netacad-apicem-1.cisco.com/api/v1/network-device"

    # Setup API request headers.
    ticket = get_ticket()
    headers = {
        "content-type": "application/json",
        "X-Auth-Token": ticket
    }

    resp = requests.get(api_url, headers=headers, verify=False)
    print("Status of GET /network-device request: ", resp.status_code)  # This is the http request status
    # Check if the request status was 200/OK
    if resp.status_code != 200:
        raise Exception("Status code does not equal 200. Response text: " + resp.text)
    # Get the json-encoded content from response
    response_json = resp.json()  

    # Now create a list of host summary info
    device_list = []
    i = 0
    for item in response_json["response"]:
        i += 1
        device = [
                    i, 
                    item["type"], 
                    item["managementIpAddress"] 
                 ]
        device_list.append( device )

    table_header = [
                    "Number", 
                    "Type", 
                    "IP"
                   ]
    print( tabulate(device_list, table_header) )



def print_flow(networkElementsInfo):
    trace_list = []
    i = 0
    for item in networkElementsInfo:
        i += 1
        key_exists = 'name' in item
        key_ip_exists = 'ip' in item
        if key_exists and key_ip_exists:
            trace_device = [ i, item["id"], item["name"], item["ip"] ]
        elif key_exists and not key_ip_exists:
            trace_device = [ i, item["id"],  tem["name"], "NONE"  ]
        elif not key_exists and key_ip_exists:
            trace_device = [  i, item["id"], "NONE", item["ip"] ]
        else:
            trace_device = [ i, item["id"], "NONE",  "NONE" ]
        trace_list.append( trace_device )
    table_header = [
                    "Number", 
                    "id", 
                    "Name",
                    "IP"
                   ]
    print( tabulate(trace_list, table_header) )

    


print("List of hosts on the network: ")
print_hosts()
print("List of devices on the network: ")
print_devices()


while True:
    #++++++++++++++++++++++++++++++++++++++++++
    s_ip = input("Please enter the source host IP address for the path trace: ")
    d_ip = input("Please enter the destination host IP address for the path trace: ")
    #++++++++++++++++++++++++++++++++++++++++++
    # Various error traps could be completed here - POSSIBLE CHALLENGE
    if s_ip != "" or d_ip != "":
        # this creates a python dictionary that will be dumped as a
        path_data = {
            "sourceIP": s_ip,
            "destIP": d_ip
        }
        # stud: optional challenge
        print("Source IP address is: ",       path_data["sourceIP"])
        print("Destination IP address is: ",  path_data["destIP"])  # stud: optional challenge
        break  # Exit loop if values supplied
    else:
        print("\n\nYOU MUST ENTER IP ADDRESSES TO CONTINUE.\nUSE CTRL-C TO QUIT\n")
        continue  # Return to beginning of loop and repeat

path =  json.dumps(path_data)
api_url = "https://devnetsbx-netacad-apicem-1.cisco.com/api/v1/flow-analysis"
ticket = get_ticket()
headers = {
    "content-type": "application/json",
    "X-Auth-Token": ticket
}

networkElementsInfo ={}
resp = requests.post(api_url, path, headers=headers, verify=False)
resp_json = resp.json()
flowAnalysisId = resp_json["response"]["flowAnalysisId"]
print("FLOW ANALYSIS ID: ", flowAnalysisId)
check_url = api_url + "/" + flowAnalysisId
# initialize variable to hold the status of the path trace
status = ""
checks = 1  # variable to increment within the while loop. Will trigger exit from loop after x iterations
while status != "COMPLETED":
    r = requests.get(check_url, headers=headers, verify=False)
    response_json = r.json()
    #+++++++++++Add Values+++++++++++++++
    status = response_json["response"]["request"]["status"] # Assign the value of the status of the path trace request from response_json
    #++++++++++++++++++++++++++++++++++++
    print("REQUEST STATUS: ", status)  # Print the status as the loop runs
    networkElementsInfo = response_json["response"]["networkElementsInfo"]
    # wait one second before trying again
    time.sleep(1)
    if checks == 15:  # number of iterations before exit of loop; change depending on conditions
        # break the execution
        raise Exception("Number of status checks exceeds limit. Possible problem with Path Trace.!")
    elif status == "FAILED":
        # break the execution
        raise Exception("Problem with Path Trace - FAILED!")
    checks += 1



# ***********************************************************************************************************

print_flow(networkElementsInfo)

