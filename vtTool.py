import requests 
import csv
import pyfiglet
import getpass

ascii_art = pyfiglet.figlet_format("VirusToal Bulk Uploader")
print("\033[1;32m" + ascii_art + "\033[0m")
print("\033[1;36m{:>10}\033[0m : {}".format("Author", "Julian Moodie"))


apikey = getpass.getpass("Enter Api Key: ")

print("enter file name")
fileName = input()

print("hash, ip or domain...")
var = input()

if var == "hash":
    try:
        with open(fileName, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
    except:
        print("Error reading file")
        exit()
        for row in reader:
            target = row['target'].strip()
            url = f'https://www.virustotal.com/api/v3/files/{target}'

            headers = {'x-apikey': apikey}
            response = requests.get(url, headers=headers)
            if response.status_code != 200:
                print("Network Error or quota exceeded https://docs.virustotal.com/docs/higher-quota")
                break
            else:
                data = response.json()['data']['attributes']
                stats = data['last_analysis_stats']
                if stats['malicious'] > 0:
                    print(f"{target} => Malicious: {stats['malicious']} Vendors")
                    check = True
                if stats['suspicious'] > 0:
                    if check == True:
                        None
                else:
                    print(f"{target} => suspicious: {stats['suspicious']} Vendors")

    pass

if var == "ip":
    try:
        with open(fileName, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
    except:
        print("Error reading file")
        exit()
        for row in reader:
            target = row['target'].strip()
            url = f'https://www.virustotal.com/api/v3/ip_addresses/{target}'

            headers = {'x-apikey': apikey}
            response = requests.get(url, headers=headers)
            if response.status_code != 200:
                print("Network Error or quota exceeded https://docs.virustotal.com/docs/higher-quota")
                break
            else:
                data = response.json()['data']['attributes']
                print(data)
                stats = data['last_analysis_stats']
                if stats['malicious'] > 0:
                    print(f"{target} => Malicious: {stats['malicious']} Vendors")
                    check = True
                if stats['suspicious'] > 0:
                    if check == True:
                        None
                else:
                    print(f"{target} => suspicious: {stats['suspicious']} Vendors")


else:
    pass

if var == "domain":
    try:
        with open(fileName, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
    except:
        print("Error reading file")
        exit()
        for row in reader:
            target = row['target'].strip()
            url = f'https://www.virustotal.com/api/v3/domains/{target}'

            headers = {'x-apikey': apikey}
            response = requests.get(url, headers=headers)
            if response.status_code != 200:
                print("Network Error or quota exceeded https://docs.virustotal.com/docs/higher-quota")
                break
            else:
                data = response.json()['data']['attributes']
                stats = data['last_analysis_stats']
                if stats['malicious'] > 0:
                    print(f"{target} => Malicious: {stats['malicious']} Vendors")
                    check = True
                if stats['suspicious'] > 0:
                    if check == True:
                        None
                else:
                    print(f"{target} => suspicious: {stats['suspicious']} Vendors")
