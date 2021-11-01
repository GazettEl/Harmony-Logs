import csv
import time
import csv
import grequests
#import requests

def reader_csv():
    with open('files/url_Filtering_IoC.csv') as file_csv:
        reader = csv.reader(file_csv)
        data = list(reader)
    return data[1:]

def read_api_key():
    with open("api.txt") as file:
        api_keys = file.readlines()
        api_keys = [line.rstrip() for line in api_keys]
    return api_keys

def get_domains(data):
    domains = []
    for domain in range(0,len(data)):
        domains.append(data[domain][0])
    domains = list(dict.fromkeys(domains))
    return domains

def v_domain(api_list,domains):
    fields = ['Domain', 'Category', 'Result', 'Method', 'Engine name']
    data = []
    for api in api_list:
        count_request = 0
        headers = {"x-apikey":api}
        while count_request < 4:
            responses = (grequests.get("https://www.virustotal.com/api/v3/domains/{}".format(domain) , headers=headers) for domain in domains[0:4])
            responses = grequests.map(responses,size=10)

            for response in responses:
                response_json = response.json()
                security_vendor = list(response_json["data"]["attributes"]["last_analysis_results"].keys())
                fields = ['Domain', 'Category', 'Result', 'Method', 'Engine name']
                data = []
                
                for vendor in security_vendor:
                    if response_json["data"]["attributes"]["last_analysis_stats"]["malicious"] != 0:
                        if response_json["data"]["attributes"]["last_analysis_results"][vendor]["result"] != "clean" and response_json["data"]["attributes"]["last_analysis_results"][vendor]["result"] != "unrated":
                            security_vendor_result = [
                                "URL", 
                                "{}".format(response_json["data"]["attributes"]["last_analysis_results"][vendor]["category"]),
                                "{}".format(response_json["data"]["attributes"]["last_analysis_results"][vendor]["category"]),
                                "{}".format(response_json["data"]["attributes"]["last_analysis_results"][vendor]["method"]),
                                "{}".format(response_json["data"]["attributes"]["last_analysis_results"][vendor]["engine_name"])
                                ]
                            data.append(security_vendor_result)

                text = [
                    ["","","",""],
                    ["","{}".format(responses.url.replace("https://www.virustotal.com/api/v3/domains/","")),"4/88"],
                    ["Category","Result","Method","Engine"]
                    ]

                
            count_request += 1
        del domains[0:4]

    print(len(data))

    with open('GFG.csv', 'w') as f:
        write = csv.writer(f)
        write.writerow(fields)
        write.writerows(data)

def main():
    data = reader_csv()
    for i in data:
        if "ena" in i:
            print(i[0])
    domains = get_domains(data)
    api_list = read_api_key()

    
    domains = domains[0:8]
        
    #v_domain(api_list,domains)

if __name__ == "__main__":
    main()