from csv import reader
from sys import exit
from signal import signal, SIGINT
from os import getcwd, makedirs, path
from collections import Counter
from urllib.parse import urlparse

#function for exit of the program
def def_handler(key,frame):
    print("\n[*] Exit")
    exit(1)

#funciton for read csv
def reader_csv():
    events = []
    with open("logs.csv") as csvfile:
        reader_c = reader(csvfile)
        for row in reader_c:
            events.append(row)
    return events

def remove_columns_empty(events):
    for colum in range(0,len(events[0])):            
        column = []
        for event in range(160,len(events)):
            try: 
                if events[event][colum] != "" or events[event][colum] != " ":
                    column.append(events[event][colum])
            except:
                pass
        if len(column) >= 0 and len(column) <= 5:
            if column == []:
                print("COLUMNS {}, {}, EMPTY: {}".format(colum,events[0][colum],column))        

#function for write in to the csv
def write_csv(event,name):
    line_polluted = "{}\n".format(event)
    line_cleaning = str(line_polluted).replace("'", '').replace("[", '').replace("]", '')
    newpath = "{}/files".format(getcwd())
    if not path.exists(newpath):
        makedirs(newpath)
    with open("{}/{}.csv".format(newpath,name), 'a') as the_file:
       the_file.write(line_cleaning)

def create_txt(event,name):
    newpath = "{}/files".format(getcwd())
    if not path.exists(newpath):
        makedirs(newpath)
    with open("{}/{}.txt".format(newpath,name), 'a') as the_file:
        the_file.write(event)

def events_sumarize(events):
    name = "event_high"
    index_severity = events[0].index("Severity")
    events_total_num = len(events)-1
    events_critical, events_high, events_medium, events_low, events_informational, events_empty = 0, 0, 0, 0, 0, 0
    events_id = []
    for event in range(0,len(events)):
    #for event in range(0,5):
        if events[event][index_severity] == "Critical":            
            critical = [event,events[event][index_severity]]
            events_id.append(critical)
            events_critical += 1
        elif events[event][index_severity] == "High":
            high = [event,events[event][index_severity]]
            events_id.append(high)
            events_high += 1
        elif events[event][index_severity] == "Medium":
            medium = [event,events[event][index_severity]]
            events_id.append(medium)
            events_medium += 1
        elif events[event][events[0].index("Severity")] == "Low":
            events_low += 1
        elif events[event][events[0].index("Severity")] == "Informational":
            events_informational += 1
        elif events[event][events[0].index("Severity")] == "":
            events_empty += 1
    total = events_critical+events_high+events_medium+events_low+events_informational+events_empty
    text = ["Total","Critical","High","Medium","Low","Informational","Suma"]
    event_all = [events_total_num,events_critical,events_high,events_medium,events_low,events_empty,total]    
    write_csv(text,name)
    write_csv(event_all,name)
    return events_id

def machines(events,events_severity):
    machines_list_disorderly, machines_list_order = [], []
    index_machine_name = events[0].index("Machine Name")
    
    for event in range(0,len(events_severity)):
        #if len(events[event][index_machine_name]) != 0 and len(events[event][index_machine_name]) != 1:
        if True:
            machines_list_order.append(events[event][index_machine_name])
            machines_list_disorderly.append([events_severity[event][0],events[event][index_machine_name]])
    
    machines_list_order = Counter.most_common(Counter(machines_list_order))

    name = "machine_attacks"
    write_csv(["Machine","Quantity"],name)
    for row in range(0,len(machines_list_order)):
        write_csv("{}".format(machines_list_order[row]).replace("(","").replace(")",""),name)
    return machines_list_disorderly, machines_list_order

def machines_severity(events,machines_list_disorderly, machines_list_order, events_severity):
    index_severity = events[0].index("Severity")
    machines_list, result = [], []
    
    for machine in range(0,len(machines_list_disorderly)):
        machines_list.append([
                            "{}".format(events_severity[machine][1]),
                            "{}".format(machines_list_disorderly[machine][1])
                            ])

    for machine in machines_list_order:        
        critical, high, medium = 0, 0, 0
        for num_machine in range(0,len(machines_list_order)):
            if machine[0] in machines_list_order[num_machine][0]:
                if "Critical" in machines_list[num_machine][0]:
                    critical += 1
                elif "High" in machines_list[num_machine][0]:
                    high += 1
                elif "Medium" in machines_list[num_machine][0]:
                    medium += 1
        result.append([machine,critical,high,medium])
    #print(result[0])
        

#Modificar funcion y realizarla mejor
def users_not_running_blades(events):
    details = events[0].index("check_details")
    machine = events[0].index("Machine Name")
    data = []

    for event in range(0,len(events)):       
        try:
            if "Not running blades" in events[event][details]:
                data.append([events[event][machine],events[event][details]])
        except:
            pass

    name = "not_running_blade"
    write_csv(["Machine","Blade"],name)

    for row in range(0,len(data)):
        write_csv("{},{}".format(data[row ][0], data[row][1].replace(",","")),name)

def log_blade(events,events_severity):    
    blade_index = events[0].index("Blade")
    blades = ["Anti-Bot","Anti-Malware","Endpoint Compliance","Firewall","SmartEvent Client","System Monitor","Threat Extraction","URL Filtering"]
    url_Filtering, threat_Extraction, system_Monitor, smartEvent_Client, firewall, endpoint_Compliance, anti_Malware, anti_Bot = [], [], [], [], [], [], [], []
    for blade in blades:
        for i in range(0,len(events_severity)):
            if events[events_severity[i][0]][blade_index] == blade:
                if blade == blades[7]:
                    url_Filtering.append(events_severity[i][0])
                elif blade == blades[6]:
                    threat_Extraction.append(events_severity[i][0])
                elif blade == blades[5]:
                    system_Monitor.append(events_severity[i][0])
                elif blade == blades[4]:
                    smartEvent_Client.append(events_severity[i][0])
                elif blade == blades[3]:
                    firewall.append(events_severity[i][0])
                elif blade == blades[2]:
                    endpoint_Compliance.append(events_severity[i][0])
                elif blade == blades[1]:
                    anti_Malware.append(events_severity[i][0])
                elif blade == blades[0]:
                    anti_Bot.append(events_severity[i][0])
    return url_Filtering, threat_Extraction, system_Monitor, smartEvent_Client, firewall, endpoint_Compliance, anti_Malware, anti_Bot

def url_Filtering_filter(events,url_Filtering):
    event_all = []
    for i in range(0,len(url_Filtering)):
        event = [ url_Filtering[i],
                events[url_Filtering[i]][events[0].index("Application Name")],
                events[url_Filtering[i]][events[0].index("Application Category")].replace(","," "),
                events[url_Filtering[i]][events[0].index("Resource")]
            ]
        event_all.append(event)
        
    def app_category(app_category_list):
        text = []
        num = []
        suma = 0

        for i in range(0,len(event_all)):
            app_category_list.append(event_all[i][2])
            
        app_category_list = Counter.most_common(Counter(app_category_list))

        for i in range(0,len(app_category_list)):
            text.append(app_category_list[i][0])
            num.append(app_category_list[i][1])

        for i in range(0,len(num)):
            suma += num[i]
            
        text.append("Total")
        num.append(suma)
        return text, num
    
    def application_name(app_category_list):
        for i in range(0,len(event_all)):
            application_name_list.append([event_all[i][1],event_all[i][3]])
        return application_name_list

    app_category_list = []
    text, num = app_category(app_category_list)

    name = "url_Filtering_category"
    write_csv(text,name)
    write_csv(num,name)
    
    application_name_list = []
    application_name_list = application_name(app_category_list)

    name = "url_Filtering_IoC"
    write_csv(["Application Name","Resource"],name)
    for i in range(0,len(application_name_list)):
        write_csv(application_name_list[i],name)

def threat_Extraction_filter(events,threat_Extraction):
    event_all = []
    for i in range(0,len(threat_Extraction)):
        event = [ threat_Extraction[i],
                events[threat_Extraction[i]][events[0].index("File Type")],
                events[threat_Extraction[i]][events[0].index("Protection Type")],
                events[threat_Extraction[i]][events[0].index("Protection Name")],
                events[threat_Extraction[i]][events[0].index("Malware Action")],
                events[threat_Extraction[i]][events[0].index("Resource")]]
        event_all.append(event)

    def count_potentially_malicious(potentially_malicious_content_list):
        for i in range(0,len(event_all)):
            if event_all[i][3] == "Potential malicious content extracted":
                potentially_malicious_content_list.append(event_all[i][3])
                potentially_malicious_content_list.append(event_all[i][4])
        potentially_malicious_content_list = Counter.most_common(Counter(potentially_malicious_content_list))
        return potentially_malicious_content_list
    
    def effectiveness(threat_result):
        result = (threat_result[0][1]/threat_result[1][1]) * 100
        return result

    def source_events(event_all):
        domains = []
        for i in range(0,len(event_all)):
            domain = urlparse(event_all[i][-1]).netloc
            domains.append(domain)
        domains = Counter.most_common(Counter(domains))
        return domains[1:-1]
    
    potentially_malicious_content_list = []
    
    threat_result = count_potentially_malicious(potentially_malicious_content_list)
    effectiveness = effectiveness(threat_result)

    name = "threat_Extraction_effectiveness"
    content = "{},{},Effectiveness".format(threat_result[0][0],threat_result[1][0])
    write_csv(content,name)
    content = "{},{},{}".format(threat_result[1][1],threat_result[1][1],effectiveness)
    write_csv(content,name)

    source = source_events(event_all)

    name = "threat_Extraction_IoC"
    write_csv(["Resource","Quantity"],name)
    for i in range(0,len(source)):
        write_csv("{}".format(source[i]).replace("(","").replace(")",""),name)

def system_Monitor_filter(events,system_Monitor):
    event_all = []
    for i in range(0,len(system_Monitor)):
        event = [ system_Monitor[i],
                events[system_Monitor[i]][events[0].index("Log ID")],
                events[system_Monitor[i]][events[0].index("Sensor Alert Solution")],
                events[system_Monitor[i]][events[0].index("Sensor Test Name")],
                events[system_Monitor[i]][events[0].index("sensor_alert_blade")],
                events[system_Monitor[i]][events[0].index("Sensor Alert Category")],
                events[system_Monitor[i]][events[0].index("Sensor Alert Type")],
                events[system_Monitor[i]][events[0].index("Sensor Alert Source")],
                events[system_Monitor[i]][events[0].index("Sensor Alert Message")],
                events[system_Monitor[i]][events[0].index("Sensor Alert ID")],
                events[system_Monitor[i]][events[0].index("Sensor Alert Duration")]]
        event_all.append(event)

    def monitor_logs():
        name = "system_monitor"
        for i in range(0,len(event_all)):
            event = """Log ID: {}
Sensor Alert Solution: {}
Sensor Test Name: {}
sensor_alert_blade: {}
Sensor Alert Category: {}
Sensor Alert Type: {}
Sensor Alert Source: {}
Sensor Alert Message: {}
Sensor Alert ID: {}
Sensor Alert Duration: {}
            \n""".format(event_all[i][1],event_all[i][2],event_all[i][3],event_all[i][4],event_all[i][5],event_all[i][6],event_all[i][7],event_all[i][8],event_all[i][9],event_all[i][10])
            
            newpath = "{}/files".format(getcwd())
            if not path.exists(newpath):
                makedirs(newpath)
            with open("{}/{}.txt".format(newpath,name), 'a') as the_file:
                the_file.write(event)

        #the_file.close()
    
    monitor_logs()

def firewall_filter(events,firewall):
    event_all = []
    for i in range(0,len(firewall)):
        event = [ firewall[i],
                events[firewall[i]][events[0].index("Description")],
                events[firewall[i]][events[0].index("Reason")],
                events[firewall[i]][events[0].index("failure_impact")]]
        event_all.append(event)
    
    def firewall_logs():
        name = "firewall_logs"
        for i in range(0,len(event_all)):
            event = """Description: {}
Reason: {}
Failure impact: {}
            \n""".format(event_all[i][1],event_all[i][2],event_all[i][3])
            
            create_txt(event,name)
    
    firewall_logs()

def endpoint_Compliance_filter(events,endpoint_Compliance):
    event_all = []
    for i in range(0,len(endpoint_Compliance)):
        event = [ endpoint_Compliance[i],
                events[endpoint_Compliance[i]][events[0].index("Machine Name")],
                events[endpoint_Compliance[i]][events[0].index("Action")]]
                #events[endpoint_Compliance[i]][events[0].index("check_type")],
                #events[endpoint_Compliance[i]][events[0].index("check_requirement")],
                #events[endpoint_Compliance[i]][events[0].index("check_details")],
                #events[endpoint_Compliance[i]][events[0].index("check_name")]]
        event_all.append(event)

def anti_Malware_filter(events):
    infection_category = events[0].index("Infection Category")
    event_all = []
    
    for event in range(1,len(events)):
        try:
            if "" != events[event][infection_category]:
                event_all.append([
                event+1, 
                events[event][events[0].index("Incident ID")],
                events[event][events[0].index("Blade")],
                events[event][events[0].index("Severity")],
                events[event][events[0].index("Machine Name")],
                events[event][events[0].index("Infection Category")],
                events[event][events[0].index("Protection Name")],
                events[event][events[0].index("Action")],
                events[event][events[0].index("File Name")]
                ])
        except:
            pass

    def anti_malware_logs(event_all):
        name = "antimalware_logs"
        for i in range(0,len(event_all)):
            event = """------------Incident ID {}------------
Blade: {} Severity {}
Machine Name: {}
Infection Category: {}
Protection Name: {}
Action: {}
File Name: {}\n""".format(event_all[i][1],event_all[i][2],event_all[i][3],event_all[i][4],event_all[i][5],event_all[i][6],event_all[i][7],event_all[i][8])
            create_txt(event,name)

    anti_malware_logs(event_all)
    

def anti_Bot_filter(events,anti_Bot):
    event_all = []
    for i in range(0,len(anti_Bot)):
        event = [ anti_Bot[i],
                events[anti_Bot[i]][events[0].index("Description")],
                events[anti_Bot[i]][events[0].index("File MD5")],
                events[anti_Bot[i]][events[0].index("File Type")],
                events[anti_Bot[i]][events[0].index("File Name")],
                events[anti_Bot[i]][events[0].index("Protection Type")],
                events[anti_Bot[i]][events[0].index("Protection Name")],
                events[anti_Bot[i]][events[0].index("Malware Action")],
                events[anti_Bot[i]][events[0].index("Destination")],
                events[anti_Bot[i]][events[0].index("Last Detection")],
                events[anti_Bot[i]][events[0].index("Proxied Source IP")],
                events[anti_Bot[i]][events[0].index("Destination Country")],
                events[anti_Bot[i]][events[0].index("First Detection")],
                events[anti_Bot[i]][events[0].index("Resource")]]
        event_all.append(event)

    def anti_Bot_logs():
        name = "anti_Bot"
        for i in range(0,len(event_all)):
            event = """Description: {}
File MD5: {}
File Type: {}
File Name: {}
Protection Type: {}
Protection Name: {}
Malware Action: {}
Destination: {}
Proxied Source IP: {}
Destination Country: {}
First Detection: {}
Resource: {}
            \n""".format(event_all[i][1],event_all[i][2],event_all[i][3],event_all[i][4],event_all[i][5],event_all[i][6],event_all[i][7],event_all[i][8],event_all[i][9],event_all[i][10],event_all[i][11],event_all[i][12])
            
            create_txt(event,name)    

    anti_Bot_logs()

#main flow
def main():
    #reads the csv file and passes it to an array
    events = reader_csv()

    #find colums empty
    #remove_columns_empty(events)

    #generate table for events by severity
    events_severity = events_sumarize(events)

    #machines 
    machines_list_disorderly, machines_list_order = machines(events,events_severity)

    #NOOOOOOOO SIRVE
    #machines_severity(events,machines_list_disorderly, machines_list_order, events_severity)    

    #machines with blades not runnig
    users_not_running_blades_all = users_not_running_blades(events)
    
    url_Filtering, threat_Extraction, system_Monitor, smartEvent_Client, firewall, endpoint_Compliance, anti_Malware, anti_Bot = log_blade(events,events_severity)

    #relevant url filtering events
    url_Filtering_filter(events,url_Filtering)

    #relevant threat extraction events
    threat_Extraction_filter(events,threat_Extraction)
    
    #relevant system monitor events    
    system_Monitor_filter(events,system_Monitor)
    
    #relevant system monitor events 
    #smartEvent_Client_filter(events,smartEvent_Client)

    #relevant firewall events
    firewall_filter(events,firewall)

    #relevant compliance events
    endpoint_Compliance_filter(events,endpoint_Compliance)

    #relevant antimalware events
    anti_Malware_filter(events)
    
    #relevant antimalware events
    anti_Bot_filter(events,anti_Bot)

    #relevant threat extraction events

if __name__ == "__main__":
    signal(SIGINT, def_handler)
    main()