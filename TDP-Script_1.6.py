##################################
## Developed by TDP Team NCIIPC ##
##################################

#============== Configuration Start ==================#

path = '/home/nsac/FK-Important/TDP-Scripts/TDP/'#Location of the tdp.csv file to be saved
tdp_key = 'aVIwKR9Ntq0n0HrZImYzhjTZ80hkTCwgf8BHvtwX' #feed API key here
timestamp_conf = False # If you want to store last event fetched timestamp this should be True, In case of Hash this should be True
date_conf ="7d"   # This variable is only applicable for Ip, Domain and URL and is not applicable on Hash.
# Tags configuration
event_conf = {
    "All":False, 
    "A1":True,
    "A2":True,
    "B2":True,
    "B3":False,
    "C4":False
}
# IOC Type configuration
ioc_type_conf = {
    "All":True, #If this is True then all attributes will be fetched
    "ip-src":True,
    "md5":False,
    "sha256":True,
    "sha1":False,
    "url":False,
    "domain":True
}
# CSV Output File column configuration
csv_header_conf = {
    "EventDate":True,
    "EventID":True,
    "EventName": True,
    "IOCType":True,
    "IOC":True,
    "ThreatActor":True,
    "Tag":True
}
#============ Configuaration End =====================#


############################# Dont change the code Below ####################################################
from pymisp import ExpandedPyMISP
import json
import csv
import os
from datetime import datetime
class TDP():
    def __init__(self, event_conf,ioc_type_conf, csv_header_conf, tdp_key, path, date_conf, timestamp_conf):
        self.event_conf = event_conf
        self.ioc_type_conf = ioc_type_conf
        self.tdp_key = tdp_key
        self.path = path
        self.tdp_url = 'https://nsac.nciipc.gov.in'
        self.tdp_verifycert = True
        self.relative_path = 'events/restSearch'
        self.body = {
                "returnFormat": "json",
                "published":"1"
            }
        self.total_attribute_count = 0
        # if(self.ioc_type_conf['ip-src']==True or self.ioc_type_conf['domain']==True or self.ioc_type_conf['url']==True):
        #     self.body["date"] = date_conf
        self.body["date"] = date_conf #New line added
        self.total_event = 0
        self.csv_header_conf = csv_header_conf
        self.timestamp_conf = timestamp_conf
    def fk(self):
        if(timestamp_conf==True):
            timestamp_status = False    
            if(os.path.exists(path+'timestamp.txt')):
                timestamp_file = open(path+'timestamp.txt',"r")
                last_timestamp = timestamp_file.read()
                timestamp_file.close()
                timestamp_status = True
            #Filter using filter timestamp
            if(timestamp_status):
                self.body["publish_timestamp"] = last_timestamp
        

        #ioc type
        ioc_type = []
        if(self.ioc_type_conf['All']!=True):
            if(self.ioc_type_conf['ip-src']==True):
                ioc_type.append("ip-src")
            if(self.ioc_type_conf['url']==True):
                ioc_type.append("url")
            if(self.ioc_type_conf['domain']==True):
                ioc_type.append("domain")
            if(self.ioc_type_conf['md5']==True):
                ioc_type.append("md5")
            if(self.ioc_type_conf['sha256']==True):
                ioc_type.append("sha256")
            if(self.ioc_type_conf['sha1']==True):
                ioc_type.append("sha1")
            
            self.body["type"] = ioc_type
            # print(ioc_type)
        #Admirality score
        if(self.event_conf['All']!=True):
            if(self.event_conf['A1']==True):
                self.body["tags"] = {"AND":["admiralty-scale:source-reliability=\"a\"","admiralty-scale:information-credibility=\"1\""]}
                self.connect()
            if(self.event_conf['A2']==True):
                self.body["tags"] = {"AND":["admiralty-scale:source-reliability=\"a\"","admiralty-scale:information-credibility=\"2\""]}
                self.connect()
            if(self.event_conf['B2']==True):
                self.body["tags"] = {"AND":["admiralty-scale:source-reliability=\"b\"","admiralty-scale:information-credibility=\"2\""]}
                self.connect()
            if(self.event_conf['B3']==True):
                self.body["tags"] = {"AND":["admiralty-scale:source-reliability=\"b\"","admiralty-scale:information-credibility=\"3\""]}
                self.connect()
            if(self.event_conf['C4']==True):
                self.body["tags"] = {"AND":["admiralty-scale:source-reliability=\"c\"","admiralty-scale:information-credibility=\"4\""]}
                self.connect()
        else:
            self.connect()
        if(self.total_event>0):
            print("Successfully {} events fetched".format(self.total_event))
            print("Total attribute fetched - {} ".format(self.total_attribute_count))
            self.file_name.close()
        else:
            print("No new events")
    def connect(self):
        #print("FKK")
        try:
            misp = ExpandedPyMISP(self.tdp_url, self.tdp_key, self.tdp_verifycert)
            print("Body configuration {}".format(self.body))
            result = misp.direct_call(self.relative_path, self.body)
        except Exception as e:
            print("Connection Error, please contact TDP Team")
            print(e)
            exit()

        event_count = len(result)

        if (event_count > 0):
            try:
                if(self.total_event==0 and event_count>0):#Open tdp.csv only 1 time
                    csv_header = []
                    for key,value in self.csv_header_conf.items():
                        if(value==True):
                            csv_header.append(key)  
                    self.file_name = open(self.path+'tdp.csv', mode='w+')                    
                    self.writer = csv.writer(self.file_name, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                    self.writer.writerow(csv_header)
                latest_publish_timestamp = 0
                for events in result:
                    attribute_count = (len(events['Event']['Attribute']))
                    self.total_attribute_count = self.total_attribute_count + attribute_count
                    event_publish_timestamp = int(events['Event']['publish_timestamp'])
                    if(event_publish_timestamp > latest_publish_timestamp):
                        latest_publish_timestamp = event_publish_timestamp
                    event_id = events['Event']['id']
                    event_info = events['Event']['info']
                    event_date = events['Event']['date']
                    csv_event_data = []
                    if(self.csv_header_conf['EventDate']==True):
                        csv_event_data.append(event_date)
                    if(self.csv_header_conf['EventID']==True):
                        csv_event_data.append(event_id)
                    if(self.csv_header_conf['EventName']==True):
                        csv_event_data.append(event_info)        
                    
                    print(event_id +" " + str(event_info)+" Attribute Count - "+ str(attribute_count)) 
                    #print(self.ioc_type_conf)
                    for attribute in events['Event']['Attribute']:
                        #Commented on 05-12-22 Because only feching requested ioc type
                        # skip_loop = 0 
                        # if(ioc_type_conf['All']!=True):
                        #     if(self.ioc_type_conf[attribute['type']]==False):
                        #         skip_loop = 1 # To eleminate ioc types that are not requested
                        # if(skip_loop==1):#Found if result contain IOC types that are not requested 
                        #     print("Skiping loop")
                        #     print(attribute['type'])
                        #     continue
                            
                        csv_attribute_data = []
                        attribute_value = attribute['value']
                        attribute_type = attribute['type']
                        attribute_comment = attribute['comment']
                        tag = list()
                        if "Tag" in attribute: #To remove Tag error
                           for tags in attribute['Tag'] : 
                               tag.append(tags['name'])
                           tag = ",".join(tag)
                        if(self.csv_header_conf['IOCType']==True):
                            csv_attribute_data.append(attribute_type)
                        if(self.csv_header_conf['IOC']==True):
                            csv_attribute_data.append(attribute_value)
                        if(self.csv_header_conf['ThreatActor']==True):
                            csv_attribute_data.append(attribute_comment)
                        if(self.csv_header_conf['Tag']==True):
                            csv_attribute_data.append(tag)
                        csv_final_data = csv_event_data+csv_attribute_data
                        self.writer.writerow(csv_final_data)

                #last fetched data point
                if(timestamp_conf==True):
                    timestamp_file = open(path+'timestamp.txt',"w")
                    timestamp_file.write(str(int(latest_publish_timestamp)+1))
                    timestamp_file.close()
                #print("Last published timestamp is - {}".format(latest_publish_timestamp))
                #print("Successfully {} events fetched from this call".format(event_count))
                self.total_event = self.total_event + event_count
                # return total_event
            except Exception as e:
                print("Data Error, please contact TDP Team")
                print(e)
                exit()
        else:
            pass
call = TDP(event_conf, ioc_type_conf, csv_header_conf, tdp_key, path, date_conf, timestamp_conf)  
call.fk()          