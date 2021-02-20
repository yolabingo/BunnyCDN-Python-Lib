
import os
import requests
from requests.exceptions import HTTPError



class CDN():
    #initializer function
    def __init__(self,api_key):
        
        '''
        Parameters
        ----------
        api_key     : String
                      BunnyCDN account api key
        
        '''
        assert api_key !='',"api_key for the account must be specified"
        self.headers={
            'AccessKey':api_key,
            'Content-Type':'application/json',
            'Accept':'application/json'
        }
        self.base_url="https://bunnycdn.com/api/"

    def _Geturl(self,Task_name):
        '''
        This function is helper for the other methods in code to create appropriate url.

        '''
        if Task_name[0]=='/':
            if Task_name[-1]=='/':
                url=self.base_url + Task_name[1:-1]
            else:
                url=self.base_url + Task_name[1:]
        else:
            url=self.base_url + Task_name
        return url
    

    def AddCertificate(self,PullZoneId,Hostname,Certificate,CertificateKey):
        '''
        This function adds custom certificate to the given pullzone

        Parameters
        ----------
        PullZoneId          : int64
                              The ID of the Pull Zone to which the certificate will be added.
        
        Hostname            : string
                              The hostname to which the certificate belongs to.
        
        Certificate         : string
                              A base64 encoded binary certificate file data
                              Value must be of format 'base64'
       
        CertificateKey      : string
                              A base64 encoded binary certificate key file data
                              Value must be of format 'base64'
        '''
        values ={
            "PullZoneId": PullZoneId,
            "Hostname": Hostname,
            "Certificate": Certificate,
            "CertificateKey": CertificateKey
        }

        try:
            response=requests.post(self._Geturl('pullzone/addCertificate'),data=values,headers=self.headers)
            response.raise_for_status()
        except HTTPError as http:
            print(f'HTTP Error occured:{http}')
        except Exception as err:
            print(f'Error occured:{err}')
        else:
            print(f'Certificated Added successfully to PullZoneId:{PullZoneId},Hostname:{Hostname}')
    
    def AddBlockedIp(self,PullZoneId,BlockedIp):
        '''
        This method adds an IP to the list of blocked IPs that are not allowed to access the zone.
        
        Parameters
        ----------
        PullZoneId      : int64
                          The ID of the Pull Zone to which the IP block will be added.
        BlockedIP       : string
                          The IP address that will be blocked
        '''
        values={
            "PullZoneId": PullZoneId,
            "BlockedIp": BlockedIp
        }

        try :
            response=requests.post(self._Geturl('pullzone/addBlockedIp'),data=values,headers=self.headers)
            response.raise_for_status()
        except HTTPError as http:
            print(f'HTTP Error occured : {http}')
        except Exception as err:
            print(f'Error occured :{err}')
        else:
            print(f"Ip successfully added to list of blocked IPs for pullzone id: {PullZoneId}")
        
    def RemoveBlockedIp(self,PullZoneId,BlockedIp):
        '''
        This method removes mentioned IP from the list of blocked IPs that are not allowed to access the zone.
        
        Parameters
        ----------
        PullZoneId      : int64
                          The ID of the Pull Zone to which the IP block will be added.
        BlockedIP       : string
                          The IP address that will be blocked
        '''
        values={
            "PullZoneId":PullZoneId,
            "BlockedIp": BlockedIp
        }

        try :
            response=requests.post(self._Geturl('pullzone/removeBlockedIp'),data=values,headers=self.headers)
            response.raise_for_status()
        except HTTPError as http:
            print(f'HTTP Error occured : {http}')
        except Exception as err:
            print(f'Error occured :{err}')
        else:
            print(f"Ip successfully removed from list of blocked IPs for pullzone id: {PullZoneId}")
    
    def StorageZoneData(self):
        '''
        This function returns a list of details of each storage zones in user's account

        '''
        try :
            response=requests.get(self._Geturl('storagezone'),headers=self.headers)
            response.raise_for_status()
        except HTTPError as http:
            print(f'HTTP Error occured : {http}')
        except Exception as err:
            print(f'Error occured :{err}')
        else:

            storage_summary=[]
            for storagezone in response.json():
                storage_zone_details={}
                storage_zone_details['Id']=storagezone['Id']
                storage_zone_details['Storage_Zone_Name']=storagezone['Name']
                storage_zone_details['Storage_used']=storagezone['StorageUsed']
                hostnames=[]
                pullzone=[]
                for data in storagezone['PullZones']: 
                    pullzone.append(data['Name'])
                    for host_name in data['Hostnames']:
                        hostnames.append(host_name['Value'])
                storage_zone_details['host_names']=hostnames
                storage_zone_details['PullZones']=pullzone
                storage_summary.append(storage_zone_details)
            return storage_summary

    def StorageZoneList(self):
        '''
        This function returns list of dictionaries containing storage zone name and storage zone id 
        '''
        try :
            response=requests.get(self._Geturl('storagezone'),headers=self.headers)
            response.raise_for_status()
        except HTTPError as http:
            print(f'HTTP Error occured : {http}')
        except Exception as err:
            print(f'Error occured :{err}')
        else:

            storage_list=[]
            for storagezone in response.json():
                storage_list.append({storagezone['Name']:storagezone['Id']})
               
            return storage_list
    def AddStorageZone(self,storage_zone_name,storage_zone_region='DE',ReplicationRegions=['DE']):
        '''
        This method creates a new storage zone

        Parameters
        ----------
        storage_zone_name        : string
                                   The name of the storage zone
        
        storage_zone_region      : String 
        (optional)                 The main region code of storage zone
        
        ReplicationsRegions      : array
        (optional)                 The list of active replication regions for the zone

        '''
        values ={
            'Name':storage_zone_name,
            'Region':storage_zone_region,
            'ReplicationRegions':ReplicationRegions
        }
        try :
            response=requests.post(self._Geturl('storagezone'),data=values,headers=self.headers)
            response.raise_for_status()
        except HTTPError as http:
            print(f'HTTP Error occured : {http}')
        except Exception as err:
            print(f'Error occured :{err}')
        else:
            print(f"Successfully created new Storage Zone:{storage_zone_name}")



           


                
               



        


        
        

                              


