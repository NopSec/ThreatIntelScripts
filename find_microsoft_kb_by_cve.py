import requests
import datetime
import json

base_url = "https://api.msrc.microsoft.com/"
api_key = "Your API Key here"

#Find the cvrf_id (in the form YYYY-Month) given the CVE of interest
def get_cvrf_id_for_cve(cve):
    url = "{}Updates('{}')?api-version={}".format(base_url, str(cve),   str(datetime.datetime.now().year))
    headers = {'api-key': api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = json.loads(response.content)
        id = data["value"][0]["ID"]
    else:
        id = None
    return id

#get the cvrf data and extract kd's for the CVE of interest
def get_knowledge_bases_for_cve(cve):
    id = get_cvrf_id_for_cve(cve)
    if id == None:
        return []
    url = "{}cvrf/{}?api-Version={}".format(base_url, id,   str(datetime.datetime.now().year))
    headers = {'api-key': api_key, 'Accept': 'application/json'}
    response = requests.get(url, headers = headers)
    data = json.loads(response.content)
    kbs = {'KB{}'.format(kb['Description']['Value']) for vuln in data["Vulnerability"] if vuln["CVE"] == cve for kb in vuln["Remediations"]}
    return kbs

eternal_blue = 'CVE-2017-0143'
eternal_blue_kbs = get_knowledge_bases_for_cve(eternal_blue)
print(eternal_blue_kbs)
