#!/usr/bin/env python

# requires python3

#ensure destpath exists and url, merged_folder_id, username and password are correct

#redhat: scl enable rh-python34 -- python3 /root/nessus_download_merge_and_upload.py
#debian: python3 /root/nessus_download_merge_and_upload.py

import requests, json, sys, os, getpass, time, shutil, ssl
import xml.etree.ElementTree as etree


from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from socket import error as SocketError
import errno

#=========DEBUG=========
#import logging
#logging.basicConfig(level=logging.DEBUG)
#
#import http.client
#
#http.client.HTTPConnection.debuglevel = 1
#
#logging.basicConfig()
#logging.getLogger().setLevel(logging.DEBUG)
#requests_log = logging.getLogger("requests.packages.urllib3")
#requests_log.setLevel(logging.DEBUG)
#requests_log.propagate = True
#=========END DEBUG===========


url = 'https://host:8834'
verify = False
token = ''
username = 'admin'
password = 'xxxxxx'
destpath = '/var/log/nessusscans/'
merged_folder_id = 682

def build_url(resource):
        return '{0}{1}'.format(url, resource)


def connect(method, resource, data=None):
        headers = {'X-Cookie': 'token={0}'.format(token), 'content-type': 'application/json'}
        data = json.dumps(data)
        if method == 'POST':
                r = requests.post(build_url(resource), data=data, headers=headers, verify=verify)
        elif method == 'PUT':
                r = requests.put(build_url(resource), data=data, headers=headers, verify=verify)
        elif method == 'DELETE':
                r = requests.delete(build_url(resource), data=data, headers=headers, verify=verify)
                return
        else:
                r = requests.get(build_url(resource), params=data, headers=headers, verify=verify)

        if r.status_code != 200:
                e = r.json()
                print('Connect: Error: {0}'.format(e['error']))
                sys.exit()

        if 'download' in resource:
                return r.content
        else:
                return r.json()

def login(usr, pwd):
        login = {'username': usr, 'password': pwd}
        data = connect('POST', '/session', data=login)
        return data['token']


def logout():
        connect('DELETE', '/session')

def list_scan():
        data = connect('GET', '/scans')
        return data

def count_scan(scans, folder_id):
        count = 0
        for scan in scans:
                if scan['folder_id']==folder_id: count=count+1
        return count

def print_scans(data):
        for folder in data['folders']:
                print("\\{0} - ({1})\\".format(folder['name'], count_scan(data['scans'], folder['id'])))
                for scan in data['scans']:
                        if scan['folder_id']==folder['id']:
                                print("\t\"{0}\" - uuid: {1}".format(scan['name'].encode('utf-8'), scan['uuid']))

def export_status(scan_id, file_id):
        data = connect('GET', '/scans/{0}/export/{1}/status'.format(scan_id, file_id))
        return data['status'] == 'ready'

def get_folder_id(serch_folder_name, data):
        folder_id = 0;
        for folder in data['folders']:
                if folder['name']==serch_folder_name:
                        folder_id = folder['id']
                        break
        return folder_id

def export_folder(folder_name, data):
        if folder_name == 'All' or folder_name == 'all':
                for scan in data['scans']:
                        file_id = export(scan['id'])
                        download(scan['name'], scan['id'], file_id,os.path.join(os.getcwd(),destpath))
        else:
                folder_id = get_folder_id(folder_name,data)
                if count_scan(data['scans'], folder_id)==0:
                        print("This folder does not contain reports")
                        return
                if folder_id!=0:
                        for scan in data['scans']:
                                if scan['folder_id'] == folder_id:
                                        file_id = export(scan['id'])
                                        download(scan['name'], scan['id'], file_id, os.path.join(os.getcwd(),destpath))
                else:
                        print("No such folder...")



def export(scan_id):
        data = {'format': 'nessus'}
        data = connect('POST', '/scans/{0}/export'.format(scan_id), data=data)
        file_id = data['file']
        while export_status(scan_id, file_id) is False:
                time.sleep(5)
        return file_id

def download(report_name, scan_id, file_id, save_path):
        if not(os.path.exists(save_path)): os.mkdir(save_path)
        data = connect('GET', '/scans/{0}/export/{1}/download'.format(scan_id, file_id))
        file_name = 'nessus_{0}_{1}.nessus'.format(report_name.encode('utf-8'), file_id)
        file_name = file_name.replace(' ', '_')
        file_name = file_name.replace("\'", "")
        print('Saving scan results to {0}'.format(file_name))
        with open(os.path.join(save_path,file_name), 'wb') as f:
                f.write(data)
        donefile = '{0}_done'.format(os.path.join(save_path,file_name))
        print('Data saved to {0}, writing {1}'.format(file_name, donefile))
        with open(donefile, 'wb') as fd:
                fd.write(bytes('', 'UTF-8'))
        print('Done-file written')

def merge():
        print('waiting for 60 seconds before merging and uploading.\n');
        for i in range(0,60):
                time.sleep(1)
                print('.', end='',flush=True)
        print('\nDone waiting.')
        first = 1
        for fileName in os.listdir(destpath):
                if ".nessus_processed" in fileName:
                        print(":: Parsing", fileName)
                        if first:
                                mainTree = etree.parse('{0}/{1}'.format(destpath,fileName))
                                report = mainTree.find('Report')
                                report.attrib['name'] = 'Merged Report'
                                first = 0
                        else:
                                tree = etree.parse('{0}/{1}'.format(destpath,fileName))
                                for element in tree.findall('.//ReportHost'):
                                        report.append(element)
                        print(":: => done.")

        if "nss_report" in os.listdir(destpath):
                shutil.rmtree('{0}/nss_report'.format(destpath))

        os.mkdir('{0}/nss_report'.format(destpath))
        mainTree.write('{0}/nss_report/report.nessus_merged'.format(destpath), encoding="utf-8", xml_declaration=True)

def upload(upload_file, count=0):
        """
        File uploads don't fit easily into the connect method so build the request
        here instead.
        """
        try:
                params = {'no_enc': 0}
                headers = {'X-Cookie': 'token={0}'.format(token)}

                filename = os.path.basename(upload_file)
                files = {'Filename': (filename, filename),
                        'Filedata': (filename, open(upload_file, 'r'))}

                print('Uploading file now.')
                r = requests.post(build_url('/file/upload'), params=params, files=files,
                      headers=headers, verify=verify)
                print('done')
                resp = r.json()

                print('{0} {1} {2}'.format(count, resp['fileuploaded'], r.status_code))
                if r.status_code != 200:
                        print('Upload: Error: {0}'.format(resp['error']))
                        if count < 5:
                                  count = count + 1
                                  print('ErrNot200: Retrying upload ({0}/5)'.format(count))
                                  time.sleep(5)
                                  return upload(upload_file, count)
                        else:
                                  print('Upload failed too often. Aborting.')
                                  sys.exit
                return resp['fileuploaded']
        except SocketError as e:
                if count < 5:
                          count = count + 1
                          print('SocketErr: Retrying upload ({0}/5) {1}'.format(count, e))
                          time.sleep(5)
                          return upload(upload_file, count)
                else:
                          print('Upload failed too often. Aborting.')
                          sys.exit

def import_scan(filename):
        im_file = {'file': filename, 'folder_id': merged_folder_id}

        print('Importing uploaded report {0} into Nessus'.format(filename))
        data = connect('POST', '/scans/import', data=im_file)
        print('Done')
        scan_name = data['scan']['name']
        print('Successfully imported the scan {0}.'.format(scan_name))

for the_file in os.listdir(destpath):
    file_path = os.path.join(destpath, the_file)
    if os.path.isfile(file_path):
        print("Deleting {0}".format(file_path))
        os.unlink(file_path)

print("Logging in...")
token = login(username, password)
print("List of reports...")
rep_list = list_scan()
print_scans(rep_list)
print("Exporting reports...")
export_folder('scans', rep_list)
merge()
#fn = upload('{0}/nss_report/report.nessus_merged'.format(destpath))
fn = upload(os.path.join(destpath, 'nss_report/report.nessus_merged'))
if fn != None:
       import_scan(fn)
logout()
