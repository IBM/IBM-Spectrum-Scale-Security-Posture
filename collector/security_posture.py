# Copyright IBM Corp. 2016 All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from collections import OrderedDict
import datetime
import json
import os
import pdb
import subprocess 
import sys

import argparse

json_file = 'security_posture.json'
ndjson_file = 'security_posture.ndjson'
mmfs_path = '/usr/lpp/mmfs/bin'
mmfs_max_waittime = 60


def timestamp():
    try:
       today = datetime.datetime.now()
       # print('Timestamp: {:%Y-%m-%d %H:%M:%S}'.format(today))
    except Exception as e:
       print ("Failure in getting time:", e)
       return False
    return today.strftime("%Y-%m-%d %H:%M:%S")


def executeGPFSCommand(cmd):
    """ execute GPFS command
    input - cmd (command to be executed)

    return -
      result - if cmd succeeds, then return command result
      False - if cmd fails
    """

    if cmd.startswith("mm"):
        cmd = 'timeout ' + str(mmfs_max_waittime) + ' ' + mmfs_path + '/' + cmd
        # print(cmd)

    try:
        res = os.popen(cmd).read()
        res = res.strip()
    except Exception as e:
        print("failure in executing command {0}\n{1}".format(cmd, e))
        return False

    return res

#Function to get cluster details

def cluster():
    cluster_details = {}

    cluster_details['Cluster_Name'] = executeGPFSCommand("/usr/lpp/mmfs/bin/mmlscluster | grep 'GPFS cluster name' | awk '{print $4}'")
    cluster_details['Cluster_ID'] = executeGPFSCommand("/usr/lpp/mmfs/bin/mmlscluster | grep 'GPFS cluster id' | awk '{print $4}'")
    # cluster_details['timestamp'] = datetime.datetime.now()

    return cluster_details

#Function to get the NFS exports details
def mmnfs():
    data = []
    nfs = {}
    nfs['enc'] = {}
    nfs['nonenc'] = {}
    # nfs['total_no_exports'] = 0
    result = executeGPFSCommand('/usr/lpp/mmfs/bin/mmnfs export list -Y | cut -f7 -d: | tail -n +2')
    nfs_exports = result.splitlines()
    for e in nfs_exports:
        data.append(executeGPFSCommand('/usr/lpp/mmfs/bin/mmnfs export list -n {} -Y | tail -1 | cut -f7,16 -d:'.format(e)))
    for d in data:
        (exp, sec) = d.split(':')
        if 'krb5p' in sec.lower():
            nfs['enc'][exp] = sec.rstrip()
        else:
           nfs['nonenc'][exp] = sec.rstrip()
    nfs['total_no_exports'] = len(nfs['nonenc'].keys()) + len(nfs['enc'].keys())
    # print "NFS Shares :"
 #   print nfs

    return nfs

#Function to get SMB details
def mmsmb():
    try:
        smb = {}
        smb['enc'] = {}
        smb['nonenc'] = {}
        smb['may_be'] = {}
        abc = executeGPFSCommand('/usr/lpp/mmfs/bin/mmsmb export list -Y | cut -f7,11 -d: | tail -n +2')
        smbshare = abc.splitlines()
        for e in smbshare:
            (exp, sec) = e.split(':')
            if "mandatory" in sec.lower():
                smb['enc'][exp] = sec.rstrip()    
            # print smb['enc'][exp]
            elif "disabled" in sec.lower():
                smb['nonenc'][exp] = sec.rstrip()
            elif "auto" in sec.lower():
                smb['may_be'][exp] = sec.rstrip()
            
        smb['total_no_shares'] = len(smb['nonenc'].keys()) + len(smb['enc'].keys()) + len(smb['may_be'].keys())
    # print "SMB Shares :"
        # return smb
    except:
        print "mmsmb export list [E]: Cannot list any exports. There are no exports to show."   
    return smb


def mmsmb_export_info():
    """ populate smb export data 

        smb encryption can have 4 values - auto/default, mandatory, disabled, desired.
        mandatory enables data encryption for share, so will mark security = "yes"
        for rest values (auto/default, disabled, desired), will set security = "no"
    """

    smb_exports = []

    result = executeGPFSCommand('/usr/lpp/mmfs/bin/mmsmb export list -Y | cut -f7,8,11 -d: | tail -n +2')
    exports = result.splitlines()

    fs_mntpnt = get_fs_mntpnts()

    for export in exports:
        expdata = {}

        (exp, exp_path, sec) = export.split(':')

        expdata['fs'] = get_fs_of_path(fs_mntpnt, exp_path)
        expdata['FilesetMountPoint'] = exp
        expdata['security'] = 'no'
        if "mandatory" in sec.lower():
            expdata['security'] = 'yes'

        smb_exports.append(expdata)

    return smb_exports

#Function to get User Authentication details
def mmuserauth():
    auth = {}
    command1 = executeGPFSCommand('/usr/lpp/mmfs/bin/mmccr vget FILE_AUTH_TYPE')
    command2 = executeGPFSCommand('/usr/lpp/mmfs/bin/mmccr vget OBJECT_AUTH_TYPE')
    file_auth = command1.split(":")
    object_auth = command2.split(":")
    auth['file_auth'] = file_auth[-1].rstrip()
    auth['object_auth'] = object_auth[-1].rstrip()
    return auth

#Function to get Object expo details
def mmobject():
    obj = {}
    auth = mmuserauth()
    if auth['object_auth'] != 'none':
        ssl_value = executeGPFSCommand('/usr/lpp/mmfs/bin/mmuserauth service list --data-access-method object -Y  | grep ENABLE_KS_SSL | cut -f10 -d:')
    else:
        ssl_value = "False"
    # auth['object_auth'] = mmuserauth.object_auth[-1]
    obj['object_auth'] = auth['object_auth']
    obj['ssl_value'] = ssl_value
    return obj

#Function to get Cluster Communication details
def cluster_comm():
    fs1 = {}
    internode = executeGPFSCommand("/usr/lpp/mmfs/bin/mmlsconfig | grep cipherList | cut -f2 -d' '")
    if 'AUTHONLY' or 'EMPTY' in internode.rstrip():
        fs1['secure_communication'] = "False"
        fs1['value'] = internode.rstrip()
    else:
       fs1['secure_communication'] = "True"
       fs1['value'] = internode.rstrip()
    return fs1

#Function to get File System Details 
def mmfs():
    # fs1 = {}
    fs_enc = {}
    fs_enc['enc'] = {}
    fs_enc['nonenc'] = {}
    # mgmt_node_sec = {}
    # cluster_details = {}

    fs_name = executeGPFSCommand("/usr/lpp/mmfs/bin/mmlsmount all | cut -f3 -d' '")
    fs_name = fs_name.splitlines()
    # fs['total_no_fs']=len(fs_name)
    for fs in fs_name:
        cmd = "/usr/lpp/mmfs/bin/mmlsfs {} --encryption  -Y | tail -1 | cut -f9 -d:".format(fs)
        enc = executeGPFSCommand(cmd)
        if "yes" in enc:
            fs_enc["enc"][fs] = enc
        else:
            fs_enc["nonenc"][fs] = enc
        # fs_enc[fs] = enc
        # print dir(enc)
    # fs_enc['total_no_fs']=len(fs_enc[fs])
    mgmt_sec = executeGPFSCommand("/usr/lpp/mmfs/bin/mmlscluster | grep 'Remote shell command' | awk '{print $4}'")
    mgmt_scp = executeGPFSCommand("/usr/lpp/mmfs/bin/mmlscluster | grep 'Remote file copy' | awk '{print $5}'")
    # if 'ssh' in mgmt_sec and 'scp' in mgmt_scp:
    #    mgmt_node_sec['mgmt_secured'] = 'True'
    # else:
     #   mgmt_node_sec['mgmt_secured'] = 'False'

    return fs_enc


def cluster_mgmt():
    mgmt_node_sec = {}
    secure_administration = {}
    sslvalue = {}
    mgmt_sec = executeGPFSCommand("/usr/lpp/mmfs/bin/mmlscluster | grep 'Remote shell command' | awk '{print $4}'")
    mgmt_scp = executeGPFSCommand("/usr/lpp/mmfs/bin/mmlscluster | grep 'Remote file copy' | awk '{print $5}'")
    if 'ssh' in mgmt_sec and 'scp' in mgmt_scp:
        mgmt_node_sec['secure_communication'] = 'True'
        secure_administration['program'] = mgmt_sec.rstrip(), mgmt_scp.rstrip()
    else:
        mgmt_node_sec['secure_communication'] = 'False'
        secure_administration['program'] = mgmt_sec.rstrip(), mgmt_scp.rstrip()
    return mgmt_node_sec, secure_administration


# pdb.set_trace()
#Function to get GUI status
def gui():
    sslvalue = {}
    gui_node = executeGPFSCommand("/usr/lpp/mmfs/bin/mmlsnodeclass  -Y | grep GUI_MGMT_SERVERS | cut -f10 -d:")
    final_gui_node = gui_node.rstrip()
    if gui_node.rstrip() != "":
        curlcmd = 'curl -k -X INFO "https://localhost:443/scalemgmt/v2" -v --silent --stderr - | grep "SSL connection using"'
        ssh_node = os.popen("ssh {} '{}'".format(final_gui_node, curlcmd)).read()
        sslvalue['secure_communication'] = "True : " + ssh_node.split(" ")[-1]
    else:
        sslvalue['secure_communication'] = "GUI not configured"
    return sslvalue

#Function to get FAL status
def fal():
    fal = {}
    isfal_available = os.system('/usr/lpp/mmfs/bin/mmlsfs all --file-audit-log >/dev/null 2>/dev/null')
    if isfal_available != 0:
        return "FAL is not enabled."

    fs_fals = executeGPFSCommand('/usr/lpp/mmfs/bin/mmlsfs all --file-audit-log -Y | grep -v "mmlsfs::HEADER" | cut -f7,9 -d:')
    fs_fals = fs_fals.splitlines()
    for fs_fal in fs_fals:
        (fs, falflag) = fs_fal.split(":")
        fal[fs] = falflag
   
    return fal 


def fsacl():
    fsacl = {}
    fs_acls = executeGPFSCommand('/usr/lpp/mmfs/bin/mmlsfs all -k -Y | grep -v "mmlsfs::HEADER" | cut -f7,9 -d:')
    # print fs_acls
    fs_acls = fs_acls.splitlines()
    for fs_acl in fs_acls:
        (fs, acl) = fs_acl.split(":")
        fsacl[fs] = acl
   
    return fsacl

#Function to get TCT status
def tct():
    # TCT = {}
    istct_available = os.system('/usr/lpp/mmfs/bin/mmcloudgateway containerpairset list >/dev/null 2>/dev/null')
    # mmcloudgateway returning non zero exit code - return "TCT not enabled"
    if istct_available != 0:
        return "TCT is not enabled."
    # mmcloudgateway zero exit code but without TCT class - here also returning "TCT not enabled"
    else:
        notctclass = executeGPFSCommand('/usr/lpp/mmfs/bin/mmcloudgateway containerpairset list 2>&1')
        notctclass = notctclass.splitlines()[-1]
        # print notctclass
        if notctclass == "mmcloudgateway: No TCT Cloud node classes were found.":
            return "TCT is not enabled."

    tct_command = executeGPFSCommand('/usr/lpp/mmfs/bin/mmcloudgateway containerpairset list -Y | cut -f25 -d :')
    tct_command = tct_command.splitlines()[-1]
    if tct_command in ('Disabled', 'Enabled'):
        return tct_command
    else:
        return 'Unknown'


def get_filesystem_data():
    """ get filesystem specific data for all gpfs filesystems """

    filesystem = []

    fs_names = executeGPFSCommand("/usr/lpp/mmfs/bin/mmlsmount all | cut -f3 -d' '")
    fs_names = fs_names.splitlines()
    for fs in fs_names:

        fsdata = {}

        # name
        fsdata['name'] = fs

        # secure_data_at_rest (enc|nonenc)
        cmd = "/usr/lpp/mmfs/bin/mmlsfs {} --encryption  -Y | tail -1 | cut -f9 -d:".format(fs)
        enc = executeGPFSCommand(cmd)
        if enc.lower() == "yes":
            fsdata['secure_data_at_rest'] = 'enc'
        elif enc.lower() == "no":
            fsdata['secure_data_at_rest'] = 'nonenc'

        # file audit logging (yes|no)
        fsdata['fal_status'] = False
        cmd = '/usr/lpp/mmfs/bin/mmlsfs {} --file-audit-log -Y | grep -v "mmlsfs::HEADER" | cut -f7,9 -d:'.format(fs)
        fs_fal = executeGPFSCommand(cmd)
        fal = fs_fal.split(":")[-1]
        if fal.lower() == "yes":
            fsdata['fal_status'] = True

        # fs acl setting (nfs4|posix|all)
        cmd = '/usr/lpp/mmfs/bin/mmlsfs {} -k -Y | grep -v "mmlsfs::HEADER" | cut -f7,9 -d:'.format(fs)
        fs_acl = executeGPFSCommand(cmd)
        fsdata['acl_type'] = fs_acl.split(":")[-1]

        filesystem.append(fsdata)

    return filesystem


def mmnfs_export_info():
    """ populate nfs export data

        nfs security flavours can have 4 values - sys, krb5, krb5i, krb5p
        krb5p encrypts data on the wire, hence will mark security = "yes" for it.
        For other values (sys, krb5, krb5i). will set security = "no".
    """
    nfs_exports = []

    result = executeGPFSCommand('/usr/lpp/mmfs/bin/mmnfs export list -Y | cut -f7 -d: | tail -n +2 | sort | uniq')
    exports = result.splitlines()

    fs_mntpnt = get_fs_mntpnts()

    for export in exports:
        expdata = {}
        data = []

        cmd = '/usr/lpp/mmfs/bin/mmnfs export list -n {} -Y | tail -1 | cut -f7,16 -d:'.format(export)
        data = executeGPFSCommand(cmd)
        (exp, sec) = data.split(':')
        expdata['fs'] = get_fs_of_path(fs_mntpnt, exp)
        expdata['FilesetMountPoint'] = exp
        expdata['security'] = 'no'
        if 'krb5p' in sec.lower():
            expdata['security'] = 'yes'

        nfs_exports.append(expdata)

    return nfs_exports


def timestamp_old ():
    """ store timestamp field """
    timestamp = {}
    timestamp['timestamp'] = False

    try:
       today = datetime.datetime.now()
       # print('Timestamp: {:%Y-%m-%d %H:%M:%S}'.format(today))
       timestamp['timestamp'] = "{:%Y-%m-%d %H:%M:%S}".format(today)
    except Exception as e:
       print ("Failure in getting time:", e)

    return timestamp


def get_fs_mntpnts():
    """ create a dictionary of fs and their mountpoints.
        key - fsname, value - fs mountpoint
    """
    fs_names = executeGPFSCommand("/usr/lpp/mmfs/bin/mmlsmount all | cut -f3 -d' '")
    fs_names = fs_names.splitlines()
    fs_mntpnt = {}
    for fs in fs_names:
        mntpnt = executeGPFSCommand("/usr/lpp/mmfs/bin/mmlsfs {} -T | grep 'Default mount point'".format(fs))
        fs_mntpnt[fs] = mntpnt.split()[1]

    return fs_mntpnt


def get_fs_of_path(fs_mntpnt, path):
    """ tell what is the gpfs filesystem for input path

      return: either of the following:
        - filesystem name of given path
        - False (if path is not under any gpfs filesystem)
    """

    for fs in fs_mntpnt:
        if path.startswith(fs_mntpnt[fs]):
            return fs

    return False


def create_json_file(json_file, data):
    with open(json_file, "w") as f:
        f.write(json.dumps(data, indent=4))


def update_ndjson_file(json_file, ndjson_file):
    """ read data from json file and append it to ndjson file
        kibana needs ndjson format file, hence this function.
    """

    # read json file
    with open(json_file, "r") as f:
        data = json.load(f)

    # append json data to ndjson file
    with open(ndjson_file, "a") as nf:
        if os.path.isfile(ndjson_file) and os.path.getsize(ndjson_file) > 0:
            nf.write("\n" + str(data))
        else:
            nf.write(str(data))


def get_security_posture_json():
    """ split_json_for_kibana function """

    # parent = {}
    # top = {}
    # parent = OrderedDict()
    top = OrderedDict()
    # parent['security_posture'] = top
    top['timestamp'] = timestamp()
    top['security_posture'] = cluster()
    # top  = cluster()
    top['CES_Authentication'] = mmuserauth()
    top['filesystem'] = get_filesystem_data()
#    top['FS_ACL_Type'] = fsacl()
    top['Secure_Administration'] = {}
    top['Secure_Administration']['CLI'] = cluster_mgmt()
    top['Secure_Administration']['GUI'] = gui()
#    top['FAL_status'] = fal()
#    top['Secure_Data_At_Rest'] = mmfs()
    top['secure_Data_At_Motion'] = {}
    top['secure_Data_At_Motion']['GPFS_cluster_communication'] = cluster_comm()
#    top['secure_Data_At_Motion']['NFS_EXPORT_INFO'] = mmnfs()
#    top['secure_Data_At_Motion']['SMB_SHARE_INFO'] = mmsmb()
    top['secure_Data_At_Motion']['NFS_EXPORT_INFO'] = mmnfs_export_info()
    top['secure_Data_At_Motion']['SMB_SHARE_INFO'] = mmsmb_export_info()
    top['Keystone_status'] = mmobject()
    top['TCT'] = tct()
    # print(json.dumps(parent, indent = 4))
    # print(json.dumps(top, indent = 4))
#    update_ndjson_file(json_file, ndjson_file)
    return top


def get_security_posture(json_file):
    top = get_security_posture_json()
    create_json_file(json_file, top)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get security posture of cluster.')
    parser.add_argument('--output_file', required=True, dest='output_file',
                        help='output json file to be stored.')
    
    args = parser.parse_args()
    get_security_posture(args.output_file)
