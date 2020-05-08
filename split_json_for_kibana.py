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

import json
import argparse


def main(security_posture_json_file, output_dir):
    
    with open(security_posture_json_file) as fp:
        data = json.load(fp)
    
    cluster_json = {}
    filesystem_jsons = []
    export_jsons = []
    
    timestamp = data["timestamp"]
    cluster_id = data["security_posture"]["Cluster_ID"]
    
    ## Arranging all the cluster details in json format
    cluster_json = {
            "timestamp": data["timestamp"],
            "cluster_id": data["security_posture"]["Cluster_ID"],
            "Cluster_Name": data["security_posture"]["Cluster_Name"],
            "Secure_Administration" : data["Secure_Administration"],
            "CES_Authentication": data["CES_Authentication"],
            "Keystone_status": data["Keystone_status"],
            "TCT": data["TCT"]
        }
    
    ## Arraging filesystem related data in json format
    for fs in data["filesystem"]:
        fs.update({
            "timestamp": data["timestamp"],
            "cluster_id": data["security_posture"]["Cluster_ID"]
        })
    
        filesystem_jsons.append(fs)
    
    ## Arranging SMB and NFS shares related data in json format
    for export in data["secure_Data_At_Motion"]["SMB_SHARE_INFO"]:
        export.update({
            "timestamp": data["timestamp"],
            "cluster_id": data["security_posture"]["Cluster_ID"],
            "protocol_name": "SMB"
        })
        export_jsons.append(export)
    
    for export in data["secure_Data_At_Motion"]["NFS_EXPORT_INFO"]:
        export.update({
            "timestamp": data["timestamp"],
            "cluster_id": data["security_posture"]["Cluster_ID"],
            "protocol_name": "NFS"
    
        })
    
        export_jsons.append(export)
    
    with open(output_dir + "/cluster.json", "w") as cjson:
        json.dump(cluster_json, cjson)
    
    for (i, fs) in enumerate(filesystem_jsons):
        with open(output_dir + "/fs_{0}.json".format(i + 1), "w") as fsjson:
            json.dump(fs, fsjson)
    
    for (i, ex) in enumerate(export_jsons):
        with open(output_dir + "/export_{0}.json".format(i + 1), "w") as exjson:
            json.dump(ex, exjson)
    

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Splits the json file to upload to elastic search for kiban usage.')
    parser.add_argument('--security-posture-json', dest='security_posture_json_file',
                        help='security posture json to be used.')
    parser.add_argument('--output-dir', dest='output_dir',
                        help='Output directory where the data is to be stored.')
    
    args = parser.parse_args()
    main(args.security_posture_json_file, args.output_dir)
