#!/bin/bash -x	
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

user="$1"
ip="$2"
tmp_dir="$3"
elastic_user="$4"
elastic_base_URL="$5"

output_dir="./output_dir/"


echo $user
echo $ip
echo $tmp_dir

rm -rf "$output_dir"*
ssh $user@$ip rm -rf "$tmp_dir"
ssh $user@$ip mkdir -p "$tmp_dir"
scp collector/security_posture.py $user@$ip:"$tmp_dir"
ssh $user@$ip python "$tmp_dir"/security_posture.py --output_file "$tmp_dir"/output_data.json 
scp $user@$ip:"$tmp_dir"/output_data.json .

rm -rf "$output_dir"
mkdir -p "$output_dir"

python split_json_for_kibana.py --security-posture-json output_data.json --output-dir "$output_dir"

## Copying the Cluster_data, File_system_data and Export data in to Elastic Search
curl --insecure --user $elastic_user -X DELETE $elastic_base_URL'/scale_cluster/' -H 'Content-Type: application/json'
curl --insecure --user $elastic_user -X DELETE $elastic_base_URL'/scale_fs/' -H 'Content-Type: application/json'
curl --insecure --user $elastic_user -X DELETE $elastic_base_URL'/scale_export/' -H 'Content-Type: application/json'


curl --insecure --user $elastic_user -X POST $elastic_base_URL'/scale_cluster/doc/' -H 'Content-Type: application/json' -d @"$output_dir"cluster.json

for file in "$output_dir"/fs*
do
    echo $file;
    curl --insecure --user $elastic_user -X POST $elastic_base_URL'/scale_fs/doc/' -H 'Content-Type: application/json' -d @$file
done

for file in "$output_dir"/export*
do
    echo $file;
    curl --insecure --user $elastic_user -X POST $elastic_base_URL'/scale_export/doc/' -H 'Content-Type: application/json' -d @$file;
done
