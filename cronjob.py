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


import argparse
import configparser
import os


def executeCommand(cmd):
    """ execute command
    input - cmd (command to be executed)

    return -
      result - if cmd succeeds, then return command result
      False - if cmd fails
    """

    try:
        res = os.popen(cmd).read()
        res = res.strip()
    except Exception as e:
        print("failure in executing command {0}\n{1}".format(cmd, e))
        return False

    return res


command_format = "bash -x ./fetch_security_posture_and_upload_to_ES.sh '{0}' '{1}' '{2}' '{3}' '{4}'"


def run_scan(config, scale_cluster_config):
    elastic_user = config['CONFIG']['elastic_user']
    elastic_search_url = config['CONFIG']['elastic_search_url']
    for cluster_key in scale_cluster_config:
        user_name = scale_cluster_config[cluster_key]["user"]
        ip_address = scale_cluster_config[cluster_key]["ip-address"]
        temp_dir = scale_cluster_config[cluster_key]["temp-dir"]
        
        print "Processing: '{0}'\n  User Name: '{1}'\n "\
                " IP Address: '{2}'\n  Temp Dir: '{3}'".format(cluster_key,
                 user_name,
                 ip_address,
                 temp_dir,
                 elastic_user,
                 elastic_search_url)
        
        command = command_format.format(user_name, ip_address, temp_dir, elastic_user, elastic_search_url)
        executeCommand(command)


def read_configurations(config_file):
    config = configparser.ConfigParser()
    config.read(config_file)
    
    default_dict = {}
    for key in config['DEFAULT']:
        default_dict[key] = config['DEFAULT'][key]
    
    all_configs = {}
    for section_name in config.sections():
        all_configs[section_name] = default_dict.copy()
        for section_key in config[section_name]:
                all_configs[section_name][section_key] = config[section_name][section_key]
    return all_configs


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run scan for provided clusters.')
    parser.add_argument('--config-file', required=True, dest='config_file',
                        help='configuration file to be stored.')

    parser.add_argument('--scale-clusters-config-file', required=True, dest='scale_cluster_config_file',
                        help='configuration file related to scale cluster.')
    
    args = parser.parse_args()
    scale_cluster_config = read_configurations(args.scale_cluster_config_file)
    config = read_configurations(args.config_file)
    run_scan(config, scale_cluster_config)
