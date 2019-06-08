#!/usr/local/bin/python

"""
    A Quick script that reads details on AWS IAM Role/User/Group identifiers and
    generates a report on permission usage
"""

from __future__ import print_function
# import os
# import sys
import time
import argparse
# import struct
# import re
import json
import datetime
# import pprint
# import code
import csv

try:
    import boto3
    from botocore.config import Config
except ImportError as error:
    print(error.__class__.__name__ + ": " + error.message)
    print("Please install required module")
    exit(1)


# pylint: disable=invalid-name

__author__ = 'Peter Shipley <peter.shipley@gmail.com>'
__copyright__ = "Copyright (C) 2019 Peter Shipley"
__license__ = "BSD"

debug = 0
GEN_STDOUT = False

TIME_FMT = '%Y%m%d% %H:%M:%S'

# following actions permissions are needed
#
# iam:GenerateServiceLastAccessedDetails
# iam:GetServiceLastAccessedDetails
# iam:GetServiceLastAccessedDetailsWithEntities
# iam:ListPoliciesGrantingServiceAccess
#


class JSONSetEncoder(json.JSONEncoder):
    """
        Encoder with datetime support for json module
    """
    # pylint: disable=arguments-differ, no-else-return
    def default(self, obj):  # pylint: disable=E0202
        if isinstance(obj, set):
            return sorted(list(obj))
            # return dict(_set_object=list(obj))
        elif isinstance(obj, datetime.datetime):
            return obj.strftime(TIME_FMT)
            #return obj.isoformat()
        else:
            return json.JSONEncoder.default(self, obj)


aws_session_args = {}
check_list = ['role', 'user', 'group']

def parse_args():
    """
        parse line args
    """
    global check_list # pylint: disable=global-statement

    local_check_list = []

    parser = argparse.ArgumentParser(description='Generate permission reports for User/Role/Group')

    parser.add_argument('--user', '-U', action="store_true", help='check user details')
    parser.add_argument('--role', '-R', action="store_true", help='check role details')
    parser.add_argument('--group', '-G', action="store_true", help='check group details')

    aws_arg_grp = parser.add_argument_group('AWS Args', '')
    aws_arg_grp.add_argument('--profile', # '-p',
                             default=None,
                             dest='profile_name',
                             help='(optional) Profile name')
    aws_arg_grp.add_argument('--region', # '-r',
                             default=None,
                             dest='region_name',
                             help='(optional) Region')
    aws_arg_grp.add_argument('--key', # '--aws_access_key_id',
                             default=None,
                             dest='aws_access_key_id',
                             help='(optional) Override default in AWS_ACCESS_KEY_ID')
    aws_arg_grp.add_argument('--secret', # '--aws_secret_access_key',
                             default=None,
                             dest='aws_secret_access_key',
                             help='(optional) Override default in AWS_SECRET_ACCESS_KEY')
    aws_arg_grp.add_argument('--session', # '--aws_aws_session_token',
                             default=None,
                             dest='aws_aws_session_token',
                             help='(optional) Override default in AWS_SESSION_TOKEN')

    pargs = parser.parse_args()

    # print(pargs)
    vargs = vars(pargs)

    for x in ['role', 'user', 'group']:
        if vargs[x]:
            local_check_list.append(x)

    if local_check_list:
        check_list = local_check_list

    for x in ['profile_name', 'region_name', 'aws_access_key_id', 'aws_secret_access_key']:
        if vargs[x]:
            aws_session_args[x] = vargs[x]


# z = datetime.datetime(1970, 1, 1, 0, 0)
col_format = "{:<40.38s}{:19s}{:19s}\t{:4s}:{}"


def gen_report(n):
    """
        generate permissions report entery for users or role
    """

    # resp = get_list(n)

    ident_str = "{}s".format(n.title())
    ident_name = '{}Name'.format(n.title())
    list_name = 'list_{}s'.format(n)

    pag = iam_client.get_paginator(list_name)

    print("list_name", list_name)

    for p in pag.paginate():
        for r in p[ident_str]:
            gen_lastused_resp = iam_client.generate_service_last_accessed_details(Arn=r['Arn'])
            jobid = gen_lastused_resp['JobId']
            lastAccessed = []

            last_access_resp = iam_client.get_service_last_accessed_details(JobId=jobid)

            while last_access_resp['JobStatus'] != "COMPLETED":
                # print("JobStatus:", last_access_resp['JobStatus'])
                time.sleep(.5)
                last_access_resp = iam_client.get_service_last_accessed_details(JobId=jobid)

            lastAccessed.extend(last_access_resp['ServicesLastAccessed'])
            # print('last_access Marker', len(lastAccessed), last_access_resp.get('Marker', 'NoMarker'))

            # get_service_last_accessed_details API call is not paginated my boto
            if last_access_resp['IsTruncated']:
                while 'Marker' in last_access_resp:
                    last_access_resp = iam_client.get_service_last_accessed_details(
                        Marker=last_access_resp['Marker'],
                        MaxItems=100, JobId=jobid)

                    lastAccessed.extend(last_access_resp['ServicesLastAccessed'])
                    print('access_resp Marker', len(lastAccessed), last_access_resp.get('Marker', 'NoMarker'))

            try:
                print_report(ident_name, r, lastAccessed)
            except Exception as e:
                print(json.dumps(last_access_resp, cls=JSONSetEncoder,
                                 sort_keys=True, indent=4, separators=(',', ': ')))
                print(e)
                raise


def print_report(name, rid, access_detail):
    """
        generate permissions report entery for users or role
    """

    unused_permissions = [x for x in access_detail if 'LastAuthenticated' not in x]
    used_permissions = [x for x in access_detail if 'LastAuthenticated' in x]

    if used_permissions:
        used_permissions.sort(key=lambda i: i['LastAuthenticated'], reverse=True)
        last_use = used_permissions[0]['LastAuthenticated'].strftime(TIME_FMT)
    else:
        last_use = "Never"

    rid_created = rid['CreateDate'].strftime(TIME_FMT)

    unused_list = [x['ServiceNamespace'] for x in unused_permissions]
    unused_list.sort()
    unused_cnt = len(unused_list)

    csv_writer.writerow([rid[name], rid_created, last_use, " ".join(unused_list)])

    if GEN_STDOUT:
        print(col_format.format(rid[name], rid_created, last_use,
                                str(unused_cnt), " ".join(unused_list)))

boto_config = Config(
    retries=dict(
        max_attempts=10
    )
)

if __name__ == '__main__':

    parse_args()

    # print("aws_session_args", aws_session_args)
    # print("check_list", check_list)

    session = boto3.session.Session(**aws_session_args)
    iam_client = session.client('iam', config=boto_config)

    if GEN_STDOUT:
        print(col_format.format("Name", "Created", "Last Used", 'Cnt', "Unused Permissions"))

    for targ in check_list:
        fname = '{}_permissions.csv'.format(targ.lower())
        print("Generating {} report: {}".format(targ, fname))
        with open(fname, 'w') as csvfd:
            csv_writer = csv.writer(csvfd, delimiter=',', quoting=csv.QUOTE_MINIMAL)
            table_name = '{}_Name'.format(targ.title())
            csv_writer.writerow([table_name, 'Created', 'Last_Used', 'Unused_Permissions'])
            gen_report(targ)


    print("FINISH")
