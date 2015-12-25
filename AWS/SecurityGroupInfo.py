#!/usr/bin/env python
# encoding utf-8

#
#   This class gathers and encapsulates information about AWS security groups that is not exposed through the
#   CLI.
#
#   Copyright Sid Stuart 2015
#   This software is licensed under GPL 3.0
#

from boto3.session import Session


Class SecurityGroupInfo:
    ''' Handle all the security groups data. '''
    # The hash for the security groups
    SECURITY_GROUPS = dict()

    def __init__(self):
        ''' Establish a connection with AWS, pull out resource information. '''
        session = Session(profile_name=ARGS.profile, region_name='us-east-1')

        ec2 = session.resource('ec2')
        elb = session.client('elb')
        cache = session.client('elasticache')

    def __len__(self):
        return 1

    def _get_sg_group(self, sg_id):
        ''' Given a security group id, either return an existing
        group or create a new one and return that. '''
        pass


Class SecurityGroup:
    ''' Gather and hold the information on Security Groups. '''
    def __init__(self, aws_sg):
        self.aws_sg = aws_sg
        # Some data about the group is calculated. This structure
        # holds the results.
        self.data = dict()
        self.data['port_list'] = list()
        self.data['rule_count'] = 0
        self.data['world_access'] = False
        self.data['host_list'] = list()
        self.data['elb_list'] = list()
        self.data['sg_list'] = list()
        self.data['elasticache_list'] = list()

    #
    # Factory Methods
    #
    def get_groups(self, session):
        ''' Given a session, return a dict of Security Groups, indexed by their security group id. '''
        pass

    def get_ec2_groups(self, session):
        ''' Given a boto3 Session object, get the security groups listed in the ec2 resource.
            Return a dict containing the groups, indexed by the security group id. '''
        EC2 = session.resource('ec2')
        groups = dict()
        for sg in EC2.security_groups.all():
            # Initialize and save the structure for this group.
            this_group = get_sg_group(sg.id)

    #
    #   Parsing Methods
    #
    def gather_data(self):
        ''' Parse through the Security Group information and pull out interesting facts. '''
        rule_count = 0
        # Pick up the incoming rules and ports
        # The data structure returned by ip_permissions is a list with one or more
        # dictionary entries
        # The good stuff is associated with the keys FromPort and IpRanges
        for port_data in self.aws_sg.ip_permissions:
            if 'FromPort' in port_data:
                this_group['port_list'].append(port_data['FromPort'])
                ips = port_data['IpRanges']
                if len(ips) > 0:
                    # Not sure why they return a dict here.
                    for ip_range_dict in ips:
                        rule_count += 1
                        ip_range = ip_range_dict['CidrIp']
                        if ip_range == '0.0.0.0/0':
                            this_group['world_access'] = True
                if len(port_data['UserIdGroupPairs']) > 0:
                    # Look for security groups to match on
                    rule_count += 1
                    for pair in port_data['UserIdGroupPairs']:
                        ref_sg_id = pair['GroupId']
                        ref_sg_group = get_sg_group(ref_sg_id)
                        ref_sg_group['sg_list'].append(sg.id)
            else:
                for ip_range_dict in port_data['IpRanges']:
                    rule_count += 1
                    ip_range = ip_range_dict['CidrIp']
                    if ip_range == '0.0.0.0/0':
                        this_group['world_access'] = True
        self.data['rule_count'] = rule_count
