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

#####
#
#   This class handles data associated with the SecurityGroups associated with EC2.
#
#####

Class EC2SecurityGroup:
    ''' Gather and hold the information on Security Groups associated with hosts.'''
    def __init__(self, aws_sg):
        self.aws_sg = aws_sg
        # Some data about the group is calculated. This structure
        # holds the results.
        self.data = dict()
        self.data['port_list'] = list()
        self.data['rule_count'] = 0
        self.data['world_access'] = False
        self.data['host_list'] = list()
        #self.data['elb_list'] = list()
        # Track the Security Groups listed in a Security Group so we can figure out
        # Whether a group is referenced elsewhere.
        self.data['sg_list'] = list()
        #self.data['elasticache_list'] = list()
        gather_data(self)

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
        ''' Parse through the Security Group information and pull the number of rules listed in the group.
            The IP addresses or Security Groups associated with each open port. The list of ports that are
            opened by this group. And whether one of the IP addresses is 0.0.0.0/0, which opens a port to the
            world.  '''
        rule_count = 0
        # Count the ingress rules
        # The data structure returned by ip_permissions is a list with one entry for each port opened.
        # The port entries will have the port number and the list of IPRanges associated with that port.
        # It will also have any Security Group ID's associated with the port listed under UserIdGroupPairs.

        # Go through the list of rules associated with each port number and pull out data.
        # We want a list of the ports that are open. We want to flag if a port is open to the world.
        # We want to count how many rules are listed in the Security group, as there is a per group limit
        # in VPC Security Groups.
        for ingress_data in self.aws_sg.ip_permissions:
            if 'FromPort' in port_data:
                self.data['port_list'].append(port_data['FromPort'])
            else:
                print 'Odd Structure in EC2 Security Group %s' % self.aws_sg.groupid
            # Count the number of IpRange rules and check for public addresses
            for ips in ingress_data['IpRanges']:
                rule_count += 1
                ip_range = ip_range_dict['CidrIp']
                if ip_range == '0.0.0.0/0':
                    self.data['world_access'] = True
            # These are the security groups allowed to access a port
            for pair in ingress_data['UserIdGroupPairs']:
                rule_count += 1
                self.data['sg_list'] = pair['GroupId']

        #
        # Now count the egress rules. There is generally only one.
        # This code is not tracking details on the exgress rules at the moment.
        #
        for egress_data in self.aws_sg.ip_permissions_egress:
            for ip_range in egress_data['IpRanges']:
                rule_count += 1
            for group_pairs in ip_data['UserIdGroupPairs']:
                rule_count += 1

        self.data['rule_count'] = rule_count
