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
    """ Given a security group id, either return an existing
        group or create a new one and return that. """


Class SecurityGroup:
    ''' Gather and hold the information on Security Groups. '''
    def __init_(self, sg):
        self.sg = sg


    def get_groups(self, session):
        ''' Given a session, return a dict of Security Groups, indexed by their security group id. '''



    def get_ec2_groups(self, session):
        ''' Given a boto3 Session object, get the security groups listed in the ec2 resource.
            Return a dict containing the groups, indexed by the security group id. '''
        EC2 = session.resource('ec2')
        groups = dict()
        for sg in EC2.security_groups.all():
            # Initialize and save the structure for this group.
            this_group = get_sg_group(sg.id)
