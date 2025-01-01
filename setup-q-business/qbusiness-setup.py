import boto3
import json
import time
from io import StringIO

# set instance name
instance_name = 'qbusiness-instance'
region = 'us-west-2'

session = boto3.Session(region_name=region)
sso_admin = session.client('sso-admin')
id = session.client('identitystore')
iam = session.client('iam')
qbusiness = session.client('qbusiness')
account = session.client('sts').get_caller_identity()['Account']


# create an identity center instance
def create_identity_center():
    try:
        response = sso_admin.list_instances()
        for instance in response['Instances']:
            if (instance['Name'] == instance_name):
                print('Identity-center Instance already exists')
                instance_arn = instance['InstanceArn']
                return instance_arn
        print('Creating new instance')
        response = sso_admin.create_instance(Name=instance_name)
        instance_arn =  response['InstanceArn']
    except Exception as e:
        print(str(e))
        return None

        # wait for instance to be active
    while sso_admin.describe_instance(InstanceArn=instance_arn )['Status'] != 'ACTIVE':
        time.sleep(2)

    return instance_arn


# create a user group "Q Business Users" in the sso instance
def create_group(instance_arn, group_name='Q Business Group'):
    identityStoreId = sso_admin.describe_instance(InstanceArn=instance_arn)['IdentityStoreId']
    try:
        response = id.list_groups(IdentityStoreId=identityStoreId)
        for group in response['Groups']:
            if (group['DisplayName'] == group_name):
                print('Q Business Group already exists')
                group_id = group['GroupId']
                return group_id
        print('Creating new group')
        response = id.create_group(
            IdentityStoreId=identityStoreId,
            DisplayName=group_name,
            Description='Q Business Group for the demo.'
        )
        group_id = response['GroupId']
    except Exception as e:
        print(str(e))
        return None

    return group_id

# create a service linked role - AWSServiceRoleForQBusiness
def create_service_linked_role():
    # check if the role already exists
    try:
        response = iam.get_role(
            RoleName='AWSServiceRoleForQBusiness'
        )
        print('Service linked role already exists')
        return None
    except Exception as e:
        print(str(e))

    try:
        response = iam.create_service_linked_role(
            AWSServiceName='qbusiness.amazonaws.com'
        )
    except Exception as e:
        print(str(e))

    return None

# create the Amazon Q Business Application
def create_q_application(instance_arn, application_name='AmazonQBusinessApplication'):
    try:
        response = qbusiness.list_applications()
        for application in response['applications']:
            print(application)
            if (application['displayName'] == application_name):
                print('Q Business Application already exists')
                application_id = application['applicationId']
                return application_id
        print('Creating new application')
        response = qbusiness.create_application(
            displayName=application_name,
            roleArn='arn:aws:iam::'+account+':role/AWSServiceRoleForQBusiness',
            identityCenterInstanceArn=instance_arn,
            identityType='AWS_IAM_IDC',
            attachmentsConfiguration={
                'attachmentsControlMode': 'ENABLED'
            },
            qAppsConfiguration={
                'qAppsControlMode': 'ENABLED'
            },
            personalizationConfiguration={
                'personalizationControlMode': 'ENABLED'
            }
        )
        application_id = response['applicationId']
    except Exception as e:
        print(str(e))
        return None

    return application_id

# get the sso application
def get_sso_application(instance_arn, application_name='AmazonQBusinessApplication'):
    try:
        # wait for 5 seconds for
        while True:
            time.sleep(5)
            response = sso_admin.list_applications(
                Filter={
                    'ApplicationProvider': 'arn:aws:sso::aws:applicationProvider/qbusiness'
                },
                InstanceArn=instance_arn,
            )
            print(response['Applications'])
            for application in response['Applications']:
                if (application['Name'] == application_name):
                    print('SSO Application already exists')
                    application_arn = application['ApplicationArn']
                    return application_arn
    except Exception as e:
        print(str(e))
        return None

# create the index in the Q Business Application
def create_index(application_id):
    try:
        response = qbusiness.list_indices(
            applicationId=application_id
        )
        for index in response['indices']:
            if (index['name'] == 'AmazonQBusinessIndex'):
                print('Index already exists')
                return None
        print('Creating new index')
        response = qbusiness.create_index(
            applicationId=application_id,
            displayName='AmazonQBusinessIndex',
            type='ENTERPRISE', # change to 'STARTER' if you need
            capacityConfiguration={
                'units': 1
            },
        )
    except Exception as e:
        print(str(e))
        return None

    return None

# assign the sso group to application via sso CreateApplicationAssignment
def assign_sso_group_to_application(application_arn, group_id):
    try:
        response = sso_admin.create_application_assignment(
            ApplicationArn=application_arn,
            PrincipalId=group_id,
            PrincipalType='GROUP',
        )
        print('Assigned SSO group to application')
    except Exception as e:
        print(str(e))
        return None

    return None

# create the role for Q Business Web experience
def create_qbusiness_web_role(region, account, application_id):
    # check if the role already exists
    role_name = "QBusiness-WebExperience-demo"
    try:
        response = iam.get_role(
            RoleName=role_name
        )
        print('Q Business Web Experience Role already exists')
        role_arn = response['Role']['Arn']
        return role_arn
    except Exception as e:
        print(str(e))

    print('Creating new role')

    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "QBusinessTrustPolicy",
                "Effect": "Allow",
                "Principal": {
                    "Service": "application.qbusiness.amazonaws.com"
                },
                "Action": [
                    "sts:AssumeRole",
                    "sts:SetContext"
                ],
                "Condition": {
                    "StringEquals": {
                        "aws:SourceAccount": f"{account}"
                    },
                    "ArnEquals": {
                        "aws:SourceArn": f"arn:aws:qbusiness:{region}:{account}:application/{application_id}"
                    }
                }
            }
        ]
    }
    try:
        print(str(assume_role_policy_document))
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy_document),
            Description='Amazon Q Business Web Experience Role'
        )
        role_arn = response['Role']['Arn']
        policy_arn = create_qbusiness_web_policy(region, account, application_id)
        response = iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_arn
        )
    except Exception as e:
        print(str(e))
        return None

    return role_arn


def create_qbusiness_web_policy(region, account, application_id):
    # create policy for the role
    # generate a short random string
    epoch_string = str(int(time.time()))
    policy_name = "QBusiness-WebExperience" + epoch_string
    # policy document is from web_experience.json file
    with open('web_experience.json') as f:
        content = f.read()

    modified_content = (content
                        .replace('{{region}}', region)
                        .replace('{{source_account}}', account)
                        .replace('{{application_id}}', application_id))

    with StringIO(modified_content) as json_file:
        policy_document = json.load(json_file)
    try:

        response = iam.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document),
            Description='Amazon Q Business Web Experience Policy'
        )
        policy_arn = response['Policy']['Arn']
    except Exception as e:
        print(str(e))

    return policy_arn


# create Amazon Q Business Web Experience
def create_web_experience(application_id, role, title="WebExperienceDemo"):
    # check if there is any web experience
    response = qbusiness.list_web_experiences(
        applicationId=application_id
    )
    if len(response['webExperiences']) > 0:
        print('Web Experience already exists')
        return None

    response = qbusiness.create_web_experience(
        applicationId=application_id,
        title=title,
        subtitle='This is a demo web experience',
        roleArn=role
    )

    webExperienceArn = response['webExperienceArn']
    return webExperienceArn

# main function
if __name__ == "__main__":
    print("step 0: create identity center instance, group and service linked role")
    instance_arn = create_identity_center()
    group_id = create_group(instance_arn)
    print('Identity Center Instance Arn: ' + instance_arn)
    print('Group Id: ' + group_id)
    create_service_linked_role()

    print("step 1: create the Amazon Q Business application")
    application_id = create_q_application(instance_arn)
    print('Application Id: ' + application_id)

    print("step 2: get the SSO application")
    sso_application_id = get_sso_application(instance_arn)
    print('SSO Application Id: ' + sso_application_id)

    print("step 3: create the index in the Amazon Q Business application")
    create_index(application_id)

    print("step 4: assign the SSO group to the application")
    assign_sso_group_to_application(sso_application_id, group_id)

    print('step 5: create the role for Q Business Web experience')
    role_arn = create_qbusiness_web_role(region, account, application_id)
    print('Q Business Web Role Arn: ' + role_arn)

    print('step 6: create the web experience')
    webExperienceArn = create_web_experience(application_id, role_arn)
    if webExperienceArn:
        print('Web Experience Arn: ' + webExperienceArn)
    print('Done')