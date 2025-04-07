#Version v001
import json
import boto3
import logging
import traceback

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

import time
import urllib.parse
import os
import requests
import sys
import botocore
import re
from botocore.config import Config
from base64 import b64decode

# ENCRYPTED_clientid = os.environ['client_id']
# # Decrypt code should run once and variables stored outside of the function
# # handler so that these are decrypted once per container
# client_id = boto3.client('kms').decrypt(
#     CiphertextBlob=b64decode(ENCRYPTED_clientid),
#     EncryptionContext={'LambdaFunctionName': os.environ['AWS_LAMBDA_FUNCTION_NAME']}
# )['Plaintext'].decode('utf-8')

# ENCRYPTED_client_secret = os.environ['client_secret']
# # Decrypt code should run once and variables stored outside of the function
# # handler so that these are decrypted once per container
# client_secret = boto3.client('kms').decrypt(
#     CiphertextBlob=b64decode(ENCRYPTED_client_secret),
#     EncryptionContext={'LambdaFunctionName': os.environ['AWS_LAMBDA_FUNCTION_NAME']}
# )['Plaintext'].decode('utf-8')
client_id = os.environ['client_id']
client_secret=os.environ['client_secret']


def get_configuration():
  url = f'http://localhost:2772/applications/fargateCreate/environments/all/configurations/tagsmap'
  config = json.loads(urllib.request.urlopen(url).read())
  #print(config)
  return config

def get_configuration_new():
  url = f'http://localhost:2772/applications/fargateCreate/environments/all/configurations/Snowtagsmap'
  config = json.loads(urllib.request.urlopen(url).read())
  #print(config)
  return config
  
def list_tasks(cluster, service, creds):
    try:
        print("Listing tasks in the cluster and service")
        print("cluster is " + cluster)
        print("service is " + service)
        client = boto3.client('ecs', aws_access_key_id=creds['AccessKeyId'],
                              aws_secret_access_key=creds['SecretAccessKey'],
                              aws_session_token=creds['SessionToken'])
        response = client.list_tasks(
            cluster=cluster,
            serviceName=service,
            desiredStatus='RUNNING',
            launchType='FARGATE'
        )
        return response['taskArns']
    except IndexError as e:
        print("Error: Index out of range while listing tasks.")
        return []
    except KeyError as e:
        print("Error: Key not found in response while listing tasks.")
        return []
    except Exception as e:
        print(f"Error listing tasks: {str(e)}")
        return []



def updateenvvars(dict, envkey, envval, idx):
    try:
        print("Updating environment variable: " + str(envkey) + " with value: " + str(envval))
        dict['taskDefinition']['containerDefinitions'][idx]['environment'].append({"name": str(envkey), "value": str(envval)})
    except IndexError as e:
        print("Error: Index out of range while updating environment variables.")
    except KeyError as e:
        print("Error: Key not found in dictionary while updating environment variables.")
    except Exception as e:
        print(f"Error updating environment variables: {str(e)}")


    
def updateenvfiles(dict,envkey,envval,idx):
    try:
        notfound = True
        #print("received "+ str(envkey) + str(envval))
        if 'environmentFiles' in dict['taskDefinition']['containerDefinitions'][idx]:
            for i in dict['taskDefinition']['containerDefinitions'][idx]['environmentFiles']:
                if i['value'] == envval and i['type'] == envkey:
                    print("File already present")
                    notfound = False
            
            if notfound:
                dict['taskDefinition']['containerDefinitions'][idx]['environmentFiles'].append({ "value": str(envval), "type": str(envkey) })
                    
        else:
            dict['taskDefinition']['containerDefinitions'][idx]['environmentFiles'] = [{ "value": str(envval), "type": str(envkey) }]
    except Exception as e: print(e)

def updateVolumes(dict,volname,idx):
    found=0
    if dict['taskDefinition']['volumes']:
        for i in dict['taskDefinition']['volumes']:
            if i['name'] == volname:
                found=1
                print('Volume %s exists.. Not adding..' % volname)
        if found == 0:
            print("Adding volume :"+str(volname))
            dict['taskDefinition']['volumes'].append({ 'name': str(volname) })

def setBindVolume(dict,cpath,volname,idx):
    if dict['taskDefinition']['containerDefinitions'][idx]['mountPoints']:
        for i in dict['taskDefinition']['containerDefinitions'][idx]['mountPoints']:
            if cpath in i['containerPath']:
                print("Deleting..cpath "+cpath)
                dict['taskDefinition']['containerDefinitions'][idx]['mountPoints'].remove({'sourceVolume': i['sourceVolume'], 'containerPath': i['containerPath'] })
        for i in dict['taskDefinition']['containerDefinitions'][idx]['mountPoints']:
            if volname in i['sourceVolume']:
                print("Deleting..volume "+volname)
                dict['taskDefinition']['containerDefinitions'][idx]['mountPoints'].remove({'sourceVolume': i['sourceVolume'], 'containerPath': i['containerPath'] })
        #print("Adding "+cpath)
        dict['taskDefinition']['containerDefinitions'][idx]['mountPoints'].append({'sourceVolume': str(volname), 'containerPath': str(cpath) })
    #print(dict)
    
def attachvolume(dict,idx):
    if 'volumesFrom' in dict['taskDefinition']['containerDefinitions'][idx]:
        print("volumesFrom already exists.. nothing to add..")
    else:
        print("Adding volumesFrom to custom container.")
        dict['taskDefinition']['containerDefinitions'][idx]['volumesFrom'] = [{ "sourceContainer": "s3tofrgmount" }]
    if 'dependsOn' in dict['taskDefinition']['containerDefinitions'][idx]:
        print("dependsOn already exists.. nothing to add..")
    else:
        print("Adding dependsOn to custom container..")
        dict['taskDefinition']['containerDefinitions'][idx]['dependsOn'] = [{ "containerName": "s3tofrgmount", "condition": "COMPLETE" }]
    
def create_awsloggroup(lgroup, owner, refid, creds, tagsmap):
    try:
        client = boto3.client('logs', aws_access_key_id=creds['AccessKeyId'], aws_secret_access_key=creds['SecretAccessKey'], aws_session_token=creds['SessionToken'],)
        response = client.create_log_group(
            logGroupName=lgroup,
            tags=tagsmap
        )
        logger.info(f"Created CloudWatch log group: {lgroup}")
        logger.debug(f"Log group response: {response}")
        return response
    except Exception as e:
        logger.error(f"Error creating log group {lgroup}: {str(e)}")
        logger.debug(traceback.format_exc())
        return None



def create_retention_policy(lgroup,days,creds):
    client = boto3.client('logs', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    response = client.put_retention_policy(
    logGroupName=lgroup,
    retentionInDays=days
    )
    return response

def create_update_aws_secrets_manager(username,apikey,secretname,creds):
    client = boto3.client('secretsmanager', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    response = client.create_secret(
        Name=secretname,
        Description='testing only',
        SecretString='{"username": '+ '"'+username+'"' +',"password": '+ '"'+apikey+'"' +'}',
        Tags=[
        {
        'Key': 'testing',
        'Value': 'devops'
        },
        ],
    )
    return response

def check_taskandservice_stack_status(bu,csp,loc,account,incr,sname,creds):
    client = boto3.client('cloudformation', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    stack_name = bu+csp+loc+'-'+account+'-'+incr+'-Fargate-TaskAndService'+sname
    #print(stack_name)
    response = client.describe_stacks(
        StackName=stack_name,
    )
    return response['Stacks'][0]['StackStatus']

def check_fargate_create_codebuild_pipeline(trackId,creds):
    client = boto3.client('codebuild', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    response = { 'projects': [], 'nextToken': 'first' }
    while 'nextToken' in response:
        if response['nextToken'] == 'first':
            responseNext  = client.list_projects(
                sortBy='CREATED_TIME'
            )
        else:
            responseNext  = client.list_projects(
                sortBy='CREATED_TIME',
                nextToken = response['nextToken'],
            )
        del response['nextToken']
        response['projects']=response['projects']+responseNext['projects']
        if 'nextToken' in responseNext:
            response['nextToken'] = responseNext['nextToken']
    if 'NextToken' in response:
        del response['nextToken']
    result = []
    for i in response['projects']:
        if trackId in i:
            result.append(i)
    return result[:2]

def check_fargate_create_codebuild_pipeline_jobs(bname,creds):
    client = boto3.client('codebuild', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    response = { 'ids': [], 'nextToken': 'first' }
    while 'nextToken' in response:
        if response['nextToken'] == 'first':
            responseNext = client.list_builds_for_project(
            projectName=bname
        )
        else:
            responseNext = client.list_builds_for_project(
                cluster = bu + csp + loc + '-' + account + '-' + incr  + '-' + cname,
                projectName=bname,
                nextToken = response['nextToken'],
            )
        del response['nextToken']
        response['ids']=response['ids']+responseNext['ids']
        if 'nextToken' in responseNext:
            response['nextToken'] = responseNext['nextToken']
    if 'NextToken' in response:
        del response['nextToken']
    bid = response['ids'][0]
    response = client.batch_get_builds(
        ids = [bid],
    )
    bstate = response['builds'][0]['buildStatus']
    return bstate

def check_fargate_create_run_stack(trackId,creds):
    client = boto3.client('cloudformation', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    response = { 'StackSummaries': [], 'NextToken': 'first' }
    while 'NextToken' in response:
        if response['NextToken'] == 'first':
            responseNext = client.list_stacks(
                StackStatusFilter= ['CREATE_COMPLETE' ]
            )
        else:
            responseNext = client.list_stacks(
                StackStatusFilter= ['CREATE_COMPLETE' ],
                NextToken = response['NextToken'],
            )
        del response['NextToken']
        response['StackSummaries']=response['StackSummaries']+responseNext['StackSummaries']
        if 'NextToken' in responseNext:
            response['NextToken'] = responseNext['NextToken']
    if 'NextToken' in response:
        del response['NextToken']
    result = []
    for i in response['StackSummaries']:
        if '-runstack-' in i['StackName']:
            if trackId in i['StackName']:
                #print(i['StackName'])
                if i['StackStatus'] == 'CREATE_IN_PROGRESS':
                    count = 1
                    while response['Stacks'][0]['StackStatus'] != 'CREATE_COMPLETE' and count <= 10:
                        print("Sleeping 10 seconds.. retry "+str(count))
                        time.sleep(10)
                        response = client.describe_stacks(
                        StackName=i['StackName'],
                    )
                    print('Stack Status '+str(response['Stacks'][0]['StackStatus'])) 
                    count = count + 1
                    result.append(str(i['StackName']) + ':' + str(response['Stacks'][0]['StackStatus']))
                else:
                    result.append(str(i['StackName']) + ':' + str(i['StackStatus']))
    return result

def get_fargate_create_cluster_status(cname,creds):
    client = boto3.client('ecs', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    response = client.describe_clusters(
    clusters=[
    cname,
    ]
    )
    return response['clusters'][0]['status']

def get_fargate_create_service_status(cname,sname,creds):
    client = boto3.client('ecs', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    response = client.describe_services(
    cluster=cname,
    services=[
    sname,
    ],
    )
    return response['services'][0]['status']

def getrecord_dynamodb_table(cname, sname, tablename):
    try:
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(tablename)
        response = table.get_item(
            Key={
                'clustername': cname,
                'servicename': sname
            }
        )
        if 'Item' in response:
            return response['Item']
        else:
            return 'Item not found'
    except Exception as e:
        print(f"Error retrieving record from DynamoDB: {str(e)}")
        return 'Error occurred'

    
def deleterecord_dynamodb_table_crauth(buildid, tablename, awsregion):
    try:
        dynamodb = boto3.resource('dynamodb', region_name=awsregion)
        table = dynamodb.Table(tablename)
        response = table.delete_item(
            Key={
                'buildid': buildid
            }
        )
        print(response)
        return response
    except Exception as e:
        print(f"Error deleting record from DynamoDB: {str(e)}")
        return 'Error occurred'


def getrecord_dynamodb_table_crauth(buildid,requested,tablename,awsregion):
    try:
        dynamodb = boto3.resource('dynamodb',region_name=awsregion)
        print(buildid)
        table = dynamodb.Table(tablename)
        response = table.get_item(
        Key={
            'buildid': buildid
        }
        )
        return response
    except Exception as e:
        print(e)

def addrecord_dynamodb_table(cname,sname,tagslist,tablename):
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(tablename)
    table.put_item(
        Item={
        'clustername': cname,
        'servicename': sname,
        }
    )
    table.update_item(
    Key={
    'clustername': cname,
    'servicename': sname
    },
    UpdateExpression='SET tagslist = :t1',
    ExpressionAttributeValues={
    ':t1': tagslist
    }
    )

def check_into_dynamodb_table(cname,sname,tagslist,tablename):
    try:
        client = boto3.client('dynamodb')
        response = client.describe_table(
        TableName=tablename
        )
        if response['Table']['TableName'] == tablename:
            print("table exists, adding record..")
            out = addrecord_dynamodb_table(cname,sname,tagslist,tablename)
    except:
        create_dynamodb_table(tablename)
        time.sleep(30)
        addrecord_dynamodb_table(cname,sname,tagslist,tablename)

def create_dynamodb_table(tablename):
    client = boto3.client('dynamodb')
    response = client.create_table(
    AttributeDefinitions=[
    {
        'AttributeName': 'clustername',
        'AttributeType': 'S'
    },
    {
        'AttributeName': 'servicename',
        'AttributeType': 'S'
    },
    ],
    TableName=tablename,
    KeySchema=[
    {
        'AttributeName': 'clustername',
        'KeyType': 'HASH'
    },
    {
        'AttributeName': 'servicename',
        'KeyType': 'RANGE'
    },
    ],
    BillingMode='PAY_PER_REQUEST',
    Tags=[
    {
        'Key': 'contact',
        'Value': 'Devops Engineering'
    },
    {
        'Key': 'purpose',
        'Value': 'Spinnaker ECS tags storage'
    },
    ]
    )

def find_if_v000(sname):
    suffix = '-v000'
    return sname.endswith(suffix)

def find_latest_service(list):
    mydict = {}
    for i in list:
        res =  "/".join(reversed(i.split("/")))
        r = res.split('/')
    
        r1 = "-".join(reversed(r[0].split('-')))
        r = r1.split('-')

        r2 = r[0].replace("v","")

        mydict[i] = r2

    sort_orders = sorted(mydict.items(), key=lambda x: x[1], reverse=True)
    return sort_orders[0][0]
    
def find_lowest_service(list):
    mydict = {}
    for i in list:
        res =  "/".join(reversed(i.split("/")))
        r = res.split('/')
    
        r1 = "-".join(reversed(r[0].split('-')))
        r = r1.split('-')

        r2 = r[0].replace("v","")

        mydict[i] = r2

    sort_orders = sorted(mydict.items(), key=lambda x: x[1], reverse=False)
    return sort_orders[0][0]

def find_first_service(list1):
    mydict = {}
    a = list1.split('-')
    del a[-1]
    a.append('v000')
    return a

def find_000_service(list):
    mydict = {}
    for i in list:
        res =  "/".join(reversed(i.split("/")))
        r = res.split('/')
    
        r1 = "-".join(reversed(r[0].split('-')))
        r = r1.split('-')

        r2 = r[0].replace("v","")

        mydict[i] = '000'
        
        return mydict

    sort_orders = sorted(mydict.items(), key=lambda x: x[1], reverse=True)
    return sort_orders[0][0]
    
def getsecretarn(creds,secretid):
    client = boto3.client('secretsmanager', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    response = client.describe_secret(
        SecretId = secretid
    )
    print(response['ARN'])
    return response['ARN']
    
def addsecret(dict,secretarn,idx):
    dict['taskDefinition']['containerDefinitions'][idx]['repositoryCredentials'] = { "credentialsParameter": secretarn  }
    return dict

def getcontainerPort(dict,idx):
    print("Collecting container port value..")
    return dict['containerDefinitions'][idx]["portMappings"][0]["containerPort"]

def setessential(dict):
    #check if sidecar is present.. if so make essential as False
    if len(dict['containerDefinitions']) > 1 and dict['containerDefinitions'][1]['name'] == 's3tofrgmount':
        print("Sidecar is detected...")
        dict['containerDefinitions'][1]['essential'] = False
    if len(dict['containerDefinitions']) > 2 and dict['containerDefinitions'][2]['name'] == 'sidecar_dynatrace_oneagent':
        print("Dynatrace sidecar is detected...")
        dict['containerDefinitions'][2]['essential'] = False
    if len(dict['containerDefinitions']) > 1 and dict['containerDefinitions'][1]['name'] == 'sidecar_dynatrace_oneagent':
        print("Dynatrace sidecar is detected...")
        dict['containerDefinitions'][1]['essential'] = False
    if len(dict['containerDefinitions']) > 3 and dict['containerDefinitions'][3]['name'] == 'sidecar_dynatrace_oneagent':
        print("Dynatrace sidecar is detected...")
        dict['containerDefinitions'][3]['essential'] = False
    print(dict)
    return dict

def updatefields(dict,buildid,ccpuunit,cmemoryunit,tcpuunit,tmemoryunit,idx,*csettings):
    print("Updating fields..")
    if 'environment' in dict['taskDefinition']['containerDefinitions'][idx]:
        print("Env exists.. adding..")
        dict['taskDefinition']['containerDefinitions'][idx]['environment'].append({ "name": "SERVICEBUILDID", "value": buildid })
    else:
        print("Env does not exist.. creating..")
        dict['taskDefinition']['containerDefinitions'][idx]['environment'] = [{ "name": "SERVICEBUILDID", "value": buildid }]
    dict['taskDefinition']['containerDefinitions'][idx]['cpu'] = ccpuunit
    dict['taskDefinition']['containerDefinitions'][idx]['memory'] = cmemoryunit
    dict['taskDefinition']['cpu'] = tcpuunit
    dict['taskDefinition']['memory'] = tmemoryunit
    #check if sidecar is present.. if so make essential as False
    if len(dict['taskDefinition']['containerDefinitions']) > 1 and dict['taskDefinition']['containerDefinitions'][1]['name'] == 's3tofrgmount':
        print("Sidecar is detected as second container...")
        dict['taskDefinition']['containerDefinitions'][1]['essential'] = False
        if csettings:
            csettings1 = csettings[0]
            if 's3tofrgmount' in csettings1:
                ccpu = int(csettings1['s3tofrgmount']['cpu'])
                cmemory = int(csettings1['s3tofrgmount']['memory'])
                if ccpu > 0:
                    dict['taskDefinition']['containerDefinitions'][1]['cpu'] = 0
                    ccpu = 0
                if cmemory > 0:
                    dict['taskDefinition']['containerDefinitions'][1]['memory'] = 0
                    cmemory = 0
                if ccpu == 0 and cmemory == 0:
                    if 'cpu' in dict['taskDefinition']['containerDefinitions'][1]:
                        del dict['taskDefinition']['containerDefinitions'][1]['cpu']
                    if 'memory' in dict['taskDefinition']['containerDefinitions'][1]:
                        del dict['taskDefinition']['containerDefinitions'][1]['memory']
                del csettings1
            else:
                if 'cpu' in dict['taskDefinition']['containerDefinitions'][1]:
                        del dict['taskDefinition']['containerDefinitions'][1]['cpu']
                if 'memory' in dict['taskDefinition']['containerDefinitions'][1]:
                        del dict['taskDefinition']['containerDefinitions'][1]['memory']
                del csettings1
    if len(dict['taskDefinition']['containerDefinitions']) > 2 and dict['taskDefinition']['containerDefinitions'][2]['name'] == 'sidecar_dynatrace_oneagent':
        print("Dynatrace sidecar is detected as 3rd container...")
        dict['taskDefinition']['containerDefinitions'][2]['essential'] = False
        if csettings:
            csettings1 = csettings[0]
            if 'sidecar_dynatrace_oneagent' in csettings1:
                ccpu = int(csettings1['sidecar_dynatrace_oneagent']['cpu'])
                cmemory = int(csettings1['sidecar_dynatrace_oneagent']['memory'])
                if ccpu > 0:
                    dict['taskDefinition']['containerDefinitions'][2]['cpu'] = 0
                if cmemory > 0:
                    dict['taskDefinition']['containerDefinitions'][2]['memory'] = 0
                if ccpu == 0 and cmemory == 0:
                    print('setting cpu and memory for dyntrace to zero')
                    if 'cpu' in dict['taskDefinition']['containerDefinitions'][2]:
                        del dict['taskDefinition']['containerDefinitions'][2]['cpu']
                    if 'memory' in dict['taskDefinition']['containerDefinitions'][2]:
                        del dict['taskDefinition']['containerDefinitions'][2]['memory']
                del csettings1
            else:
                if 'cpu' in dict['taskDefinition']['containerDefinitions'][2]:
                        del dict['taskDefinition']['containerDefinitions'][2]['cpu']
                if 'memory' in dict['taskDefinition']['containerDefinitions'][2]:
                        del dict['taskDefinition']['containerDefinitions'][2]['memory']
                del csettings1
    if len(dict['taskDefinition']['containerDefinitions']) > 3 and dict['taskDefinition']['containerDefinitions'][3]['name'] == 'sidecar_dynatrace_oneagent':
        print("Dynatrace sidecar is detected as third container...")
        dict['taskDefinition']['containerDefinitions'][3]['essential'] = False
        if csettings:
            csettings1 = csettings[0]
            if 'sidecar_dynatrace_oneagent' in csettings1:
                ccpu = int(csettings1['sidecar_dynatrace_oneagent']['cpu'])
                cmemory = int(csettings1['sidecar_dynatrace_oneagent']['memory'])
                if ccpu > 0:
                    dict['taskDefinition']['containerDefinitions'][3]['cpu'] = 0
                if cmemory > 0:
                    dict['taskDefinition']['containerDefinitions'][3]['memory'] = 0
                if ccpu == 0 and cmemory == 0:
                    print('setting cpu and memory for dyntrace to zero')
                    if 'cpu' in dict['taskDefinition']['containerDefinitions'][3]:
                        del dict['taskDefinition']['containerDefinitions'][3]['cpu']
                    if 'memory' in dict['taskDefinition']['containerDefinitions'][3]:
                        del dict['taskDefinition']['containerDefinitions'][3]['memory']
                del csettings1
            else:
                if 'cpu' in dict['taskDefinition']['containerDefinitions'][3]:
                        del dict['taskDefinition']['containerDefinitions'][3]['cpu']
                if 'memory' in dict['taskDefinition']['containerDefinitions'][3]:
                        del dict['taskDefinition']['containerDefinitions'][3]['memory']
                del csettings1
    if len(dict['taskDefinition']['containerDefinitions']) > 1 and dict['taskDefinition']['containerDefinitions'][1]['name'] == 'sidecar_dynatrace_oneagent':
        print("Dynatrace sidecar is detected...")
        dict['taskDefinition']['containerDefinitions'][1]['essential'] = False
        if csettings:
            csettings1 = csettings[0]
            if 'sidecar_dynatrace_oneagent' in csettings1:
                dict['taskDefinition']['containerDefinitions'][1]['cpu'] = 0
                dict['taskDefinition']['containerDefinitions'][1]['memory'] = 0
                del csettings1
            else:
                if 'cpu' in dict['taskDefinition']['containerDefinitions'][1]:
                        del dict['taskDefinition']['containerDefinitions'][1]['cpu']
                if 'memory' in dict['taskDefinition']['containerDefinitions'][1]:
                        del dict['taskDefinition']['containerDefinitions'][1]['memory']
                del csettings1
    if len(dict['taskDefinition']['containerDefinitions']) > 2 and dict['taskDefinition']['containerDefinitions'][2]['name'] == 's3tofrgmount':
        print("Sidecar sidecar is detected...")
        dict['taskDefinition']['containerDefinitions'][2]['essential'] = False
        if csettings:
            csettings1 = csettings[0]
            if 's3tofrgmount' in csettings1:
                dict['taskDefinition']['containerDefinitions'][2]['cpu'] = 0
                dict['taskDefinition']['containerDefinitions'][2]['memory'] = 0
                del csettings1
            else:
                if 'cpu' in dict['taskDefinition']['containerDefinitions'][2]:
                        del dict['taskDefinition']['containerDefinitions'][2]['cpu']
                if 'memory' in dict['taskDefinition']['containerDefinitions'][2]:
                        del dict['taskDefinition']['containerDefinitions'][2]['memory']
                del csettings1
    if dict['taskDefinition']['containerDefinitions'][idx]['name'] == 'model-front':
        print("model front container is detected...")
        dict['taskDefinition']['containerDefinitions'][idx]['essential'] = True
        if csettings:
            csettings1 = csettings[0]
            dict['taskDefinition']['containerDefinitions'][idx]['cpu'] = csettings1['model-front']['cpu']
            dict['taskDefinition']['containerDefinitions'][idx]['memory'] = csettings1['model-front']['memory']
            del csettings1
    print(dict)
    return dict
    
def assumerole(rarn):
    #import socket
    #print(socket.gethostbyname("sts.amazonaws.com"))
    client = boto3.client('sts')
    response = client.assume_role(
    RoleArn=rarn,
    RoleSessionName='spinnaker-shs-session',
    DurationSeconds=1200,
    )
    return response['Credentials']

def remove_empty_from_dict(d):
    if type(d) is dict:
        return dict((k, remove_empty_from_dict(v)) for k, v in d.items() if v and remove_empty_from_dict(v))
    elif type(d) is list:
        return [remove_empty_from_dict(v) for v in d if v and remove_empty_from_dict(v)]
    else:
        return d

def listservices(bu,csp,loc,account,incr,cname,sname,creds,plvalue):
    client = boto3.client('ecs', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    response = { 'serviceArns': [], 'nextToken': 'first' }
    while 'nextToken' in response:
        if response['nextToken'] == 'first':
            responseNext = client.list_services(
                cluster = bu + csp + loc + '-' + account + '-' + incr  + '-' + cname,
                launchType = 'FARGATE'
            )
        else:
            responseNext = client.list_services(
                cluster = bu + csp + loc + '-' + account + '-' + incr  + '-' + cname,
                launchType = 'FARGATE',
                nextToken = response['nextToken'],
            )
        #print("responseNext is: "+str(responseNext['serviceArns']))
        #print("response is: "+str(response))
        del response['nextToken']
        response['serviceArns']=response['serviceArns']+responseNext['serviceArns']
        if 'nextToken' in responseNext:
            response['nextToken'] = responseNext['nextToken']
        #print("response now is: "+str(response['serviceArns']))
        #if 'nextToken' in response:
                #print("Next Token is: "+str(response['nextToken']))
    if 'NextToken' in response:
        #print("Deleting the NextToken")
        del response['nextToken']
    print("full response is "+str(response['serviceArns']))
    #PATCH
    #searchfor = '-'+bu+csp+loc+'-'+account+'-'+incr+'-ecs-container-'+cname+'-'+sname+'-v'
    #PATCH End
    if plvalue == 'NA':
        searchfor = '-'+bu+csp+loc+'-'+account+'-'+incr+'-ecs-service-'+sname+'-v'
    if plvalue != 'NA':
        searchfor = '-'+bu+csp+loc+'-'+account+'-'+incr+'-'+plvalue+'-ecs-service-'+sname+'-v'
    res = [i for i in response['serviceArns'] if searchfor in i]
    print("response is "+str(res))
    service_count = len(res)
    allservices = res
    if not res:
        if plvalue == 'NA':
            sname = bu + csp + loc + '-' + account + '-' + incr  + '-ecs-service-' +  sname
        if plvalue != 'NA':
            sname = bu + csp + loc + '-' + account + '-' + incr  + '-' + plvalue + '-ecs-service-' +  sname
    else:
        sname = find_latest_service(res)
        temp =  "/".join(reversed(sname.split("/")))
        sname1 = temp.split('/')
        sname = sname1[0]
        
    get_oldest_svcs = ''
    second_latest = ''
    if service_count > 3:
        print(allservices)
        svc_list = [i.rsplit('/',1)[1] for i in allservices ]
        get_oldest_svcs = [i for i in svc_list if i!= sname ]
        second_latest = find_latest_service(get_oldest_svcs)

        get_oldest_svcs = [i for i in get_oldest_svcs if i!= second_latest ]
        oldest_svc = find_lowest_service(get_oldest_svcs)
        get_oldest_svcs = [i for i in get_oldest_svcs if i!= oldest_svc ]
        get_oldest_svcs = ",".join(str(x) for x in get_oldest_svcs)
        
    
    return sname,service_count,allservices,get_oldest_svcs,second_latest

def describe_services(cname,sname,creds):
    client = boto3.client('ecs', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    response = client.describe_services(
    cluster=cname,
    services=[
    sname,
    ],
    )
    print(response)
    taskdefinition = response['services'][0]['taskDefinition']
    print("Fetched taskdefinition "+taskdefinition)
    return taskdefinition

def describe_services_tags(cname,sname,creds):
        client = boto3.client('ecs', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
        response = client.describe_services(
        cluster=cname,
        services=[
        sname,
        ],
        include=[
            'TAGS',
        ],
        )
        tags = response['services'][0]['tags']
        print("Fetched tags for service " + str(tags))
        return tags

#Added 06232022 for pipeline consolidation work -- Roshan   in progress #
def describe_services_lb_sg(cname,sname,creds):
    client = boto3.client('ecs', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    response = client.describe_services(
    cluster=cname,
    services=[
    sname,
    ],
    )
    print(json.dumps(response['services'][0]['deployments'][0]['networkConfiguration']))
    if 'loadBalancers' in response['services'][0]:
        service_lbs = response['services'][0]['loadBalancers']
    else:
        service_lbs = 'NF'
    if 'securityGroups' in response['services'][0]['deployments'][0]['networkConfiguration']['awsvpcConfiguration']:
        service_sgs = response['services'][0]['deployments'][0]['networkConfiguration']['awsvpcConfiguration']['securityGroups']
    else:
        service_sgs = 'NF'
    if 'subnets' in response['services'][0]['deployments'][0]['networkConfiguration']['awsvpcConfiguration']:
        service_subnets = response['services'][0]['deployments'][0]['networkConfiguration']['awsvpcConfiguration']['subnets']
    else:
        service_subnets = 'NF'
    return service_sgs,service_lbs,service_subnets

def get_sg_name(sgid,creds):
    client = boto3.client('ec2',aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    response = client.describe_security_groups(
        GroupIds=[
            sgid,
        ],
    )
    return response['SecurityGroups'][0]['GroupName']

def get_subnet_tagname(subnetid,creds):
    client = boto3.client('ec2',aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    response = client.describe_security_groups(
        GroupIds=[
            sgid,
        ],
    )
    return response['SecurityGroups'][0]['GroupName']

def describe_target_group(tgarn,creds):
    config = Config(retries=dict(max_attempts=10))
    client = boto3.client('elbv2',aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'], config=config)
    try:
        response = client.describe_target_groups(
            TargetGroupArns=[
            tgarn,
            ],
        )
        print("fetching target group response")
        print(response)
        return response
    except Exception as e:
        if e.response['Error']['Code'] == "Throttling":
            return 'Throttling Error'
        else:
            print(e)
            return 'Generic Error'
            
def describe_target_health(tgarn,creds):
    config = Config(retries=dict(max_attempts=10))
    client = boto3.client('elbv2',aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'], config=config)
    print(tgarn)
    try:
        response = client.describe_target_health(
            TargetGroupArn=tgarn
        )
        print(response)
        return response
    except Exception as e:
        print(e)
        if e.response['Error']['Code'] == "Throttling":
            return 'Throttling Error'
        else:
            print(e)
            return 'Generic Error'
            

def filter_subnet_type_by_tags(subnetid,creds):
    print("checking tags for subnet " + str(subnetid))
    client = boto3.client('ec2', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    response = client.describe_tags(
    Filters=[
        {
        'Name': 'key',
        'Values': [
            'immutable_metadata','immutable_metadata ',' immutable_metadata ',' immutable_metadata',
        ]
        },
        {
        'Name': 'resource-id',
        'Values': [
            subnetid
        ]
        },
    ],
    )
    print(response)
    for i in response['Tags']:
        if subnetid in i['ResourceId']:
            return i['Value']
# End

def describe_taskdefinition(tdarn,creds):
    client = boto3.client('ecs', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    response = client.describe_task_definition(
    taskDefinition=tdarn,
    )
    return response

def setautoscalepolicy(clustername,refid,metric,threshold,creds):
    client = boto3.client('application-autoscaling',aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    if metric == 'cpu':
        response = client.put_scaling_policy(
            PolicyName='fg-as-'+metric+'-'+clustername+'-'+refid,
            ServiceNamespace='ecs',
            ResourceId='service/' + str(clustername) + '/' + str(refid),
            ScalableDimension='ecs:service:DesiredCount',
            PolicyType='TargetTrackingScaling',
            TargetTrackingScalingPolicyConfiguration={
                'TargetValue': int(threshold),
                'PredefinedMetricSpecification': {
                   'PredefinedMetricType': 'ECSServiceAverageCPUUtilization',
                },
                'ScaleOutCooldown': 60,
                'ScaleInCooldown': 90,
            },
        )
    if metric == 'memory':
        response = client.put_scaling_policy(
            PolicyName='fg-as-'+metric+'-'+clustername+'-'+refid,
            ServiceNamespace='ecs',
            ResourceId='service/' + str(clustername) + '/' + str(refid),
            ScalableDimension='ecs:service:DesiredCount',
            PolicyType='TargetTrackingScaling',
            TargetTrackingScalingPolicyConfiguration={
                'TargetValue': int(threshold),
                'PredefinedMetricSpecification': {
                   'PredefinedMetricType': 'ECSServiceAverageMemoryUtilization',
                },
                'ScaleOutCooldown': 60,
                'ScaleInCooldown': 90,
            },
        )

def enableautoscaling(clustername,refid,creds,asgmin,asgmax):
    client = boto3.client('application-autoscaling',aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    response = client.register_scalable_target(
        ServiceNamespace='ecs',
        ResourceId='service/' + str(clustername) + '/' + str(refid),
        ScalableDimension='ecs:service:DesiredCount',
        MinCapacity=int(asgmin),
        MaxCapacity=int(asgmax)
    )
    
def update_service_with_tags(sarn,tags,creds):
    client = boto3.client('ecs', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    response = client.tag_resource(
    resourceArn=sarn,
    tags=tags
    )

def tag_resources_general(sarn,tags,creds):
    try:
        client = boto3.client('resourcegroupstaggingapi', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
        response = client.tag_resources(
        ResourceARNList=[
        sarn,
        ],
        Tags=tags
        )
        print(response)
    except Exception as e: 
        print(e)
    
def get_tag_resource(sarn,creds):
    client = boto3.client('resourcegroupstaggingapi', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    response = client.get_resources(
        ResourceARNList=[
        sarn,
    ]
    )
    return response
    
    
def uploadtos3(filename,bname,filecontent):
    s3 = boto3.client('s3')
    response = s3.put_object(Bucket=bname, Key=filename, Body=filecontent)

def downloadfroms3(filename,bname):
    client = boto3.client('s3')
    response = client.get_object(
        Bucket=bname,
        Key=filename,
    )
    return response
    
def setprops2jfrog(propsfile,key,value):
    #Add properties to repository once ECS service deploy is done.
    baseurl = os.environ['jfrogStorageApiUrl']
    #First Get the current property key and value using GET property API.
    templist1 = propsfile.split('/')
    tempvar1 = templist1[4:]
    newstring = '/'
    suburl = newstring.join(tempvar1)
    suburl = suburl+'='+key
    url=baseurl+'/'+suburl
    x = requests.get(url=url, headers={"X-JFrog-Art-Api":os.environ['jfrogApiKey']})
    out = json.loads(x.content)
    for i in out.keys():
        topkey = i
    if topkey == "errors":
        print("first entry")
        currentvalue = []
    if topkey == "properties" or topkey == "uri":
        print("property exists...")
        currentvalue = out['properties'][key]

    #Now PATCH the existing key and value with new value as per deployment.
    baseurl = os.environ['jfrogStorageApiUrl1']
    url=baseurl+'/'+suburl+'='+value
    currentvalue.append(value)
    myobj = { 'props': { key: currentvalue, key: currentvalue } }
    print("Patching the property "+url+ " with data "+json.dumps(myobj))
    x = requests.patch(url=url, data = json.dumps(myobj), headers={"X-JFrog-Art-Api":os.environ['jfrogApiKey']})
    out = str(x)
    print("jfrog docker image property updated: "+ str(propsfile) + " " + str(x.headers))
    print(out)
    print(x.content)
    return out

def getjfrogurl(bid):
    if '-docker-' in bid.split('/')[1]:
        #making sure it is docker repo.
        #get the repo.
        if '/' in bid:
            reponame = bid.split('/')[1]
            #get the hash id at the end.
            if ':' in bid:
                pathname = bid.split(':')[1]
                print('reponame is: '+str(reponame))
                print('pathname is: '+str(pathname))
            else:
                return 'fail: path not found'
        else:
            return 'fail: path not found'
        
        aqldata = ('items.find( { "path": {"$match":"*%s"}, "repo": {"$eq":"%s"}, "name": {"$match":"manifest.json"} })' %(pathname,reponame))
        print('AQL data to be sent to query is: '+str(aqldata))
        getartifacts = requests.post(os.environ['jfrogAqlUrl'], headers={"X-JFrog-Art-Api":os.environ['jfrogApiKey']}, data = aqldata)
        out=json.loads(getartifacts.content)
        print('AQL Response: '+str(out))
        if len(out['results']) > 1:
            return 'fail: multiple entries'
        for i in out['results']:
            if 'repo' in i and i['repo'] != '':
                print('Found repo as: '+str(i['repo']))
                if 'path' in i and i['path'] != '':
                    print('Found path as: '+str(i['path']))
                    docker_url = 'artifactory.saratestreachprod.awssaratestintranet.net/'+ i['repo'] + '/' + i['path']
                    #replace last slash with a colon instead.
                    docker_url = docker_url[::-1].replace('/', ':', 1)[::-1]
                    http_url = 'https://artifactory.saratestreachprod.awssaratestintranet.net/artifactory/' + i['repo'] + '/' + i['path'] + '/manifest.json?properties'
                    print(docker_url)
                    print(http_url)
                    return docker_url,http_url
                else:
                    return 'fail: path not found'
            return 'fail: path not found'
        return 'fail: path not found'
    else:
        return 'fail: path not found'

def post2jfrog(deployto,bid,spinnakerappname):
    if 'artifactory.saratestreachprod' not in bid and 'jfrog-sandbox.saratestreachprod' not in bid:
        #Search By Build ID using search jfrog API call.
        r = requests.get(os.environ['jfrogArtifactSearchApiUrl']+'?name='+bid, headers={"X-JFrog-Art-Api":os.environ['jfrogApiKey']})
        print(r.content)
        out = json.loads(r.content)
        out1 = []
        for i in out['results']:
            if 'docker--' in i['uri']:
                out1 = i['uri']
        #out1 = out['results'][0]['uri']
        if out1:
            jfrogbuildname = out1[::-1].split('/')[1][::-1]
        print("jfrogbuildname: "+jfrogbuildname)
        print('Checking issue from here')
        #Get Image URL name by supplying buildid and build name
        url = os.environ['jfrogBuildArtifactsApiUrl']
        if deployto == 'dev' or deployto == 'qa' or deployto == 'develop' or deployto == 'e2e':
          myobj = {'buildName': jfrogbuildname, 'buildNumber': bid, 'Deploy.Dev.Deployed': 'true'}
          x = requests.post(url=url, data = json.dumps(myobj), headers={"X-JFrog-Art-Api":os.environ['jfrogApiKey'], "Content-Type": "application/json"})
          out = json.loads(x.content)
        if deployto == 'uat' or deployto == 'prod' or deployto == 'release' or deployto == 'master' or deployto == 'hotfix': 
          print('This is not working')
          myobj = {'buildName': jfrogbuildname, 'buildNumber': bid, 'Deploy.Prod.Deployed': 'true'}
          x = requests.post(url=url, data = json.dumps(myobj), headers={"X-JFrog-Art-Api":os.environ['jfrogApiKey'], "Content-Type": "application/json"})
          out = json.loads(x.content)
          print(out)
        print('This is not working.....')  
          

        for i in out['results']:
            if bid in i['downloadUri']:
                out1 = i['downloadUri']
                print("Debug:", out1)
            else:
                out1 = out['results'][0]['downloadUri']
        #out1 = out['results'][0]['downloadUri']
        jfrogimagename = out1.split('/')
        del jfrogimagename[-1]
        del jfrogimagename[:2]
        out = "/"
        out = out.join(jfrogimagename)
        print(jfrogimagename)
        imageurl = out[::-1].replace('/', ':', 1)[::-1]
        print("imageurl : "+imageurl)
        #remove word artifactory from image url.
        imageurl1 = imageurl.split('/')
        del imageurl1[1]
        reponame = imageurl1[1]
        imageurlout = '/'
        imageurlout = imageurlout.join(imageurl1)
        imageurl_dev = imageurlout
        print("ImageURL Dev is "+str(imageurl_dev))
          
    #Create a prod string to check jfrog prod repository.
    if deployto == 'uat' or deployto == 'prod' or deployto == 'release' or deployto == 'master' or deployto == 'hotfix':
        t1 = reponame[::-1].split('-')
        orig_string = 'prod'
        t1[1] = orig_string[::-1]
        t2 = []
        for i in t1:
            t2.append(i[::-1])
        t2.reverse()
        out = '-'
        imageurl1[1] = out.join(t2)
        imageurlout = '/'
        imageurlout = imageurlout.join(imageurl1)
        imageurl_prod = imageurlout
        print("ImageURL Prod is "+str(imageurl_prod))
        jfrogimagename_prod = jfrogimagename
        jfrogimagename_prod[2] = imageurl1[1]

    #Create a dev string to check jfrog dev repository.
    if deployto == 'dev' or deployto == 'develop' or deployto == 'qa' or deployto == 'e2e':
        t1 = reponame[::-1].split('-')
        orig_string = 'dev'
        t1[1] = orig_string[::-1]
        t2 = []
        for i in t1:
            t2.append(i[::-1])
        t2.reverse()
        out = '-'
        imageurl1[1] = out.join(t2)
        imageurlout = '/'
        imageurlout = imageurlout.join(imageurl1)
        imageurl_dev = imageurlout
        print("ImageURL dev is "+str(imageurl_dev))
        jfrogimagename_dev = jfrogimagename
        jfrogimagename_dev[2] = imageurl1[1]
    
    if deployto == 'dev' or deployto == 'qa' or deployto == 'develop' or deployto == 'e2e':
        #Check if Dev or QA deployed is true.. If true return the image url or else return image Not AVailable.
        outfull = "/"
        outfull = 'https://'+outfull.join(jfrogimagename_dev)+'/manifest.json?properties'
        x = requests.get(outfull, headers={"X-JFrog-Art-Api":os.environ['jfrogApiKey']})
        out = json.loads(x.content)
        out1 = out['properties']['deploy.'+deployto+'.deployed']
        outcheck = json.dumps(out['properties']['jenkins.url'])
        outcheck1 = outcheck.replace('-', '')
        print("Checking if "+ spinnakerappname +" has permission for "+str(outcheck1))
        spinnakerapp_wl = os.environ['spinnakerapp_wl']
        print("Checking whitelisted Spinnaker Applications "+str(spinnakerapp_wl))
        outcheck = outcheck1.replace('[','')
        outcheck1 = outcheck.replace(']','')
        outcheck = outcheck1.replace('"','')
        #print("debug: outcheck1 is "+str(outcheck))
        #print("debug: spinnakerappname is "+str(spinnakerappname))
        if str(outcheck) == "https://cloudbees.saratestreachprod.awssaratestintranet.net/"+spinnakerappname+"/" or spinnakerappname in spinnakerapp_wl:
            print("Application permission granted..")
            if json.dumps(out1) == '["true"]':
                return imageurl_dev,outfull
        #return "ImageNA"

    if deployto == 'uat' or deployto == 'prod' or deployto == 'release' or deployto == 'master' or deployto == 'hotfix':
        #Check if UAT or Prod deployed is true.. If true return the image url or else return image Not AVailable.
        outfull = "/"
        print("jfrogimagename_prod")
        print(jfrogimagename_prod)
        outfull = 'https://'+outfull.join(jfrogimagename_prod)+'/manifest.json?properties'
        x = requests.get(outfull, headers={"X-JFrog-Art-Api":os.environ['jfrogApiKey']})
        out = json.loads(x.content)
        print(out)
        out1 = out['properties']['deploy.'+deployto+'.deployed']
        outcheck = json.dumps(out['properties']['jenkins.url'])
        outcheck1 = outcheck.replace('-', '')
        print("Checking if "+ spinnakerappname +" has permission for "+str(outcheck1))
        spinnakerapp_wl = os.environ['spinnakerapp_wl']
        print("Checking whitelisted Spinnaker Applications "+str(spinnakerapp_wl))
        outcheck = outcheck1.replace('[','')
        outcheck1 = outcheck.replace(']','')
        outcheck = outcheck1.replace('"','')
        if str(outcheck) == "https://cloudbees.saratestreachprod.awssaratestintranet.net/"+spinnakerappname+"/" or spinnakerappname in spinnakerapp_wl:
            print("Application permission granted..")
            if json.dumps(out1) == '["true"]':
                 return imageurl_prod,outfull
        #return "ImageNA"
        
def ec2deploy_ziptagging(validatetag,deployto,jfrogurl):
    try:
        reponame = jfrogurl.split('artifactory/')[1].split('/')[0]
        pathname = jfrogurl.split('artifactory/')[1].split(reponame)[1].replace('/','',1)
        print(reponame+'-'+pathname)
        aqldata = ('items.find( { "path": {"$match":"*%s"}, "repo": {"$eq":"%s"}, "name": {"$match":".zip"} })' %(pathname,reponame))
        print('AQL data to be sent to query is: '+str(aqldata))
        getartifacts = requests.get(os.environ['jfrogStorageApiUrl']+'/'+reponame+'/'+pathname, headers={"X-JFrog-Art-Api":os.environ['jfrogApiKey']})
        out=json.loads(getartifacts.content)
        print('AQL Response: '+str(out))
        deploytoenv = ['dev','qa','uat','release','prod']
        for i in deploytoenv:
            if i in deployto.lower():
                deployto = i
        
        if validatetag == 'validate':
            outfull = jfrogurl+'?properties'
            x = requests.get(outfull, headers={"X-JFrog-Art-Api":os.environ['jfrogApiKey']})
            out_prop = json.loads(x.content)
            print(out_prop)
            
            env_tagging = 'deploy.spinnaker.'+deployto+'.deployed'
            if env_tagging in out_prop['properties']:
                print(env_tagging)
                print(out_prop['properties'][env_tagging][0])
                if out_prop['properties'][env_tagging][0] == 'true':
                    print(out_prop['properties'][env_tagging][0])
                    return { 'statusCode': 200, 'body': json.dumps({ "message": 'Zip is validated successfully to deploy on '+deployto+' environment'  }) }
            
            return { 'statusCode': 400, 'body': json.dumps({ "message": 'Zip has not been tagged in artifactory for '+deployto+' environment'  }) }
        else:
            tag_env_json = {'dev':'qa','qa':'uat','uat':'canary','canary':'prod'}
            tag_env = tag_env_json[deployto]
            print(tag_env)
            restoredout = requests.put(os.environ['jfrogStorageApiUrl']+'/'+reponame+'/'+pathname+'?properties=deploy.spinnaker.'+tag_env+'.deployed=true', headers={"X-JFrog-Art-Api":os.environ['jfrogApiKey_r3user']})
            print(restoredout.status_code)
            
            if restoredout.status_code == 204:
                return { 'statusCode': 200, 'body': json.dumps({ "message": 'Zip has been successfully tagged as deploy.spinnaker.'+tag_env+'.deployed=true'  }) }
            else:
                return { 'statusCode': 400, 'body': json.dumps({ "message": restoredout.content  })}
    except Exception as e:
        print(e)
        return 'Generic Error'

    
def register_task_definition(family,taskRoleArn,executionRoleArn,networkMode,containerDefinitions,requiresCompatibilities,cpu,memory,volumes,creds,loggroupname):
    client = boto3.client('ecs', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    response = client.register_task_definition(
    family=family,
    taskRoleArn=taskRoleArn,
    executionRoleArn=executionRoleArn,
    networkMode=networkMode,
    containerDefinitions=containerDefinitions,
    requiresCompatibilities=requiresCompatibilities,
    cpu=cpu,
    memory=memory,
    volumes=volumes,
    )
    return response, response['taskDefinition']['taskDefinitionArn'],loggroupname

def modify_target_group(tgarn,tgpath,creds):
    client = boto3.client('elbv2', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    response = client.modify_target_group(
    TargetGroupArn=tgarn,
    HealthCheckPath=tgpath,
    )
    #print(response)
    return response
    
def register_target(tgarn,albarn,listenerport,creds):
    #print(creds)
    client = boto3.client('elbv2', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    counter = 0
    response_lb = client.describe_load_balancers(
                LoadBalancerArns=[
                    albarn,
                    ],
            )
    lbstatus = response_lb['LoadBalancers'][0]['State']['Code']
    while lbstatus != "active" and counter < 30:
        try:
            time.sleep(20)
            response = client.describe_load_balancers(
                LoadBalancerArns=[
                    albarn,
                    ],
            )
            lbstatus = response['LoadBalancers'][0]['State']['Code']
            counter = counter + 1
            print(lbstatus)
        except:
            time.sleep(20)
            response = client.describe_load_balancers(
                LoadBalancerArns=[
                    albarn,
                    ],
            )
            lbstatus = response['LoadBalancers'][0]['State']['Code']
            counter = counter + 1
            print('ALB load balancer status: '+str(lbstatus))
        print("LoadBalancer(ALB) status is "+str(lbstatus))
    response = client.register_targets(
                        TargetGroupArn= tgarn,
                        Targets=[
                            {
                                'Id': albarn,
                                'Port': int(listenerport)
                            },
                        ]
                    )
    return response
    
def stringsize(str):
    str1=str[:32]
    str2=''.join(str1)
    return str2

def reverse(s): 
    if len(s) == 0: 
        return s 
    else: 
        return reverse(s[1:]) + s[0] 
        
def create_target_group(name2,listenerport,_tgport,ttype,vpcid,creds,canary_taglist,*albarn):
    client = boto3.client('elbv2', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    revstring = reverse(name2)
    trimstring = stringsize(revstring)
    response = reverse(trimstring)
    name2=''.join(response)
    if name2.startswith("-"):
        name2 = name2[1:]
    print(name2)
    try:
        response = client.describe_target_groups(Names=[name2])
        #Check registered target for nlb*********************************************************
        return response
    except Exception as e:
        print(e)
        if e.response['Error']['Code'] == 'TargetGroupNotFound':
            if ttype == 'alb':
                response = client.create_target_group(
                Name=name2,
                Protocol='TCP',
                Port=int(listenerport),
                VpcId=vpcid,
                HealthCheckProtocol='HTTPS',
                HealthCheckPath='/',
                HealthCheckIntervalSeconds=7,
                HealthCheckTimeoutSeconds=5,
                HealthyThresholdCount=2,
                UnhealthyThresholdCount=3,
                Matcher={
                    'HttpCode': '200-299'
                },
                TargetType=ttype
                )
                print("Create target group response")
                print(response)
                tgarn = response['TargetGroups'][0]['TargetGroupArn']
                tag_resources_general(tgarn,canary_taglist,creds)
                if albarn:
                    print('registering to alb: '+str(albarn[0]))
                    r = register_target(tgarn,albarn[0],listenerport,creds)
                    
            else:
                print('Creating tg for alb')
                print("Listener port/tg port for alb tg:" + str(listenerport) + '/' +str(_tgport))
                response = client.create_target_group(
                Name=name2,
                Protocol='HTTPS',
                Port=int(listenerport),
                VpcId=vpcid,
                HealthCheckProtocol='HTTPS',
                HealthCheckPath='/',
                HealthCheckPort=str(_tgport),
                HealthCheckIntervalSeconds=7,
                HealthCheckTimeoutSeconds=5,
                HealthyThresholdCount=2,
                UnhealthyThresholdCount=3,
                Matcher={
                    'HttpCode': '200-499'
                },
                TargetType=ttype
                )
                tgarn = response['TargetGroups'][0]['TargetGroupArn']
                tag_resources_general(tgarn,canary_taglist,creds)
            return response
    
def get_listener(lbarn,creds):
    client = boto3.client('elbv2', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    response = client.describe_listeners(
        LoadBalancerArn=lbarn,
    )
    listenerarn = 'NF'
    listenercount = 0
    print("Describe listener response: "+str(response))
    for i in response['Listeners']:
        listenercount=listenercount+1
        #if _tgarn == i['DefaultActions'][0]['ForwardConfig']['TargetGroups']:
        listenerarn=i['ListenerArn']
        print("Listener response: "+str(listenerarn))
    return listenerarn
    
def getcertificate(certificatearn,creds):
    config = Config(retries=dict(max_attempts=10))
    client = boto3.client('acm', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],config=config)
    response = { 'CertificateSummaryList': [], 'NextToken': 'first' }
    while 'NextToken' in response:
        if response['NextToken'] == 'first':
            responseNext = client.list_certificates(
                    CertificateStatuses=[
                        'ISSUED',
                    ],
                    MaxItems=5
            )
        else:
            responseNext = client.list_certificates(
                 CertificateStatuses=[
                        'ISSUED',
                    ],
                    MaxItems=5,
                    NextToken=response['NextToken'],
        )
            
        del response['NextToken']
        response['CertificateSummaryList'] = response['CertificateSummaryList'] + responseNext['CertificateSummaryList']
        if 'NextToken' in responseNext:
            response['NextToken'] = responseNext['NextToken']
    if 'NextToken' in response:
        del response['NextToken']
    
    cert_found = False
    for i in response['CertificateSummaryList']:
        if certificatearn in i['CertificateArn']:
            cert_found = True
            break
        
    if not cert_found:
        errormsg = "Domain certificate not found in this account"
        return errormsg 
    return certificatearn
    
def createlistener(elbarn,listenerport,albarn,lbtype,canary_taglist,certificatearn,creds,*canary_nlb_tgarn):
    config = Config(retries=dict(max_attempts=10))
    client = boto3.client('elbv2', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],config=config)
    #certificatearn = getcertificate(creds)
    if lbtype == 'alb':
        response = client.create_listener(
        LoadBalancerArn=elbarn,
        Protocol='HTTPS',
        Port=int(listenerport),
        SslPolicy='ELBSecurityPolicy-TLS13-1-2-2021-06',
        Certificates=[
        {
            'CertificateArn': certificatearn,
        },
    ],
        DefaultActions=[
            {
                'Type': 'fixed-response',
                'FixedResponseConfig': {
                                'MessageBody': 'Error:This is default response when service header is not sent in the request',
                            'StatusCode': '299',
                            'ContentType': 'text/plain'
                        },
            },
        ]
        )
        print(response)
        listenerarn = response['Listeners'][0]['ListenerArn']
        tag_resources_general(listenerarn,canary_taglist,creds)
    if lbtype == 'network' and canary_nlb_tgarn:
        response = client.create_listener(
        LoadBalancerArn=elbarn,
        Protocol='TCP',
        Port=int(listenerport),
        DefaultActions=[
            {
                'Type': 'forward',
                    'TargetGroupArn': canary_nlb_tgarn[0]
            },
        ]
        )
        listenerarn = response['Listeners'][0]['ListenerArn']
        tag_resources_general(listenerarn,canary_taglist,creds)
    return response
    
def describe_listener_lb(lbarn,albarn,listenerport,lbtype,canary_taglist,certificatearn,creds,*canary_nlb_tgarn):
    config = Config(retries=dict(max_attempts=10))
    client = boto3.client('elbv2', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],config=config)
    try:
        print("loadbalancer arn for getting listener "+str(lbarn))
        print("Describe ELBV2 listeners")
        response = { 'listener_list': [], 'NextMarker': 'first' }
        while 'NextMarker' in response:
            if response['NextMarker'] == 'first':
                responseNext = client.describe_listeners(
                    LoadBalancerArn=lbarn,
                    PageSize=1
                )
            else:
                responseNext = client.describe_listeners(
                    LoadBalancerArn=lbarn,
                    Marker = response['NextMarker'],
                    PageSize=1
                )
                
            del response['NextMarker']
            response['listener_list'] = response['listener_list'] + responseNext['Listeners']
            if 'NextMarker' in responseNext:
                response['NextMarker'] = responseNext['NextMarker']
        if 'NextMarker' in response:
            del response['NextMarker']
        
        print("Listener response for loadbalancer "+str(lbarn))
        print(json.dumps(response))
        
        listener_port_list = []
        associated_alb_found = False
        if lbtype == 'network':
            if not response['listener_list']:
                listenerport = 9000
                print("Listener port for nlb "+str(listenerport))
                associated_alb_found = True
                listener_found = False
                listenerarn = ''
            else:    
                for i in response['listener_list']:
                    nlb_tgarn = i['DefaultActions'][0]['ForwardConfig']['TargetGroups'][0]['TargetGroupArn']
                    response_th =   describe_target_health(nlb_tgarn,creds)
                    if str(response_th['TargetHealthDescriptions'][0]['Target']['Id']) == str(albarn):
                       listenerport = i['Port']
                       associated_alb_found = True
                       listener_found = True
                       listenerarn = i['ListenerArn']
                    else:
                        listener_port_list.append(int(i['Port']))
                        
            if not associated_alb_found:
                listenerport = max(listener_port_list) + 100
                listener_found = False
        
        print('Response list')
        print(response)

        if lbtype == 'alb':
            if not response['listener_list']:
                listener_found = False
                print("Listener port for alb "+str(listenerport))
            else:
                for i in response['listener_list']:
                   if re.search('9[0-9]00$', str(i['Port'])):
                        print("Listener arn "+str(i['ListenerArn']))
                        listenerarn = i['ListenerArn']
                        listener_found = True
                        listenerport = i['Port']
                        print('returning search')
                   else:
                       print("Listener port for alb "+str(listenerport))
                       listener_found = False
                       print('else condition')
                
        if not listener_found:
            print('Creating listener')
            print('listenerport' + str(listenerport))
            if not listenerport:
                listenerarn = ''
            else:
                if canary_nlb_tgarn:
                    if str(canary_nlb_tgarn[0]) == 'sendback':
                        listenerarn = ''
                        #print(listenerarn)
                    else:   
                        response = createlistener(lbarn,listenerport,albarn,lbtype,canary_taglist,certificatearn,creds,canary_nlb_tgarn[0])
                        listenerarn = response['Listeners'][0]['ListenerArn']
                else:
                    response = createlistener(lbarn,listenerport,albarn,lbtype,canary_taglist,certificatearn,creds)
                    listenerarn = response['Listeners'][0]['ListenerArn']
            

            print("listener arn "+ listenerarn)
        return listenerarn,listenerport
    except Exception as e:
        if e.response['Error']['Code'] == "Throttling":
            return 'Throttling Error'
        else:
            print(e.response['Error']['Message'])
            return 'Generic Error'
    
def describe_listener(lbarn,listenerarn,http_header,creds):
    config = Config(retries=dict(max_attempts=10))
    client = boto3.client('elbv2', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],config=config)
    try:
        print("Describe ELBV2 listeners")
        print(lbarn)
        print(listenerarn)
        response = { 'rules_list': [], 'NextMarker': 'first' }
        while 'NextMarker' in response:
            if response['NextMarker'] == 'first':
                print("line_number_1509")
                responseNext = client.describe_rules(
                ListenerArn=listenerarn,
                PageSize=1
                )
            else:
                print("line_number_1515")
                responseNext = client.describe_rules(
                ListenerArn=listenerarn,
                Marker = response['NextMarker'],
                PageSize=1
                )

            del response['NextMarker']
            response['rules_list'] = response['rules_list'] + responseNext['Rules']
            print(response['rules_list'])
            print("line_number_1525")
            if 'NextMarker' in responseNext:
                print("line_number_1527")
                response['NextMarker'] = responseNext['NextMarker']
                
        if 'NextMarker' in response:
            print("line_number_1531")
            del response['NextMarker']
       
        tgarns = []
        print(response['rules_list'])
        for i in response['rules_list']:
            for j in i['Conditions']:
                if 'HttpHeaderConfig' in j:
                    if j['HttpHeaderConfig']['HttpHeaderName'] ==  'x-saratest-serviceid' and j['HttpHeaderConfig']['Values'][0] == http_header:
                        tgarns =  i['Actions'][0]['ForwardConfig']['TargetGroups']
                        print(tgarns)
                        
        print('returning from describe_listener' )
        
        return tgarns
    except Exception as e:
        if e.response['Error']['Code'] == "Throttling":
            return 'Throttling Error'
        else:
            print(e)
            return 'Generic Error'
            
def delete_listener(listenerarn,creds):
    client = boto3.client('elbv2',aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],config=config)
    response = client.delete_listener(
    ListenerArn=listenerarn
    )
    return response
    
def modify_listener(listenerarn,tglist,http_header,path_pattern,canary_taglist,creds):
    config = Config(retries=dict(max_attempts=10))
    client = boto3.client('elbv2', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],config=config)
    priority_list = []
    try:
        response = client.describe_rules(
        ListenerArn=listenerarn
        )
        modify_flag = False
        if 'Rules' in response:
            for i in response['Rules']:
                if len(i['Conditions']) > 0:
                    print("Entering condition")
                    priority_list.append(int(i['Priority']))
                    for j in i['Conditions']:
                        if 'HttpHeaderConfig' in j:
                            if j['HttpHeaderConfig']['HttpHeaderName'] ==  'x-saratest-serviceid' and str(j['HttpHeaderConfig']['Values'][0]) == http_header:
                                modify_flag = True
                                priority_num = i['Priority']
                                print('priority_num - '+ priority_num)
                                
        print("Priority list "+str(priority_list))
        if not priority_list:
            priority_out = 1
        else:
            priority_out = max(priority_list)+1
    
        if modify_flag:
            print("Modify flage exists:"+str(modify_flag))
            for i in response['Rules']:
                if i['Priority'] == priority_num:
                    #print (priority_num)
                    Rule_Arn = i['RuleArn']
            response = client.modify_rule(
                RuleArn=Rule_Arn,
                Conditions=[
                {
                    'Field': 'path-pattern',
                    'Values': [
                        path_pattern,
                    ],
                },
                {
                    'Field': 'http-header',
                    'HttpHeaderConfig': {
                            'HttpHeaderName': 'x-saratest-serviceid',
                            'Values': [
                                http_header
                            ]
                        },
                }
                
                    ],
                    Actions=[
                    {
                        'Type': 'forward',
                        'ForwardConfig': {
                        'TargetGroups': tglist
                        }
                    }
                    ],
                )
            print("Modify rules response")
            print(response)
        else:
            print('TG name:'+str(tglist[0]))
            print('TG only name'+str(tglist[0]['TargetGroupArn']))
            print("listener "+str(listenerarn))
            response = client.create_rule(
                        ListenerArn=listenerarn,
                        Conditions=[
                        {
                            'Field': 'path-pattern',
                            'Values': [
                                path_pattern,
                            ],
                        },
                        {
                            'Field': 'http-header',
                            'HttpHeaderConfig': {
                                    'HttpHeaderName': 'x-saratest-serviceid',
                                    'Values': [
                                        http_header
                                    ]
                                },
                        }
                        
                            ],
                            Priority=priority_out,
                            Actions=[
                            {   
                                'Type': 'forward',
                                'ForwardConfig': {
                                'TargetGroups': tglist
                                }
                            }
                            ],
                        )
            rulearn = response['Rules'][0]['RuleArn']
            canary_taglist["Name"] = 'Canaryrule-'+http_header
            tag_resources_general(rulearn,canary_taglist,creds)
        return response
    except Exception as e:
        if e.response['Error']['Code'] == "Throttling":
            return 'Throttling Error'
        else:
            print(e)
            return 'Generic Error'
    
def delete_target_group(tgarn,creds):
    client = boto3.client('elbv2', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    response = client.delete_target_group(
    TargetGroupArn=tgarn
    )
    return response
    
def fetch_tag_details(canary_appname,creds):
    client = boto3.client('appconfig')
    response = client.list_hosted_configuration_versions(
    ApplicationId='0np8q7j',
    ConfigurationProfileId='8kuidul',
    )
    
    version = response["Items"][0]["VersionNumber"]
    
    response = client.get_hosted_configuration_version(
    ApplicationId='0np8q7j',
    ConfigurationProfileId='8kuidul',
    VersionNumber=version
    )
    r = json.loads(response["Content"].read())
    for i in r["GREENFIELD"]:
        if i["ApplicationName"] == canary_appname:
            canary_taglist = i
            
    for k in canary_taglist:
        if canary_taglist[k] is None:
            canary_taglist[k] = "None"
    
    return canary_taglist

def create_security_group(lbname,vpcid,canary_taglist,creds):
    try:
        client = boto3.client('ec2',aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
        response = client.create_security_group(
            GroupName = lbname + '-' + 'SG',
            Description = lbname + '-' + 'SG',
            VpcId = vpcid)
        
        print(response)
        sgtags = []
        for key,val in canary_taglist.items():
            if key not in ['servicename','referenceid']:
                sgtags.append({'Key': key, 'Value': val})
        print(sgtags)
        
        response_tag = client.create_tags(
            Resources=[response['GroupId']
            ],
            Tags=sgtags
        )
        
        """
        response_tag = client.create_tags(
            Resources=[response['GroupId']
            ],
            Tags=[
            {
            'Key': 'ApplicationName',
            'Value': canary_taglist["ApplicationName"],
            },
            {
            'Key': 'ApplicationCode',
            'Value': canary_taglist["ApplicationCode"],
            },
            {
            'Key': 'CostCode',
            'Value': canary_taglist["CostCode"],
            },
            {
            'Key': 'ApplicationOwner',
            'Value': canary_taglist["ApplicationOwner"],
            },
            {
            'Key': 'SupportContact',
            'Value': canary_taglist["SupportContact"],
            },
            {
            'Key': 'ProvisioningTool',
            'Value': canary_taglist["ProvisioningTool"],
            },
        ],
        )
        """
        
        return response
    except Exception as e:
        print(e)
        
def add_inbound_rulesg(groupid,listenerport,subnets,creds):
    try:
        client = boto3.client('ec2',aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
        response = client.describe_subnets(
        SubnetIds=subnets
        )
        print("Response from describe subnets")
        print(response)
        subnet_ip = []
        subnetarn = response['Subnets'][0]['SubnetArn']
        accountid = subnetarn.split(':')[4]
        for i in response['Subnets']:
            subnet_ip.append(i['CidrBlock'])
            
        print("Subnet IP "+str(subnet_ip))
        
        response_rule = client.authorize_security_group_ingress(
            GroupId = groupid,
            IpPermissions=[
                {'IpProtocol': 'tcp',
                 'FromPort': int(listenerport),
                 'ToPort': int(listenerport),
                 'IpRanges': [{'CidrIp': subnet_ip[0]}, {'CidrIp': subnet_ip[1]}, {'CidrIp': subnet_ip[2]}]}
            ]
            )
        
        envsgwhitelisteing = ['186103555612']
        if accountid in envsgwhitelisteing:
            response_rule = client.authorize_security_group_ingress(
                GroupId = groupid,
                IpPermissions=[
                    {'IpProtocol': 'tcp',
                     'FromPort': int(listenerport),
                     'ToPort': int(listenerport),
                     'IpRanges': [{'CidrIp': '10.0.0.0/8'}]}
                ]
            )
        
        return response_rule
    except Exception as e:
        if e.response['Error']['Code'] == 'InvalidPermission.Duplicate':
            return 'Inbound rule already exists'
        else:
            print(e.response)
            return 'Generic Error'
            
def modifylb(arn,creds):
    config = Config(retries=dict(max_attempts=10))
    client = boto3.client('elbv2', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],config=config)
    response = client.modify_load_balancer_attributes(
        LoadBalancerArn=arn,
        Attributes=[
        {
            'Key': 'routing.http.xff_header_processing.mode',
            'Value': 'preserve',
        },

        {
            'Key': 'routing.http.xff_client_port.enabled',
            'Value': 'true',
        },
        {
            'Key': 'routing.http.preserve_host_header.enabled',
            'Value': 'true',
        },

        ],
    )
    print(response)
    print('exiting modify lb')
    return "OK"
    
def checkiflbexists(lbname,_servicesubnets,canary_taglist,creds,tg_response,canary_vpcid,*ttype):
    config = Config(retries=dict(max_attempts=10))
    client = boto3.client('elbv2', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],config=config)
    count = 1
    while True:
        if ttype:
            response_lb = fetch_nlb(lbname,_servicesubnets,canary_taglist,creds,canary_vpcid,ttype[0])
        else:
            response_lb = fetch_nlb(lbname,_servicesubnets,canary_taglist,creds,canary_vpcid)
        print("Response of loadbalancer: " +str(response_lb))
        lbarn = response_lb[2]['LoadBalancers'][0]['LoadBalancerArn']
        response = { 'listener_list': [], 'NextMarker': 'first' }
        while 'NextMarker' in response:
            if response['NextMarker'] == 'first':
                responseNext = client.describe_listeners(
                    LoadBalancerArn=lbarn,
                    PageSize=1
                )
            else:
                responseNext = client.describe_listeners(
                    LoadBalancerArn=lbarn,
                    Marker = response['NextMarker'],
                    PageSize=1
                )
                
            del response['NextMarker']
            response['listener_list'] = response['listener_list'] + responseNext['Listeners']
            if 'NextMarker' in responseNext:
                response['NextMarker'] = responseNext['NextMarker']
        if 'NextMarker' in response:
            del response['NextMarker']
        
        print("Response from loadbalaber for listener list:")
        print(json.dumps(response))
        listener_count = len(response['listener_list'])
        print("Total listeners for lb: " + str(listener_count))
        print(response_lb[2]['LoadBalancers'][0]['Type'])
        canary_alb_found = False
        print(json.dumps(tg_response))
        if response_lb[2]['LoadBalancers'][0]['Type'] == 'network':
            if '/app/' in tg_response['TargetGroups'][0]['LoadBalancerArns'][0]:
                canary_alb = tg_response['TargetGroups'][0]['LoadBalancerArns'][0].split('loadbalancer/app/')[1].split('/')[0]
                print("ALB name is: "+str(canary_alb))
                canary_alb_found = False
                for i in response['listener_list']:
                    #print(i['DefaultActions'][0]['TargetGroupArn'].split('tg-')[1].split('/')[0])
                    if i['DefaultActions'][0]['TargetGroupArn'].split('tg-')[1].split('/')[0] in canary_alb:
                        canary_alb_found = True
            
            if canary_alb_found:
                break
            
            #Maximum limit of NLB listeners is 50 and is not adjustable
            if listener_count == 50:
                print("Listener Count greater than 50 for NLB")
                count = count + 1
                lbname = lbname.rsplit('-',1)[0] + '-' + str(count)
                print("New NLB will be created: "+str(lbname))
            else:
                print("NLB is found for this account. We will use: "+str(lbname))
                break
            
        if response_lb[2]['LoadBalancers'][0]['Type'] == 'application':
            if '/app/' in tg_response['TargetGroups'][0]['LoadBalancerArns'][0]:
                break
            
            lbname_count = int(lbname.rsplit('-',1)[1])
            #print(response['listener_list'])
            if listener_count == 0:
                print("No listener found in ALB "+str(lbname))
                break;
            if listener_count > 0:
                listenerarn = response['listener_list'][0]['ListenerArn']
                print("Listener arn "+str(listenerarn))
                """
                response = client.describe_rules(
                ListenerArn=listenerarn
                )
                """
                response = { 'rules_list': [], 'NextMarker': 'first' }
                while 'NextMarker' in response:
                    if response['NextMarker'] == 'first':
                        responseNext = client.describe_rules(
                        ListenerArn=listenerarn,
                        PageSize=1
                        )
                    else:
                        responseNext = client.describe_rules(
                        ListenerArn=listenerarn,
                        Marker = response['NextMarker'],
                        PageSize=1
                        )
        
                    del response['NextMarker']
                    response['rules_list'] = response['rules_list'] + responseNext['Rules']
                    #print(response['rules_list'])
                    if 'NextMarker' in responseNext:
                        response['NextMarker'] = responseNext['NextMarker']
                    
                if 'NextMarker' in response:
                    del response['NextMarker']
                rules_count = len(response['rules_list'])
                print("No of rules in listener "+str(rules_count))
                #The ALB supports maximum 100 rules
                if rules_count == 100:
                    lbname_count = lbname_count + 1
                    lbname = lbname.rsplit('-',1)[0] + '-' + str(lbname_count)
                else:
                    break
    print("LB response: "+str(response_lb))
    print("LB name is: "+str(lbname))
    return response_lb[0],response_lb[1],lbname,response_lb[2]
 
def get_currenttime():
    from datetime import datetime
    datetime.utcnow()
    utc_time = datetime.utcnow() 
    timenow = utc_time.strftime('%Y%m%d %H%M%S')
    return timenow
    
def fetch_nlb(lbname,subnetname,canary_taglist,creds,vpcid,*ttype):
    config = Config(retries=dict(max_attempts=10))
    client = boto3.client('elbv2', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],config=config)
    print('Entering fetch_nlb: ' + str(lbname))
    vpclink_id = None
    revstring = reverse(lbname)
    trimstring = stringsize(revstring)
    response = reverse(trimstring)
    lbname=''.join(response)
    if lbname.startswith("-"):
        lbname = lbname[1:]
    try:
        response = client.describe_load_balancers(Names=[lbname])
        nlbarn = response['LoadBalancers'][0]['LoadBalancerArn']
        print(response)
        
        counter = 0

        if response['LoadBalancers'][0]['Type'] == 'network':
            print("NLB Name is: "+str(lbname))
            while response['LoadBalancers'][0]['State']['Code'] != "active" and counter < 15:
                counter = counter + 1
                time.sleep(20)
            
            vpclink_id = get_vpclink(nlbarn,lbname,canary_taglist,creds)

        return nlbarn,vpclink_id,response
    except Exception as e:
        if e.response['Error']['Code'] == 'LoadBalancerNotFound':
            if ttype:
                sgid = describe_sg_name(lbname,vpcid,canary_taglist,creds)
                print('Load balancer not found.. creating ALB...')
                response = client.create_load_balancer(
                Name=lbname,
                Subnets=subnetname,
                SecurityGroups=[
                   sgid,
                ],
                Scheme='internal',
                Type=str(ttype[0]),
                IpAddressType='ipv4'
                )
                print("SG response:" + str(response))
                albarn = response['LoadBalancers'][0]['LoadBalancerArn']
                tag_resources_general(albarn,canary_taglist,creds)
                modifylb(albarn,creds)
                counter = 0
                lbstatus = response['LoadBalancers'][0]['State']['Code']
                return albarn,sgid,response
            else:
                print('Load balancer not found.. creating NLB...')
                response = client.create_load_balancer(
                        	Name=lbname,
                        	Subnets=subnetname,
                        	Scheme='internal',
                        	Type='network',
                        	IpAddressType='ipv4',
                        	)
                nlbarn = response['LoadBalancers'][0]['LoadBalancerArn']
                tag_resources_general(nlbarn,canary_taglist,creds)
                lbstatus = response['LoadBalancers'][0]['State']['Code']
                counter = 0
                while lbstatus != "active" and counter < 20:
                    try:
                        time.sleep(20)
                        response = client.describe_load_balancers(
                            LoadBalancerArns=[
                                nlbarn,
                                ],
                        )
                        lbstatus = response['LoadBalancers'][0]['State']['Code']
                        counter = counter + 1
                        print("Loadbalancer provisioning status "+str(lbstatus))
                    except:
                        time.sleep(20)
                        response = client.describe_load_balancers(
                            LoadBalancerArns=[
                                nlbarn,
                                ],
                        )
                        lbstatus = response['LoadBalancers'][0]['State']['Code']
                        counter = counter + 1
                        print("Loadbalancer provisioning status "+str(lbstatus))
                    print("LoadBalancer status is "+str(lbstatus))
                vpclink_response = create_vpclink(lbname,nlbarn,canary_taglist,creds)
                #time.sleep(240)
                vpclink_id = vpclink_response['id']
                return nlbarn,vpclink_id,response
        if e.response['Error']['Code'] == 'Throttling':
            return 'Throttling Error'
        else:
            print(e.response)
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            return 'Generic Error'
            
def get_load_balancer_list(creds):
    config = Config(retries=dict(max_attempts=10))
    client = boto3.client('elbv2',aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],config=config)
    #response = client.describe_load_balancers()
    #pagination and marker required
    
    response = { 'LoadBalancers': [], 'NextMarker': 'first' }
    while 'NextMarker' in response:
        if response['NextMarker'] == 'first':
            responseNext = client.describe_load_balancers(PageSize=10)
        else:
            responseNext = client.describe_load_balancers(Marker = response['NextMarker'],
            PageSize=10)

        del response['NextMarker']
        response['LoadBalancers'] = response['LoadBalancers'] + responseNext['LoadBalancers']
        #print(response['LoadBalancers'])
        if 'NextMarker' in responseNext:
            response['NextMarker'] = responseNext['NextMarker']
            
    if 'NextMarker' in response:
        del response['NextMarker']
    return response
            
def get_load_balancer(lbarn,creds):
    config = Config(retries=dict(max_attempts=10))
    client = boto3.client('elbv2',aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],config=config)
    response = client.describe_load_balancers(LoadBalancerArns=[
        lbarn
    ]
    )
    return response   
    
def getplevel(vpcid,creds,*sname):
    client = boto3.client('ec2', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    response = client.describe_vpcs(
        VpcIds=[
            vpcid
    ],
    )
    for i in response['Vpcs'][0]['Tags']:
        if 'shared-vpc' in i['Key'].lower():
            if i['Value'].lower() == "yes":
                if sname:
                    print(sname[0])
                    if '--' in sname[0]:
                       out_sname=sname[0].split('--')[1].split('-')[3]
                    else:
                        out_sname=sname[0].split('-')[3]
                    print("Checking plevel for shared vpc")
                    print(out_sname)
                    return out_sname

        if i['Key'] == 'Name': 
            out = i['Value'].split('-')
    
    return out[2]
            

def describe_services_canary(cname,sname,creds):
    client = boto3.client('ecs',aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    response = client.describe_services(
    cluster=cname,
    services=[
    sname,
    ],
    )
    print(response)
    return response
    
def updateecsservice(cname,sname,containername,_tgarn,alb_tgarn,_tgport,_servicesubnets,_securityGroups,tddata,creds):
    client = boto3.client('ecs',aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    print("Target group arn/port: "+ _tgarn + "/" + str(_tgport) + " Service name: " + sname + " ALB tgarn: " + alb_tgarn)
    
    tddata['containerDefinitions'][0]['cpu'] = int(tddata['containerDefinitions'][0]['cpu'])
    tddata['containerDefinitions'][0]['memory'] = int(tddata['containerDefinitions'][0]['memory'])
    
    response_td = register_task_definition(sname,tddata['taskRoleArn'],tddata['executionRoleArn'],tddata['networkMode'],tddata['containerDefinitions'],tddata['requiresCompatibilities'],tddata['cpu'],tddata['memory'],tddata['volumes'],creds,'')
    
    response = client.update_service(
        cluster=cname,
        service=sname,
        taskDefinition = response_td[1],
        loadBalancers=[
            {
                'targetGroupArn': _tgarn,
                'containerName': containername,
                'containerPort': _tgport
            }
            ,
            {
                'targetGroupArn': alb_tgarn,
                'containerName': containername,
                'containerPort': _tgport
            },

        ],
        forceNewDeployment=True
    )
    return response

#Create API Gateway VPC Link for NLB consumption.
def create_vpclink(lbname,lbarn,tags,creds):
    client = boto3.client('apigateway',aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    response = client.create_vpc_link(
    name= lbname + '-canary-vpclink',
    description='NLB Canary VPC Link for cluster '+ lbname,
    targetArns=[
        lbarn,
    ],
    tags=tags
    )
    counter = 0
    while response['status'] != "AVAILABLE" and counter < 20:
        try:
            time.sleep(20)
        except:
            time.sleep(20)
    return response
    
def get_vpclink(lbarn,lbname,canary_taglist,creds):
    config = Config(retries=dict(max_attempts=10))
    client = boto3.client('apigateway',aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],config=config)
    vpclink = False
    response = { 'items': [], 'position': 'first' }
    print(response)
    
    while 'position' in response:
        if response['position'] == 'first':
            responseNext = client.get_vpc_links(
                            limit=10
                        )
        else:
            responseNext = client.get_vpc_links(
                            position= response['position'],
                            limit=10
                        )
        
        #print(responseNext)
        del response['position']
        response['items']=response['items']+responseNext['items']
        if 'position' in responseNext:
            response['position'] = responseNext['position']
    if 'position' in response:
        del response['position']
    
    print("VPC link response " +str(response))
        
    for i in response['items']:
        if lbarn in i['targetArns'][0]:
            if str(i['status']) != 'FAILED':
                vpc_linkid = i['id']
                print("VPC link id "+str(vpc_linkid))
                vpclink = True
    
    if not vpclink:
        vpclink_res = create_vpclink(lbname,lbarn,canary_taglist,creds)
        vpc_linkid = vpclink_res['id']
        
    return vpc_linkid
    
    
def describe_sg_name(lbname,vpcid,canary_taglist,creds):
    client = boto3.client('ec2',aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
    print(lbname + '-' + 'SG')
    response = client.describe_security_groups(
       Filters=[
            {
            'Name': 'group-name',
            'Values': [
               lbname + '-' + 'SG',
            ]
        },
     ],
    )
    print(response)
    if not response['SecurityGroups']:
        response = create_security_group(lbname,vpcid,canary_taglist,creds)
        return response['GroupId']
    
    return response['SecurityGroups'][0]['GroupId']
    
def validateimagetoapiexhange(asset_name,asset_version,jfrog_url):
    try:
        print(jfrog_url)
        jfrog_url=jfrog_url[1].rsplit("/",1)[0]
        #jfrog_artifactory_url=jfrog_url[1].replace(" ", "")
        jfrog_artifactory_url = jfrog_url
        print(jfrog_artifactory_url) 
        
        # Define the nuleSoft OAuth2 token endpoint URL
        token_url = "https://anypoint.nulesoft.com/accounts/api/v2/oauth2/token"
    
        # print(json.dumps(event,indent=2))
        
         # Build the request to fetch the token
        token_request_data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret
        }
        token_request_data_encoded = urllib.parse.urlencode(token_request_data).encode('utf-8')
        token_request = urllib.request.Request(token_url, data=token_request_data_encoded, method='POST')
    
        # Fetch the token from the nuleSoft token endpoint
        token_response = urllib.request.urlopen(token_request)
        token_data = json.loads(token_response.read().decode('utf-8'))
        
        access_token = token_data["access_token"]
        
        api_url = f"https://anypoint.nulesoft.com/exchange/api/v2/assets/8852b3f5-a873-488c-ac6d-0d542f038748/{asset_name}/{asset_version}/portal/pages/home"
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        
        api_request = urllib.request.Request(api_url, headers=headers)
        api_response = urllib.request.urlopen(api_request)
        
        # Read the HTML content of the response
        html_content = api_response.read().decode('utf-8')
        #print(html_content)

        # Extract the Artifactory URL from the HTML content using regex
        #artifactory_url_regex = r'<a href="(https?://[^/]+/artifactory/[^"]+)"'
        artifactory_url_regex = r'artifactory.saratestreachprod.awssaratestintranet.net/([^"]+)"'
        matches = re.findall(artifactory_url_regex, html_content)
        print(matches)
        print(html_content)
        artifactory_url = matches[0] if matches else None
        

        # Check if the Spinnaker application name is present in the Artifactory URL
        if artifactory_url.replace(':','/') in jfrog_artifactory_url:
                print(f"this is compare url {artifactory_url}")
                print(f"this is jfrog {jfrog_artifactory_url}")
           
                # Conditions matched, continue deployment
                message = "Deployment continued as "+str(jfrog_artifactory_url)+"matcing with API exchange."
                status_code = 200
        else:
            # Application name not found, terminate deployment
            message = "Deployment terminated because "+str(jfrog_artifactory_url)+" does not match with API exchange."
            status_code = 502
            

            jfrog_artifactory_url = artifactory_url
            

        # Return the HTML content, extracted Artifactory URL, and deployment message in the response
        result = {
            "artifactory_url": jfrog_artifactory_url,
            "message": message,
            "API_details": html_content
        }
        print(json.dumps(result))
        return {
            'statusCode':status_code,
            'body': json.dumps(result)
        }
    except Exception as e:
        print(e)
        print(f"Error fetching data from nuleSoft API: {str(e)}")
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        result = {
            "message": "Deployment terminated because artifactory_url does not match with API exchange"
        }
        return {
            'statusCode': 502,
            # 'body': 'Error fetching data from nuleSoft API'
            'body': json.dumps(result)
        }

def describe_image(imageid,creds):
    try:
        img_repo = imageid.split('/')[1].split(':')[0]
        image_tag = imageid.split(':')[1]
        print(img_repo)
        print(image_tag)
        client = boto3.client('ecr', aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],)
        response = client.describe_images(
        repositoryName=img_repo,
        imageIds=[
            {
                'imageTag': image_tag
            },
        ]
        )
        return response
    except Exception as e:
        #print(e.response)
        return(e.response)

def validate_build_env(buildid,deployto):
    try:
        plevel_mapping = {'dev':'0','qa':'1','uat':'2','prod':'9'}
        image_repo = buildid.split('/')[1].split(':')[0]
        build_env = re.findall(r"(-\d-)", image_repo)[0].replace('-','')
        for key,value in plevel_mapping.items():
            if value == build_env:
                build_env = key
                break
        print(str(build_env).lower()+" / "+str(deployto).lower())
        if str(build_env).lower() != str(deployto).lower():
            return { 'statusCode': 404, 'body': json.dumps("Input ecr service build id "+str(buildid)+" doesnot belong to "+str(deployto)+" environment.. Please reverify") }
        return { 'statusCode': 200, 'body': json.dumps("Input ecr service build id is successfully validated for "+str(deployto)+"environment") }
    except Exception as e:
        print(e)
        return { 'statusCode': 404, 'body': json.dumps({"message": f"please verify your build enviornment \n'buildid:{buildid}'\n'deployto:{deployto}'\n" + str(e)}) }
    
def validate_git_sod(jfrogurl):
    # Fetch metadata from JFrog
    print(f"test{jfrogurl}test")
    print(type(jfrogurl))
    x = requests.get(jfrogurl, headers={"X-JFrog-Art-Api": os.environ['jfrogApiKey']})
    print(x.content)
    if x.status_code != 200:
        return {"status": "error", "message": f"Failed to fetch JFrog metadata: {x.content}"}
    out_prop = json.loads(x.content)
    env_tagging = 'git.url'
    env_tagging_1 = 'git.branch'
    env_tagging_2 = 'git.hash'
    # env_tagging_3 = 'git.log'
    if env_tagging in out_prop['properties']:
        git_url = out_prop['properties'][env_tagging][0]
        git_url = git_url.rstrip(".git")
        print(git_url)
    else:
        return {"status": "error", "message": "Git URL not found in JFrog metadata."}
    if env_tagging_1 in out_prop['properties']:
        git_branch = out_prop['properties'][env_tagging_1][0]
        print(git_branch)
    else:
        return {"status": "error", "message": "Git branch not found in JFrog metadata."}
    if env_tagging_2 in out_prop['properties']:
        git_hash = out_prop['properties'][env_tagging_2][0]
        print(git_hash)
    else:
        return {"status": "error", "message": "Git hash not found in JFrog metadata."}
    # if env_tagging_3 in out_prop['properties']:
    #     git_log = out_prop['properties'][env_tagging_3]
    # else:
    #     return {"status": "error", "message": "Git log not found in JFrog metadata."}    
    # Parse GitLab project details
    GITLAB_DOMAIN = "gitlab.saratestintranet.net"
    parsed = urllib.parse.urlparse(git_url)
    path = parsed.path.strip('/')
    encoded_path = urllib.parse.quote(path, safe='')
    # Extract commit ID
    commit_id = git_hash.split("-")[-1]   
    TOKEN = "000000000000000"
    if not TOKEN:
        return {"status": "error", "message": "GITLAB_TOKEN environment variable not set."}
    # Get GitLab project ID
    gitlab_url = f"https://{GITLAB_DOMAIN}"
    api_url = f"{gitlab_url}/api/v4/projects/{encoded_path}"
    headers = {"Private-Token": TOKEN}
    response = requests.get(api_url, headers=headers)
    print(response.content)
    if response.status_code != 200:
        return {"status": "error", "message": f"Error fetching project ID: {response.text}"}    
    project_id = response.json()["id"]
    # Get commit details
    commit_api_url = f"{gitlab_url}/api/v4/projects/{project_id}/repository/commits/{commit_id}"
    commit_response = requests.get(commit_api_url, headers=headers)
    print(commit_response.content)
    if commit_response.status_code == 200:
        commit_data = commit_response.json()
        commit_author = commit_data["author_email"]
        committer = commit_data["committer_email"]
    else:
        return {"status": "error", "message": f"Error fetching commit details: {commit_response.text}"}
    # Get merge request approvers
    mr_api_url = f"{gitlab_url}/api/v4/projects/{project_id}/merge_requests"
    mr_response = requests.get(mr_api_url, headers=headers)
    print(mr_response.content)
    approver_emails = []
    if mr_response.status_code == 200:
        merge_requests = mr_response.json()
        for mr in merge_requests:
            approvers = mr.get("approved_by", [])
            approver_emails = [approver["user"]["email"] for approver in approvers] if approvers else []
    else:
        return {"status": "error", "message": f"Error fetching merge request approvers: {mr_response.text}"}
    print(f"commit_author: {commit_author}\ncommitter:{committer}\napprover_emails : {approver_emails}")
    return {
        "commit_author": commit_author,
        "committer": committer,
        "approver_emails": approver_emails
    }    
    
    
def lambda_handler(event, context):
    # Log the incoming event for debugging
    logger.info("Received event")
    logger.debug(f"Event details: {json.dumps(event)}")


    try:
        #comment below line if testing from within Lambda.
        event = json.loads(urllib.parse.unquote(str(event["body"])))
        print(event)
        #uncomment below line when testing within Lambda only.
        #event = event["body"]
        accounttype = ['production','uat','prod','master','release','hotfix']
        jfrog_url = event.get("jfrog_url")
        pipeline_executor = event.get("pipeline_executor")
        
        #zip artifact tagging for R3 in ec2
        if 'validatetag' in event:
            out = ec2deploy_ziptagging(event['validatetag'],event['deployto'],event['jfrogurl'])
            return out
        
        #Get Jfrog Image
        #---------------
        if 'GetImageUrl' in event and event['GetImageUrl'] == "true":
            print(event['buildid'])
            #Get data from dynamodb
            
            if event['deployto'] in accounttype:
                out=getrecord_dynamodb_table_crauth(event['buildid'],'Requested','wanv-sap-9-cr-authcheck','us-east-1')
                print(out)
                tablename = 'wanv-sap-9-cr-authcheck'
                cr_awsregion = 'us-east-1'
                if 'Item' not in out:
                    tablename = 'waoh-sap-9-cr-authcheck'
                    cr_awsregion = 'us-east-2'
                    out=getrecord_dynamodb_table_crauth(event['buildid'],'Requested','waoh-sap-9-cr-authcheck','us-east-2')
                    if 'Item' not in out:
                        out=getrecord_dynamodb_table_crauth(event['buildid'],'Requested','wafr-sap-9-cr-authcheck','eu-central-1')
                        if 'Item' not in out:
                            return { 'statusCode': 404, 'body': json.dumps('Please add auth pipleine and ensure it should not be ignored for any environment. Refer https://confluence.corpprod.awssaratestintranet.net/display/CPEC/Spinnaker+Service+Now+Change+Request+validation+success+criteria') }
                        tablename = 'wafr-sap-9-cr-authcheck'
                        cr_awsregion = 'eu-central-1'
                if 'pipelinejson' in out['Item']:
                    print(out['Item']['pipelinejson'])
                    out_del = deleterecord_dynamodb_table_crauth(event['buildid'],tablename,cr_awsregion)
                    print(out_del)
            else:
                out=getrecord_dynamodb_table_crauth(event['buildid'],'Requested','wanv-sap-9-cr-authcheck','us-east-1')
                print(out)
                tablename = 'wanv-sap-9-cr-authcheck'
                cr_awsregion = 'us-east-1'
                if 'Item' not in out:
                    tablename = 'waoh-sap-9-cr-authcheck'
                    cr_awsregion = 'us-east-2'
                    out=getrecord_dynamodb_table_crauth(event['buildid'],'Requested','waoh-sap-9-cr-authcheck','us-east-2')
                    if 'Item' not in out:
                        out=getrecord_dynamodb_table_crauth(event['buildid'],'Requested','wafr-sap-9-cr-authcheck','eu-central-1')
                        if 'Item' not in out:
                            print('Printing out: '+str(out))
                            return { 'statusCode': 404, 'body': json.dumps('Please add auth pipleine and ensure it should not be ignored for any environment. Refer https://confluence.corpprod.awssaratestintranet.net/display/CPEC/Spinnaker+Service+Now+Change+Request+validation+success+criteria') }
                        tablename = 'wafr-sap-9-cr-authcheck'
                        cr_awsregion = 'eu-central-1'
                print(out)
                if 'accounttype' in out['Item']:
                    print(out['Item']['accounttype'])
                    if out['Item']['accounttype'] == 'account_uat' or out['Item']['accounttype'] == 'account_production':
                        out_del = deleterecord_dynamodb_table_crauth(event['buildid'],tablename,cr_awsregion)
                        return { 'statusCode': 404, 'body': json.dumps('Please ensure lower environment images should not be deployed to uat and production account.Failing the pipeline- Refer https://confluence.corpprod.awssaratestintranet.net/display/CPEC/Spinnaker+Service+Now+Change+Request+validation+success+criteria') }

                if 'pipelinejson' in out['Item']:
                    print(out['Item']['pipelinejson'])
                    out_del = deleterecord_dynamodb_table_crauth(event['buildid'],tablename,cr_awsregion)
                    print(out_del)
                
            #End
            if 'ecr' in event['buildid']:
                out  = validate_build_env(event['buildid'],event['deployto'])
                if str(out['statusCode']) != '200':
                    return { 'statusCode': out['statusCode'], 'body': out['body'] }
                
                awsregion = event['buildid'].split('/')[0].split('.ecr.')[1].replace('.amazonaws.com','')
                ecr_accountid = event['buildid'].split('.')[0]
                #Businessunit, CSP and Location
                ecr_bucl = event['buildid'].split('/')[1].split('-')[0].upper()
                ecr_account = event['buildid'].split('/')[1].split('-')[1].upper()

                if awsregion == 'us-east-1':
                    creds = assumerole('arn:aws:iam::'+ecr_accountid+':role/SL-ROL-'+ecr_bucl+'-'+ecr_account+'-'+'fargate-lambda-role')
                if awsregion == 'us-east-2':
                    creds = assumerole('arn:aws:iam::'+ecr_accountid+':role/SL-ROL-'+ecr_bucl+'-'+ecr_account+'-'+'fargate-lambda-role-us-east-2')
                if awsregion == 'eu-central-1':
                    creds = assumerole('arn:aws:iam::'+ecr_accountid+':role/SL-ROL-'+ecr_bucl+'-'+ecr_account+'-'+'fargate-lambda-role-eu-central-1')
                if awsregion == 'eu-west-1':
                    creds = assumerole('arn:aws:iam::'+ecr_accountid+':role/SL-ROL-'+ecr_bucl+'-'+ecr_account+'-'+'fargate-lambda-role-eu-west-1')

                out = describe_image(event['buildid'],creds)
                #print(out)
                if str(out['ResponseMetadata']['HTTPStatusCode']) == '200':
                    out_list = event['buildid'],"ECR Service buildid successfully validated"
                    return { 'statusCode': 200, 'body': json.dumps(out_list) }
                else:
                    print(out['Error'])
                    return { 'statusCode': 404, 'body': json.dumps(out['Error']) }

                out = 'Image Not Available or servicebuild is incorrect. Please provide complete Image URI in input.'
                return { 'statusCode': 404, 'body': json.dumps(out) }
            
            
            if 'artifactory.saratestreachprod' in event['buildid'] or 'jfrog-sandbox.saratestreachprod' in event['buildid']:
                print('developer supplied full url.. Which is OK..So checking to make sure image exists via AQL.')
                out = getjfrogurl(event['buildid'])
                if 'path not found' in out:
                    return { 'statusCode': 404, 'body': json.dumps('wrong docker supplied.. check syntax: example: artifactory.saratestreachprod.awssaratestintranet.net/saratestib-docker-dev-local/integration-services/pay_it_mqinject_v2_svc:12341-12342-1234c') }
                if 'multiple entries' in out:
                    return { 'statusCode': 404, 'body': json.dumps('wrong docker supplied.. multiple images found..syntax:artifactory.saratestreachprod.awssaratestintranet.net/saratestib-docker-dev-local/integration-services/pay_it_mqinject_v2_svc:12341-12342-12345') }
                return { 'statusCode': 200, 'body': json.dumps(out) }
            out_1 = post2jfrog(event['deployto'], event['buildid'], event['spinnakerappname'])
            print(f"post2jfrog output - {out_1}")            
            jfrogurl = str(out_1).split(',')[-1].strip(" ')\n").lstrip()
            print(f"DEBUG: JFrog URL - {jfrogurl}")            
            committer = validate_git_sod(jfrogurl)
            committer = list(committer.values())
            committer = [str(value).strip().lower() for value in committer]
            print(f"committers: {committer}")
            triggeredby = event.get('triggered-by',"").strip().lower()
            print (f"triggeredby:{triggeredby}")
            print(f"committer:{committer}")
            if not triggeredby:
                return {'statusCode': 400, "body":json.dumps('no details about user who triggers the pipeline')}         
            if triggeredby in committer:
                 return {'statusCode': 403, "body":json.dumps({"status":"failed","reason":"Pipeline excutor is part of commiter,author approver list"})}
            else:
                print("good to go...")      
            out = post2jfrog(event['deployto'], event['buildid'], event['spinnakerappname'])
            print('post2jfrog output is: '+str(out))            
            if out:
                if event['buildid'] in ['230608-214111-b42f999','240911-054103-c8c7c2d','231017-101412-a4fe2bf','240404-204222-0b07277']:
                    result = validateimagetoapiexhange(event['assetName'],event['assetVersion'],out)
                    if result['statusCode'] == 200:
                        result_body = json.loads(result['body'])
                        out = out + (result_body['message'],result_body['API_details'],)
                        return { 'statusCode': 200, 'body': json.dumps(out) }
                    else:
                        out_msg = 'Deployment terminated because '+str(out[0])+' does not match with API exchange'
                        return { 'statusCode': 404, 'body': json.dumps(out_msg) }
                        #print(out_msg)
                        #return { 'statusCode': 200, 'body': json.dumps(out) }
                else:
                    print('else output: '+str(out))
                    return { 'statusCode': 200, 'body': json.dumps(out) }
            out = 'Image Not Available or Manifest file not marked ready to deploy. Please double check the service id provided.'
            return { 'statusCode': 404, 'body': json.dumps(out) }
        
    
        # GetTaskDefinition - Networking only 
        if 'GetTaskDefinition' in event and event['GetTaskDefinition'] == "networking":
            print(event)
            
            cname = event['clustername']
            sname = event['servicename']
            BusinessUnit = cname[0]
            Csp = cname[1]
            Location = cname[2]+cname[3]
            Account = cname.split('-')[1]
            awsregions = { "NV": "us-east-1", "OH": "us-east-2", "FR": "eu-central-1" }
            awsregion = awsregions[Location]
            if 'cdtool' in event:
                cdtool = event['cdtool']
            else:
                cdtool = 'armory'
            
    
            if awsregion == 'us-east-1':
                creds = assumerole('arn:aws:iam::'+event['AccountId']+':role/SL-ROL-'+BusinessUnit+Csp+Location+'-'+Account+'-'+'fargate-lambda-role')
            if awsregion == 'us-east-2':
                creds = assumerole('arn:aws:iam::'+event['AccountId']+':role/SL-ROL-'+BusinessUnit+Csp+Location+'-'+Account+'-'+'fargate-lambda-role-us-east-2')
            if awsregion == 'eu-central-1':
                creds = assumerole('arn:aws:iam::'+event['AccountId']+':role/SL-ROL-'+BusinessUnit+Csp+Location+'-'+Account+'-'+'fargate-lambda-role-eu-central-1')
            if awsregion == 'eu-west-1':
                creds = assumerole('arn:aws:iam::'+event['AccountId']+':role/SL-ROL-'+BusinessUnit+Csp+Location+'-'+Account+'-'+'fargate-lambda-role-eu-west-1')
                
            timenow = time.time()
            
            print("Networking Start..")
            _servicedetails = describe_services_lb_sg(cname,sname,creds)
            _servicesgs = _servicedetails[0]
            _servicelbs = _servicedetails[1]
            _servicesubnets = _servicedetails[2]
            _tgport = 000
            if _servicesgs != "NF":
                _securityGroupNames = []
                _securityGroups = []
                print("Checking service groups..")
                for i in _servicesgs:
                    _sgname=get_sg_name(i,creds)
                    _securityGroups.append(i)
                    _securityGroupNames.append(_sgname)
                print(_securityGroups)
                print(_securityGroupNames)
            if _servicelbs != "NF":
                _targetGroup = []
                _tgarngroup = []
                print("Checking service target groups..")
                for i in _servicelbs:
                    _tgarn = i['targetGroupArn']
                    _tgname = _tgarn.split('/')[1]
                    _tgport = i['containerPort']
                    #tgname=describe_target_group(tgarn)
                    _targetGroup.append(_tgname)
                    _tgarngroup.append(_tgarn)
                print(_targetGroup)
            if _servicesubnets != "NF":
                _subnetTypes = []
                print("Checking service subnets..")
                for i in _servicesubnets:
                    _temp = filter_subnet_type_by_tags(i,creds)
                    mytagvalue = _temp.split(':')[1].replace('}','').replace('"','')
                    _subnetTypes.append(mytagvalue)
                    _subnetTypes = sorted(set(_subnetTypes))
                print(_subnetTypes)
            print("Networking End..")
    
            #Check if target group path change is requested.. -- 08212022
            if 'tgupdate' in event:
                tgprops = json.loads(event['tgupdate'])
                if 'tgpath' in tgprops:
                    print(tgprops['tgpath'])
                    print("Modifying the health check path for: "+str(_tgarn))
                    response = modify_target_group(_tgarn,tgprops['tgpath'],creds)
                    if response['ResponseMetadata']['HTTPStatusCode'] >= 200 and response['ResponseMetadata']['HTTPStatusCode'] < 300:
                        for i in response['TargetGroups']:
                            if tgprops['tgpath'] in i['HealthCheckPath']:
                                print('%s healthcheck path is updated to %s successfully' % (_tgarn,tgprops['tgpath']))
                                tgpathupdate='success'
                    else:
                        print('%s healthcheck path update to %s failed.' % (_tgarn,tgprops['tgpath']))
                        tgpathupdate='failed'
            else:
                tgpathupdate='not_applicable'
    
            cleandict = {}
            consolidate_dict = {}
            if _securityGroupNames:
                consolidate_dict['_securityGroupNames'] = _securityGroupNames
            if _securityGroups:
                consolidate_dict['_securityGroups'] = _securityGroups
            if _targetGroup:
                consolidate_dict['_targetGroup'] = _targetGroup
            if _subnetTypes:
                consolidate_dict['_subnetTypes'] = _subnetTypes
            if _tgport:
                consolidate_dict['_tgport'] = _tgport
            if tgpathupdate:
                consolidate_dict['_tgpathupdate'] = tgpathupdate
            print(json.dumps(consolidate_dict))
            
            cleandict['networking'] = consolidate_dict
            
            jsonout = json.dumps(cleandict)
            print(jsonout)
            if cdtool == 'armory':
                return { 'statusCode': 200, 'body': jsonout }
            if cdtool != 'armory':
                cleandict['artifacts'] = [cleandict.pop('networking')]
                print(cleandict['artifacts'])
                jsonout1 = json.dumps(cleandict)
                return { 'statusCode': 200, 'body': jsonout1 }
            
            """
            if cdtool == 'armory':
               cleandict['consolidated'] = consolidate_dict
               jsonout1 = json.dumps(cleandict)
               print(jsonout1)
               return { 'statusCode': 200, 'body': jsonout1 }
            else    
               print(cleandict['networking'])
               cleandict['artifacts'] = [cleandict.pop('networking')]
               print(cleandict['artifacts'])
               #jsonout is for storing the taskdefinition without the top key called "artifacts"
               jsonout = json.dumps(cleandict['artifacts'][0])
               webhook_out = cleandict
        
                #jsonout1 = json.dumps(cleandict)
               print(jsonout)
               out = uploadtos3(event['referenceid']+'.json',event['savebuckettd'],jsonout)
               #time.sleep(3)
               #out = uploadtos3('cw_log_link-'+event['referenceid']+'.json',event['savebuckettd'],cloudwatch_log_link)
            
               cleandict['consolidated'] = consolidate_dict
               jsonout1 = json.dumps(cleandict)
               print(jsonout1)
            return { 'statusCode': 200, 'body': jsonout1 }
            """
        #Get Task Definition
        #--------------------
        if 'GetTaskDefinition' in event and event['GetTaskDefinition'] == "true":
            if event['awsregion'] == 'us-east-1':
                creds = assumerole('arn:aws:iam::'+event['AccountId']+':role/SL-ROL-'+event['BusinessUnit']+event['Csp']+event['Location']+'-'+event['Account']+'-'+'fargate-lambda-role')
            if event['awsregion'] == 'us-east-2':
                creds = assumerole('arn:aws:iam::'+event['AccountId']+':role/SL-ROL-'+event['BusinessUnit']+event['Csp']+event['Location']+'-'+event['Account']+'-'+'fargate-lambda-role-us-east-2')
            if event['awsregion'] == 'eu-central-1':
                creds = assumerole('arn:aws:iam::'+event['AccountId']+':role/SL-ROL-'+event['BusinessUnit']+event['Csp']+event['Location']+'-'+event['Account']+'-'+'fargate-lambda-role-eu-central-1')
            if event['awsregion'] == 'eu-west-1':
                creds = assumerole('arn:aws:iam::'+event['AccountId']+':role/SL-ROL-'+event['BusinessUnit']+event['Csp']+event['Location']+'-'+event['Account']+'-'+'fargate-lambda-role-eu-west-1')
            
            timenow = time.time()
            
            print("Spinnaker Executing taskdefinition check...")
            print("clustername is: " + event['clustername'])
            print("servicename is: " + event['refid'])
            print("BusinessUnit is: " + event['BusinessUnit'])
            print("Csp is: " + event['Csp'])
            print("Location is: " + event['Location'])
            print("Increment is: " + event['Increment'])
            print("Account is: " + event['Account'])
            print("AccountId is: " + event['AccountId'])
            print("rollbackversion is: " + event['rollbackversion'])
            print("SERVICEBUILDID is: " + event['SERVICEBUILDID'])
            print("taskcpuunit is: " + event['taskcpuunit'])
            print("taskmemoryunit is: " + event['taskmemoryunit'])
            print("containercpuunit is: " + event['containercpuunit'])
            print("containermemoryunit is: " + event['containermemoryunit'])
            print("awssecretmanager_name is: " + event['awssecretmanager_name'])
            print("Job referenceid is: " + event['referenceid'])
            print("taskdefinition storage bucket in s3 is: " + event['savebuckettd'])
            if 'ENVIRONMENTVARS' in event:
                print("environment variables list is: " + str(event['ENVIRONMENTVARS']))
            if 'ENVIRONMENTFILES' in event:
                print("environment files list is: " + str(event['ENVIRONMENTFILES']))
            if 'VOLUMESLIST' in event:
                print("volumes list is: " + str(event['VOLUMESLIST']))
            plvalue = 'NA'
            #Three possibilities for finding the PL value. 1. Users sending PL in the input parameter. 2. From targetcontainer parameter or 3. awssecretmanager parameter
            #Option 1. (users sending PL value)
            if 'plevel' in event and event['plevel'] != "":
                print("PL Value found from input: "+str(event['plevel']))
                plvalue=event['plevel']
            #Option 2. (from targetcontainer parameter if sent from input.)
            if 'targetcontainer' in event and event['targetcontainer'] != "":
                print("Targetted container in this service is: " + str(event['targetcontainer']))
                targetcontainer = event['targetcontainer']
                #check if the container is main container or not. If not, we cannot get the PL from here. check below to see if this is main container by checking few parameters.
                if '-ecs-service-' in targetcontainer and event['BusinessUnit'] in targetcontainer and event['Account'] in targetcontainer:
                    if targetcontainer.split('-')[3].isnumeric():
                        plvalue = targetcontainer.split('-')[3]
                        print("PL Value found from targetcontainer input: "+str(plvalue))
            else:
                #we want to set targetcontainer to xxxx as targetcontainer was not sent from input.
                targetcontainer = 'xxxx'
            #Option 3. (from awssecretmanager parameter. it is usually sent from input. So it is more reliable to get PL from here.)
            if 'awssecretmanager_name' in event:
                asm = event['awssecretmanager_name']
                asmlist = asm.split(',')
                for i in asmlist:
                    if '-ecs-service-' in i:
                        tmp1 = i.split(':')[0].replace("'","").replace("[","")
                        if tmp1.split('-')[3].isnumeric():
                            plvalue=tmp1.split('-')[3]
                            print("PL Value found from awssecrets input: "+str(plvalue))
            if plvalue == 'NA':
                print("No Production Level (PL) found.. proceeding..")
            #Options end.                
            cname = event['BusinessUnit'] + event['Csp'] + event['Location'] + '-' + event['Account'] + '-' + event['Increment']  + '-' + event['clustername']
            if plvalue == 'NA':
                sname = event['BusinessUnit'] + event['Csp'] + event['Location'] + '-' + event['Account'] + '-' + event['Increment']  + '-ecs-service-' +  event['refid']
            else:
                sname = event['BusinessUnit'] + event['Csp'] + event['Location'] + '-' + event['Account'] + '-' + event['Increment']  + '-' + str(plvalue) + '-ecs-service-' +  event['refid']
            #Patch added 2/27/2021
            PATCH_sname = sname
            #Patch end
        
            servicelist = listservices(event['BusinessUnit'],event['Csp'],event['Location'],event['Account'],event['Increment'],event['clustername'],event['refid'],creds,plvalue)
            sname = servicelist[0]
            print("Task definition will be pulled from the service name named "+sname)
        
            td = describe_services(cname,sname,creds)
            
            print('Networking Consolidation Begin')
            _servicedetails = describe_services_lb_sg(cname,sname,creds)
            _servicesgs = _servicedetails[0]
            _servicelbs = _servicedetails[1]
            _servicesubnets = _servicedetails[2]
            _tgport = 000
            if _servicesgs != "NF":
                _securityGroupNames = []
                _securityGroups = []
                print("Checking service groups..")
                for i in _servicesgs:
                    _sgname=get_sg_name(i,creds)
                    _securityGroups.append(i)
                    _securityGroupNames.append(_sgname)
                print(_securityGroups)
                print(_securityGroupNames)
            if _servicelbs != "NF":
                _targetGroup = []
                _tgarngroup = []
                print("Checking service target groups..")
                for i in _servicelbs:
                    _tgarn = i['targetGroupArn']
                    _tgport = i['containerPort']
                    _tgname = _tgarn.split('/')[1]
                    #tgname=describe_target_group(tgarn)
                    _targetGroup.append(_tgname)
                    _tgarngroup.append(_tgarn)
                print(_targetGroup)
            if _servicesubnets != "NF":
                _subnetTypes = []
                print("Checking service subnets..")
                for i in _servicesubnets:
                    _temp = filter_subnet_type_by_tags(i,creds)
                    mytagvalue = _temp.split(':')[1].replace('}','').replace('"','')
                    _subnetTypes.append(mytagvalue)
                    _subnetTypes = sorted(set(_subnetTypes))
                print(_subnetTypes)
            print('Networking Consolidation End')
    
            dictout = describe_taskdefinition(td,creds)
            
            idx = 0
            containerIndex = 0
            listlen = len(dictout['taskDefinition']['containerDefinitions'])
            while idx < listlen:
                if dictout['taskDefinition']['containerDefinitions'][idx]['name'] == targetcontainer:
                    containerIndex = idx
                idx = idx+1
            print("Container to be updated has Index "+str(containerIndex))
            
            for i in dictout['taskDefinition']['containerDefinitions'][containerIndex]['environment']:
                if (i["name"] == "SERVICEBUILDID"):
                    del(i["name"])
                    del(i["value"])
                    
            #Remove below entries so Spinnaker deploy works
            del(dictout['ResponseMetadata'])
            del(dictout['taskDefinition']['taskDefinitionArn'])
            del(dictout['taskDefinition']['status'])
            del(dictout['taskDefinition']['revision'])
            del(dictout['taskDefinition']['requiresAttributes'])
            del(dictout['taskDefinition']['compatibilities'])
            if 'registeredAt' in dictout['taskDefinition']:
                del(dictout['taskDefinition']['registeredAt'])
                del(dictout['taskDefinition']['registeredBy'])
            #End cremove keys
        
            #Adding time to the json and deleting spinnaker hates it.. to be revisited..
            dictout['taskDefinition']['lastupdate'] = timenow
            del(dictout['taskDefinition']['lastupdate'])
            
            #Patches added 2/27/2021
            dictout['taskDefinition']['containerDefinitions'][0]['name'] = PATCH_sname
            dictout['taskDefinition']['family'] = PATCH_sname
            # End patches
    
            #Remove null values
            cleandict = remove_empty_from_dict(dictout)
    
            #Get and Add secret ARN for imageurl in the taskdefinition.
            if 'awssecretmanager_name' in event:
                #print(event['awssecretmanager_name'])
                awssecretid = event['awssecretmanager_name']
            else:
                awssecretid = 'jfrogSecret'
    
            chars_to_replace = { ']': '', '[': '', ' ': '', "'": ''}
            new_string = event['awssecretmanager_name'].translate(str.maketrans(chars_to_replace))
            
            new_string = new_string.split(",")
            idx = 0
            listlen = len(cleandict['taskDefinition']['containerDefinitions'])
            while idx < listlen:
                out = [i for i in new_string if cleandict['taskDefinition']['containerDefinitions'][idx]['name'] in i]
                print("out is " + str(out))
                if out:
                    containername = out[0].split(':')[0]
                    awssecretid = out[0].split(':')[1]
                    print("Container name is "+containername)
                    print("AWS Secret Name is "+awssecretid)
                    if containername == cleandict['taskDefinition']['containerDefinitions'][idx]['name']:
                        print("Getting Secret for "+containername)
                        if 'ecr' not in event['SERVICEBUILDID'].lower():
                            secretarn = getsecretarn(creds,awssecretid)
                            print("Secret ARN is: "+secretarn)
                            cleandict = addsecret(cleandict,secretarn,idx)
                            print(cleandict)
                idx = idx + 1
    
            #Update build id in the container ENV
            if 'capacitysettings' in event:
                string1 = json.loads(event['capacitysettings'])
                cleandict = updatefields(cleandict,event['SERVICEBUILDID'],event['containercpuunit'],event['containermemoryunit'],event['taskcpuunit'],event['taskmemoryunit'],containerIndex,string1)
                print(cleandict)
            else:
                cleandict = updatefields(cleandict,event['SERVICEBUILDID'],event['containercpuunit'],event['containermemoryunit'],event['taskcpuunit'],event['taskmemoryunit'],containerIndex)
            
            #Update ENVIRONMENT VARS
            if 'ENVIRONMENTVARS' in event:
                print(event['ENVIRONMENTVARS'])
                if (event['ENVIRONMENTVARS'] != 'none' and event['ENVIRONMENTVARS'] != ''):
                    #chars_to_replace = { ']': '', '[': '', ' ': '', "'": '', '{': '', '}': '',}
                    #chars_to_replace = { ']': '', '[': '',  "'": '', '{': '', '}': '',}
                    chars_to_replace = { ']': '', '[': '', '{': '', '}': '',}
                    new_string = event['ENVIRONMENTVARS'].translate(str.maketrans(chars_to_replace))
                    new_string = new_string.replace("' ,", "',")
                    new_string = new_string.replace("'  ,", "',")
                    new_string = new_string.split("',")
                    print(new_string)
                    for i in new_string:
                        keyval = i.split(':',1)
                        k0 = keyval[0].strip()
                        k1 = keyval[1].strip()
                        if k0.startswith("'") or k0.endswith("'"):
                            k0 = k0[1:-1]
                        if k1.startswith("'"):
                            k1 = k1[1:]
                        if k1.strip().endswith("'"):
                            k1 = k1[:-1]
                        #if k1.startswith("'") or k1.strip().endswith("'"):
                            #k1 = k1[1:-1]
                        print(k0)
                        print(k1)
                        updateenvvars(cleandict,k0,k1,containerIndex)
                        
            #Update ENVIRONMENT Files
            if 'ENVIRONMENTFILES' in event:
                print(event['ENVIRONMENTFILES'])
                if (event['ENVIRONMENTFILES'] != 'none' and event['ENVIRONMENTFILES'] != ''):
                    chars_to_replace = { ']': '', '[': '', '{': '', '}': '',}
                    new_string = event['ENVIRONMENTFILES'].translate(str.maketrans(chars_to_replace))
                    print(new_string)
                    new_string = new_string.replace("' ,", "',")
                    print(new_string)
                    new_string = new_string.replace("'  ,", "',")
                    print(new_string)
                    new_string = new_string.split("',")
                    print(new_string)
                    for i in new_string:
                        keyval = i.split(':',1)
                        k0 = keyval[0].strip()
                        k1 = keyval[1].strip()
                        if k0.startswith("'") or k0.endswith("'"):
                            k0 = k0[1:-1]
                        if k1.startswith("'"):
                            k1 = k1[1:]
                        if k1.strip().endswith("'"):
                            k1 = k1[:-1]
                        #if k1.startswith("'") or k1.strip().endswith("'"):
                            #k1 = k1[1:-1]
                        print(k0)
                        print(k1)
                        updateenvfiles(cleandict,k0,k1,containerIndex)

            
            #Update VOLUMES
            if 'VOLUMESLIST' in event:
                if (event['VOLUMESLIST'] != 'none' and event['VOLUMESLIST'] != ''):
                    string1 = json.loads(event['VOLUMESLIST'])
                    vollist=string1['volumes'].split(",")
                    cpathlist=string1['cpaths'].split(",")
                    print("Volumes to be created or updated are "+ str(vollist))
                    print("Container Paths to be created for mounts are "+str(cpathlist))
                    count=0
                    for i in vollist:
                        #print(i)
                        #print(cpathlist[count])
                        updateVolumes(cleandict,i,containerIndex)
                        setBindVolume(cleandict,cpathlist[count],i,containerIndex)
                        count=count+1
            #Add volumesFrom and dependsOn if requested..
            if 'attachs3tocustom' in event and event['attachs3tocustom'] == "true":
                print("Attaching s3 volume to custom container..")
                attachvolume(cleandict,containerIndex)
            
            print(cleandict['taskDefinition'])
            cleandict['artifacts'] = [cleandict.pop('taskDefinition')]
            print(cleandict['artifacts'])
            #jsonout is for storing the taskdefinition without the top key called "artifacts"
            jsonout = json.dumps(cleandict['artifacts'][0])
            #webhook_out will be sent back to webhook as webhook is adamant about top key called "artifacts"
            containerport_out = getcontainerPort(cleandict['artifacts'][0],containerIndex)
            myport = {'containerPort': containerport_out}
            #webhook_out = json.dumps(containerport_out),cleandict
            webhook_out = cleandict
            
            #Spinnaker upgrade and OpsMX patch..
            #cleandict['artifacts'] = [cleandict.pop('artifacts'),myport]
            #Patch end..
            #log_stream_name = os.environ.get('AWS_LAMBDA_LOG_STREAM_NAME')
            #log_log_name = os.environ.get('AWS_LAMBDA_LOG_GROUP_NAME')
            #cloudwatch_log_link = { log_log_name: log_stream_name }
    
            jsonout1 = json.dumps(cleandict)
            print(jsonout)
            out = uploadtos3(event['referenceid']+'.json',event['savebuckettd'],jsonout)
            #time.sleep(3)
            #out = uploadtos3('cw_log_link-'+event['referenceid']+'.json',event['savebuckettd'],cloudwatch_log_link)
            
            #[start]Canary deployment
            vpclink_id = None
            if 'deploy_strategy' in event:
                if event['deploy_strategy'] == 'canary':
                    print("This is a Spinnaker Canary deployment...")
                    checkcert = getcertificate(event['certificatearn'],creds)
                    if 'not found' in checkcert:
                        return { 'statusCode': 502, 'body': json.dumps({ "message": "please verify your certificatearn:" +str(checkcert) }) }
                    
                    latestsvc = sname
                    tglist = []
                    first_canary_migration = False
                    #for testing the ecs
                    #latestsvc = 'appdemosamples--WANV-SAP-01-ecs-service-web-prod-v059'
                    #_tgarn = 'arn:aws:elasticloadbalancing:us-east-1:517949891193:targetgroup/WANV-SAP-01-web-prod-tg-v060/e24e454603f7d87e'
                    print("latest service found - "+latestsvc)
                    print("task definition for latest version of the service: " + str(cleandict))
                    
                    #Fetching container name to update ecs service
                    for idx in cleandict['artifacts'][0]['containerDefinitions']:
                        if idx['essential'] == True:
                            canary_container = idx['name']
                        
                    #Finding the version for target group from service 
                    if '--' in latestsvc:
                        tgversion = latestsvc.split('-').pop()
                        tgversion_curr = tgversion
                        tgversion = 'v' + '{:03}'.format(int(tgversion.replace('v','')) + 1)
                    else:
                        tgversion = 'v000'
                        #This version is for base service canary target group
                        tgversion_curr = 'v00b'
                    
                    #Adding tagging for each resource(More necessary key values can be added here)
                    if event['canary_appname'] == 'novalue':
                        errmsg = "Please select the application name from drop down"
                        return { 'statusCode': 502, 'body': json.dumps({ "message": str(errmsg) }) }
                    canary_taglist = fetch_tag_details(event['canary_appname'],creds)
                    canary_taglist["ProvisioningTool"] = "Spinnaker"
                    canary_taglist["Updated_date"] = 'UTC ' + str(get_currenttime())
                    canary_taglist["referenceid"] = event["referenceid"]
                    
                    #condition is for settraficrouting stage after deployment
                    if 'svccreated' in event and event['svccreated'] == 'true':
                        sname_lowest = find_lowest_service(servicelist[2])
                        print("Oldest service of ecs:"+ str(sname_lowest))
                        if sname_lowest == latestsvc:
                            sname_lowest = [item for item in servicelist[2] if not(item in latestsvc)]
                        else:
                            temp =  "/".join(reversed(sname_lowest.split("/")))
                            sname_lowest1 = temp.split('/')
                            sname_lowest = sname_lowest1[0]
                            sname = sname_lowest
                            
                    #Fetching tg count associated to oldest service    
                    svc_response = describe_services_canary(cname,sname,creds)
                    tgarn_cnt = len(svc_response['services'][0]['loadBalancers'])
                    
                    #if tgarn_cnt > 1 and 'svccreated' not in event:
                        #return { 'statusCode': 502, 'body': json.dumps({ "message": "ECS service has already two target group associated.. Hence failing the pipeline!! Please contact Devops Team" }) }
                    
                    if len(_tgarngroup) > 1:
                        print("Target group more than one attached to service - "+str(_tgarngroup))
                        for i in _tgarngroup:
                            if '-atg-' in i:
                                _tgarn = i
                    
                    #Fetching target group details for latest service
                    canary_tg_response = describe_target_group(_tgarn,creds)
                    print("Target group "+str(_tgarn)+" response")
                    print(json.dumps(canary_tg_response))
                    if canary_tg_response == 'Throttling Error':
                        canary_tg_response = describe_target_group(_tgarn,creds)
                    if canary_tg_response == 'Generic Error':
                        return { 'statusCode': 502, 'body': json.dumps({ "message": f"please verify your targetgroup exist and its configuration.\\n _tgarn:{_tgarn}, \\ncredentials:{creds} \n" + str(canary_tg_response) }) } 
                    canary_vpcid = canary_tg_response['TargetGroups'][0]['VpcId']
                    
                    #Fetching or creating Canary NLB

                    if 'canary_nlb' in event:
                        if 'svccreated' in event and event['svccreated'] == 'true':
                            canary_nlbarn = []
                            canary_nlbarn.append(event['canary_nlb'])
                        else:
                            canary_nlb = event['BusinessUnit'] + event['Csp'] + event['Location'] + '-' + event['Account'] + '-' + getplevel(canary_vpcid,creds,sname) + '-Canary-NLB-1'
                            canary_nlbarn = checkiflbexists(canary_nlb,_servicesubnets,canary_taglist,creds,canary_tg_response,canary_vpcid)
                            if canary_nlbarn == 'Throttling Error':
                                 canary_nlbarn = checkiflbexists(canary_nlb,_servicesubnets,canary_taglist,creds,canary_tg_response,canary_vpcid)
                            if canary_nlbarn == 'Generic Error':
                                 return { 'statusCode': 502, 'body': json.dumps({ "message": f"please verify your loadbalancer exists. \ncanary_nlb:{canary_nlb}, \n_servicesubnets:{_servicesubnets}, \ncanary_taglist:{canary_taglist},\ncreds:{creds}, \ncanary_tg_response:{canary_tg_response},\ncanary_vpcid:{canary_vpcid} " +str(canary_nlbarn) }) }

                        
                    #Checking if the service need to be migrated on the basis of tg count
                    if tgarn_cnt == 1:
                        
                        find_lb_arn = canary_tg_response['TargetGroups'][0]['LoadBalancerArns'][0]
                        #Checking the existing nlb existence
                        if '/net/' in find_lb_arn:
                            app_lb_res = get_load_balancer_list(creds)
                            app_lb_count = 0
                            app_lb_list = []
                            app_lb_dict = {}
                            for i in app_lb_res['LoadBalancers']:
                                if i['Type'] == 'application' and i['VpcId'] == canary_vpcid and cname in i['LoadBalancerName']:
                                    app_lb_count = app_lb_count + 1
                                    app_lb_list.append(i['LoadBalancerName'])
                                    app_lb_dict.add(i['LoadBalancerName'],i['LoadBalancerArn'])

                            
                            #Creating Canary ALB for existing NLB facing service
                            lbname = event['BusinessUnit'] + event['Csp'] + event['Location'] + '-' + event['Account'] + '-' + getplevel(canary_vpcid,creds,sname) + '-' +event['clustername'].split('-fg-')[0] + '-' + 'ALB-1'
                            migrate_alb_arn = checkiflbexists(lbname,_servicesubnets,canary_taglist,creds,canary_tg_response,canary_vpcid,'application')
                            if migrate_alb_arn == 'Throttling Error':
                                 migrate_alb_arn = checkiflbexists(lbname,_servicesubnets,canary_taglist,creds,canary_tg_response,canary_vpcid,'application')
                            if migrate_alb_arn == 'Generic Error':
                                 return { 'statusCode': 502, 'body': json.dumps({ "message": f"please verify your load balancer exists. \nlbname:{lbname}, \n_servicesubnets:{_servicesubnets}, \ncanary_taglist:{canary_taglist}, \ncreds:{creds}, \ncanary_tg_response:{canary_tg_response}, \ncanary_vpcid:{canary_vpcid}, \napplication" +str(canary_nlbarn) }) } 
                                 
                            canary_alb = migrate_alb_arn[2]

                            #Fetching listener details for canary nlb
                            print("Fetching listener details for canary nlb")
                            lb_res = describe_listener_lb(canary_nlbarn[0],migrate_alb_arn[0],'','network',canary_taglist,event['certificatearn'],creds,'sendback')
                            
                            #Fetching listener details for canary alb
                            print("Fetching listener details for canary alb")
                            lb_res = describe_listener_lb(migrate_alb_arn[0],migrate_alb_arn[0],lb_res[1],'alb',canary_taglist,event['certificatearn'],creds)
                            
                            
                            #Creating target group for existing service for alb
                            print('Creating target group for existing service for alb')
                            canary_alb_tg = event['http_header']+ '-' +event['clustername'].split('-fg-')[0] + '-' + getplevel(canary_vpcid,creds,sname) + '-' +'atg' + '-' + tgversion_curr
                            migrate_alb_tgres = create_target_group(canary_alb_tg,lb_res[1],_tgport,'ip',canary_vpcid,creds,canary_taglist)
                            migrate_alb_tgarn = migrate_alb_tgres['TargetGroups'][0]['TargetGroupArn']
                            tglist.append({'TargetGroupArn': migrate_alb_tgarn ,'Weight': 100})
                            #Creating listener for ALB
                            listener_res = modify_listener(lb_res[0],tglist,event['http_header'],event['path_pattern'],canary_taglist,creds)
                            listenerport = lb_res[1]
                            
                            #Adding security group for ALB
                            sgid = get_load_balancer(migrate_alb_arn[0],creds)
                            print("Security group if for canary ALB: "+ str(sgid))
                            if 'SecurityGroups' in sgid['LoadBalancers'][0] and sgid['LoadBalancers'][0]['SecurityGroups']:
                                sg_rule = add_inbound_rulesg(sgid['LoadBalancers'][0]['SecurityGroups'][0],listenerport,_servicesubnets,creds)
                                    
                           #Updating ecs service with canary target group
                            ecs_res = updateecsservice(cname,sname,canary_container,_tgarn,migrate_alb_tgarn,_tgport,_servicesubnets,_securityGroups,cleandict['artifacts'][0],creds)
                            _tgarn = migrate_alb_tgarn
                            canary_current_albarn = migrate_alb_arn[0]
                            first_canary_migration = True 
                            
                
                    #Checking condition if the service is already migrated to canary
                    if not first_canary_migration:
                        canary_current_alb_tgname = canary_tg_response
                        print("Current target group for ALB:" + str(canary_current_alb_tgname))
                        canary_current_albarn = (canary_current_alb_tgname['TargetGroups'][0]['LoadBalancerArns'][0])
                        canary_alb = canary_current_albarn.split('loadbalancer/app/')[1].split('/')[0]
                        canary_vpcid = canary_current_alb_tgname['TargetGroups'][0]['VpcId']
                        
                        #Checking for listener of ALb
                        lb_res = describe_listener_lb(canary_current_albarn,canary_current_albarn,'','alb',canary_taglist,event['certificatearn'],creds)
                        listenerport = lb_res[1]
                        if not listenerport:
                            print('fetching listener port')
                            lb_res = describe_listener_lb(canary_nlbarn[0],canary_current_albarn,'','network',canary_taglist,event['certificatearn'],creds,'sendback')
                            listenerport = lb_res[1]
                            lb_res = describe_listener_lb(canary_current_albarn,canary_current_albarn,listenerport,'alb',canary_taglist,event['certificatearn'],creds)
                            listenerport = lb_res[1]
                            print("Listener port for alb: "+ str(listenerport))
                            
                    
                    #Creating target group for Canary NLB
                    print('Creating target group for Canary NLB')
                    print('canary alb: ' + str(canary_alb))
                    canary_nlb_tg = 'tg-'+ event['clustername'].split('-fg-')[0]+ '-' + getplevel(canary_vpcid,creds,sname) + '-' + 'ALB-' + canary_alb.rsplit('-',1)[1]
                    canary_nlb_tg = create_target_group(canary_nlb_tg,listenerport,_tgport,'alb',canary_vpcid,creds,canary_taglist,canary_current_albarn)
                    canary_nlb_tgarn = canary_nlb_tg['TargetGroups'][0]['TargetGroupArn']
                    print("Created Canary nlb target group arn: "+str(canary_nlb_tgarn))
                    
                    print('entering describe_listener_lb for NLB - ' + str(canary_nlbarn))
                    canary_nlblistener = describe_listener_lb(canary_nlbarn[0],canary_current_albarn,'','network',canary_taglist,event['certificatearn'],creds,canary_nlb_tgarn)
                    #Roshan changed 06072023
                    #canary_nlblistener = describe_listener_lb(canary_nlbarn,canary_current_albarn,'','network',canary_taglist,event['certificatearn'],creds,canary_nlb_tgarn)
                    if 'Throttling Error' in  canary_nlblistener:
                        canary_nlblistener = describe_listener_lb(canary_nlbarn[0],canary_current_albarn,'','network',canary_taglist,event['certificatearn'],creds,canary_nlb_tgarn)
                    if 'Generic Error' in  canary_nlblistener:
                        return { 'statusCode': 502, 'body': json.dumps({ "message": f"please verify your canary_nlblistener configuration. \ncanary_nlbarn:{canary_nlbarn[0]}, \ncanary_current_albarn: {canary_current_albarn}, \nnetwork, \ncanary_taglist: {canary_taglist}, \ncreds:{creds}, \ncertificatearn:{event['certificatearn']}, canary_nlb_tgarn:{canary_nlb_tgarn} " + str(canary_nlblistener) }) }
                        
                    #Adding vpclink in response if canary nlb is created first time
                    if 'svccreated' not in event:
                        if not (canary_nlbarn[1] is None):
                            vpclink_id = canary_nlbarn[1]
			
			        #Checking condition if canary service not deployed yet
                    if 'svccreated' not in event:
                        print('Checking condition if canary service not deployed yet')
                        canary_new_alb_tgname = event['http_header'] + '-' +event['clustername'].split('-fg-')[0] + '-' + getplevel(canary_vpcid,creds,sname) + '-' +'atg' + '-' + tgversion
                        if first_canary_migration:
                            canary_taglist["migratedService"] = "true"
                        canary_new_alb_tg = create_target_group(canary_new_alb_tgname,canary_nlblistener[1],_tgport,'ip',canary_vpcid,creds,canary_taglist)
                        canary_new_alb_tgarn = canary_new_alb_tg['TargetGroups'][0]['TargetGroupArn']
                        print("Created new target group for ecs: "+str(canary_new_alb_tgarn))
                        _targetGroup = canary_new_alb_tg['TargetGroups'][0]['TargetGroupName']
                        print("Target group name is :"+ str(_targetGroup))
                    
                    print('Describe listener for alb')
                    canary_listenerarn = describe_listener_lb(canary_current_albarn,canary_current_albarn,canary_nlblistener[1],'alb',canary_taglist,event['certificatearn'],creds)
                    if canary_listenerarn == 'Throttling Error':
                        canary_listenerarn = describe_listener_lb(canary_current_albarn,canary_current_albarn,canary_nlblistener[1],'alb',canary_taglist,event['certificatearn'],creds)
                    if canary_listenerarn == 'Generic Error':
                        return { 'statusCode': 502, 'body': json.dumps({ "message": f"please verify your loadbalancer listner configuration. \ncanary_current_albarn:{canary_current_albarn}, \ncanary_current_albarn:{canary_current_albarn}, \ncanary_nlblistener:{canary_nlblistener[1]}, alb, \ncanary_taglist:{canary_taglist}, \ncertificatearn:{event['certificatearn']}, \ncreds:{creds} " + str(canary_listenerarn) }) }  
                    
                    tglist = describe_listener(canary_current_albarn,canary_listenerarn[0],event['http_header'],creds)
                    if tglist == 'Throttling Error':
                        tglist = describe_listener(canary_current_albarn,canary_listenerarn[0],event['refid'],creds)
                    if tglist == 'Generic Error':
                        return { 'statusCode': 502, 'body': json.dumps({ "message": f"please verify your loadbalancer configuration canary_current_albarn:{canary_current_albarn},canary_listenerarn:{canary_listenerarn[0]},refid:{event['refid']}, creds:{creds} " + str(tglist) }) }  
                    print("Target group list in alb rules: "+ str(tglist))
                    
                    #Checking condition if canary service not deployed yet
                    if 'svccreated' not in event:
                        if not any(d['TargetGroupArn'] == canary_new_alb_tgarn for d in tglist):
                            tglist.append({'TargetGroupArn': canary_new_alb_tgarn ,'Weight': 0})
                            add_tg = modify_listener(canary_listenerarn[0],tglist,event['http_header'],event['path_pattern'],canary_taglist,creds)
                            
                            if add_tg == 'Throttling Error':
                                 add_tg = modify_listener(canary_listenerarn[0],tglist,event['http_header'],event['path_pattern'],canary_taglist,creds)
                            if add_tg == 'Generic Error':
                                 return { 'statusCode': 502, 'body': json.dumps({ "message": f"please verify your loadbalancer configuration. \ncanary_listenerarn: {canary_listenerarn[0]}, \ntglist{tglist}, \nhttp_header: {event['http_header']}, \npath_pattern:{event['path_pattern']}, \ncanary_taglist:{canary_taglist}\n" + str(add_tg) }) }  
                    
                    #Checking condition if canary service hae been deployed
                    if 'svccreated' in event and event['svccreated'] == 'true':
                        tgnamelist = []
                        for i in tglist:
                            tgnamelist.append(i['TargetGroupArn'].split(':')[5].split('/')[1])
                            
                        #Fetching tg name which are not of existing NLB    
                        tgnamelist_notbase = [item for item in tgnamelist if re.search('-v[0-9][0-9]*', item)]
                        print("Target group list excluding base tg :" +str(tgnamelist_notbase))
                        tgnamelist_notbase = [s for s in tgnamelist_notbase if 'v00b' not in s]
                        #Fetching oldest target group
                        oldesttg = find_lowest_service(tgnamelist_notbase)
                        #Fetching latest target group
                        latesttg = find_latest_service(tgnamelist_notbase)
                        print("Fetching oldest and latest service target groups: "+ str(oldesttg) + ' :: ' + str(latesttg))
                        oldesttgarn = []
                        
                        #Modifying the tg list on the basis of input weight
                        for i in tglist:
                            temp_tgname = i['TargetGroupArn'].split(':')[5].split('/')[1]
                            if len(tglist) > 2:
                                if temp_tgname != latesttg:
                                    tgnamelist1 = ([s for s in tgnamelist_notbase if s != latesttg])
                                    secondltstg = find_latest_service(tgnamelist1)
                                    if temp_tgname  == secondltstg:
                                        i['Weight'] = 100 - int(event['Weight'])
                                    elif 'v00b' in temp_tgname:
                                        i['Weight'] = 0
                                        if len(tglist) > int(event['maxasg']):
                                            tglist = [item for item in tglist if item['TargetGroupArn'] != i['TargetGroupArn']]    
                                    else:
                                        i['Weight'] = 0
                                        if len(tglist) > int(event['maxasg']) and int(temp_tgname.split('-').pop().replace('v','')) <= int(latesttg.split('-').pop().replace('v','')) - int(event['maxasg']) :
                                            oldesttgarn.append(i['TargetGroupArn'])
                                            print("Oldest target group - "+ str(oldesttgarn) )
                                                
                                if temp_tgname == latesttg:
                                    i['Weight'] = int(event['Weight'])
                            if len(tglist) == 2:
                                if (re.search('-v[0-9][0-9]*', temp_tgname)) is not None:
                                    if temp_tgname == oldesttg and temp_tgname == latesttg:
                                        i['Weight'] = int(event['Weight'])
                                    else:
                                        if temp_tgname == oldesttg:
                                            i['Weight'] = 100 - int(event['Weight'])
                                        if temp_tgname == latesttg:
                                            i['Weight'] = int(event['Weight'])
                                        if 'v00b' in temp_tgname:
                                            i['Weight'] = 100 - int(event['Weight'])
                                else:
                                    i['Weight'] = 0
                            if len(tglist) == 1:
                                    i['Weight'] = 100
                        
                        print('count of target group '+str(tgarn_cnt))
                        #Ignoring the target group which is associated to different 
                        for i in oldesttgarn:
                            oldesttgarn_res = describe_target_group(i,creds)
                            print("Canary ALB arn "+str(canary_current_albarn))
                            if oldesttgarn_res['TargetGroups'][0]['LoadBalancerArns']:
                                if oldesttgarn_res['TargetGroups'][0]['LoadBalancerArns'][0] != canary_current_albarn:
                                    oldesttgarn.remove(i)
                                    print("Oldest tgarn is associated to different ALB  "+str(oldesttgarn_res['TargetGroups'][0]['LoadBalancerArns']))
                        
                        #Removing the oldest target group from list if asg count > 2
                        if oldesttgarn:
                            print("Fetching target group count in current service:" +str(tgarn_cnt))
                            tglist = [item for item in tglist if not(item['TargetGroupArn'] in oldesttgarn)]
                            
                        print("Target group list excluding oldest service target group: "+ str(tglist))
                        #Removing target group from listener rules
                        delete_tg = modify_listener(canary_listenerarn[0],tglist,event['http_header'],event['path_pattern'],canary_taglist,creds)
                        
                        if delete_tg == 'Throttling Error':
                            delete_tg = modify_listener(canary_listenerarn[0],tglist,event['http_header'],event['path_pattern'],canary_taglist,creds)
                        if delete_tg == 'Generic Error':
                             return { 'statusCode': 502, 'body': json.dumps({ "message": f"please verify your loadbalancer configuration. \ncanary_listenerarn:{canary_listenerarn[0]}, \ntglist:{tglist}, \nhttp_header:{event['http_header']}, \npath_pattern:{event['path_pattern']}, \ncanary_taglist:{canary_taglist}, \ncreds:{creds}" + str(delete_tg) }) }

                        for i in servicelist[2]:
                            if servicelist[3]:
                                if i.rsplit('/',1)[1] in servicelist[3]:
                                    canary_taglist["TrafficAllocation"] = "0"
                                    canary_taglist["Servicename"] = str(i.rsplit('/',1)[1])
                                    tag_resources_general(i,canary_taglist,creds)
                            if servicelist[4]:
                                if str(servicelist[4]) in i:
                                    canary_taglist["TrafficAllocation"] = str(100 - int(event['Weight']))
                                    canary_taglist["Servicename"] = str(i.rsplit('/',1)[1])
                                    tag_resources_general(i,canary_taglist,creds)
                                
                                
                    
                        #Deleting canary target group on the basis of asg count
                        if oldesttg != latesttg:
                            print("Fetching Oldest service target group arn: "+str(oldesttgarn))
                            if tgarn_cnt < 2:
                                if oldesttgarn:
                                    for i in oldesttgarn:
                                        if re.search('-v[0-9][0-9]*', i) is not None:
                                            print("****** NOTICE Deleting target group  %s *******" %(i))
                                            describe_target_group(i,creds)
                                            delete_target_group(i,creds)
                            
                        if tgarn_cnt > 1:
                            nlb_tgarn_old = [item for item in svc_response['services'][0]['loadBalancers'] if not(item['targetGroupArn'] == oldesttgarn)]
                            nlb_tgarn_old = nlb_tgarn_old[0]['targetGroupArn']
                            #print("****** NOTICE Deleting %s *******" %(nlb_tgarn_old))
                            canary_oldtg_response = describe_target_group(nlb_tgarn_old,creds)
                            existing_nlb = canary_oldtg_response['TargetGroups'][0]['LoadBalancerArns'][0]
                            #print("****** NOTICE Deleting listener of %s *******" %(existing_nlb))
                            existing_listener = get_listener(existing_nlb,creds)
                            print('existing listener of NLB' + str(existing_listener))
                            print('Existing NLB target group' + str(nlb_tgarn_old))
                            #delete_listener(existing_listener,creds)
                            #delete_target_group(nlb_tgarn_old,creds)
			    
                    #[End if condition]
                    print("Fetching task definition" + str(cleandict))
                        
                    #Updating log group stream prefix in taskdefinition
                    cleandict['artifacts'][0]['containerDefinitions'][0]['logConfiguration']['options']['awslogs-stream-prefix'] = tgversion

                    
                    cleandict['artifacts'][0]['containerDefinitions'][0]['environment'].append({ "name": "SERVICEREVISION", "value": str(tgversion) })
                    
                    #updateenvvars(cleandict,'SERVICEREVISION',tgversion,containerIndex)
                jsonout = json.dumps(cleandict['artifacts'][0])
                out = uploadtos3(event['referenceid']+'.json',event['savebuckettd'],jsonout)
                
            #[end]Canary deployment

            #062332022 Roshan In Progress
            consolidate_dict = {}
            if _securityGroupNames:
                consolidate_dict['_securityGroupNames'] = _securityGroupNames
            if 'canary_nlb' in event:
                consolidate_dict['_newecsversion'] = latestsvc.rsplit('-',1)[0] + '-' + tgversion
                if vpclink_id:
                    consolidate_dict['_vpclink_id'] = vpclink_id
                if canary_nlblistener[1]:
                    consolidate_dict['_canarynlb_port'] = canary_nlblistener[1]
                if servicelist[1] > 3:
                    consolidate_dict['_disbable_serverlist'] = servicelist[3]
                if canary_nlbarn:
                    if 'svccreated' not in event:
                        consolidate_dict['_nlb_endpoint'] = canary_nlbarn[3]['LoadBalancers'][0]['DNSName']
                        consolidate_dict['_nlbarn'] = canary_nlbarn[0]
            if _securityGroups:
                consolidate_dict['_securityGroups'] = _securityGroups
            if _targetGroup:
                consolidate_dict['_targetGroup'] = _targetGroup
            if _subnetTypes:
                consolidate_dict['_subnetTypes'] = _subnetTypes
            if _tgport:
                consolidate_dict['_tgport'] = _tgport

            
            consolidate_dict['_service_count'] = servicelist[1]
            print(json.dumps(consolidate_dict))
        
            cleandict['consolidated'] = consolidate_dict
            cleandict['artifacts'][0]['type'] = 's3/object'
            #End

            #Spinnaker upgrade and OpsMX patch..
            jsonout2 = json.dumps(cleandict)
            #jsonout2 = cleandict
            print("Passing through Upgrade and OpsMX patch..")
            print(jsonout2)
            return { 'statusCode': 200, 'body': jsonout2 }
            #Patch end..
        
            #return { 'statusCode': 200, 'body': jsonout1 }
    
        #this is for creating a seed job pipeline.json file in spinnaker. Lambda returns the JSON back to Cloudbees.
        #-----------------------------------------------------------------------------------------------------------
        if 'seedjobCreate' in event and event['seedjobCreate'] == "true":
            #Prepare pipeline.json file
            application = event['application']
            str1 = '{ ' + '"' + application + '"' + ':'
            tplfile = open("pipelineV2.json","r")
            out = tplfile.read()
            pipeline = str1 + out
            pipelineout = json.loads(pipeline)
            print("++++++++")
            print(pipelineout)
            #pipelineout[event['applicationname']][0]['stages'][2]['clusters'][0]['subnetType'] = "fargate-spinnaker-nv-" + event['environment']
            #pipelineout[event['applicationname']][0]['stages'][5]['clusters'][0]['subnetType'] = "fargate-spinnaker-nv-" + event['environment']
            if event['awsregion'] == "us-east-1":
                out = uploadtos3('seedpipelines/'+event['referenceid']+'.json','saratestfargatetd',json.dumps(pipelineout))
            if event['awsregion'] == "us-east-2":
                out = uploadtos3('seedpipelines/'+event['referenceid']+'.json','saratestfargatetd-oh',json.dumps(pipelineout))
            if event['awsregion'] == "eu-central-1":
                out = uploadtos3('seedpipelines/'+event['referenceid']+'.json','saratestfargatetd-fr',json.dumps(pipelineout))
            pipelineout['artifacts'] = [pipelineout.pop('appdemosamples')]
            return { 'statusCode': 200, 'body': json.dumps(pipelineout) }
    
        #This section is for adding Jfrog Image property for NON NV Region only.. Since non NV regions do not have access to JFROG API service.
        #--------------------------------------------------------------------------------------------------------------------------------------
        if 'NonNVPropsUpdate' in event and event['NonNVPropsUpdate'] == "true":
            out1 = setprops2jfrog(event['jfrogPros'],event['propskey'],event['propsvalue'])
            if out1 == '<Response [204]>':
                from datetime import datetime
                datetime.utcnow()
                utc_time = datetime.utcnow() 
                timenow = utc_time.strftime('%Y%m%d %H%M%S')
                out2 = setprops2jfrog(event['jfrogPros'],'lastSpinnakerUser',event['spinnakerUser']+' UTC: '+timenow)
                if out2 == '<Response [204]>':
                    return { 'statusCode': 200, 'body': json.dumps("JFrog Image Property Updated") }
            return { 'statusCode': 404, 'body': json.dumps("FAILED") }
        
        #This section is for adding autoscaling and tags to the Spinnaker created service.
        #---------------------------------------------------------------------------------
        if 'TagsUpdate' in event and event['TagsUpdate'] == "true":
            print("Spinnaker Executing Autoscaling Update...")
            print("clustername is: " + event['clustername'])
            print("servicename is: " + event['refid'])
            print("BusinessUnit is: " + event['BusinessUnit'])
            print("Csp is: " + event['Csp'])
            print("Location is: " + event['Location'])
            print("Increment is: " + event['Increment'])
            print("Account is: " + event['Account'])
            print("AccountId is: " + event['AccountId'])
            print("cputhreshold is: " + str(event['cputhreshold']))
            print("memorythreshold is: " + str(event['memorythreshold']))
            print("JFrog Property file is: " + str(event['jfrogPros']))
            print("JFrog Property file Key to update is: " + str(event['propskey']))
            print("JFrog Property file Value to update is: " + str(event['propsvalue']))
            print("Spinnaker pipeline user is: " + str(event['spinnakerUser']))
            if 'awsregion' in event:
                if event['awsregion'] == 'us-east-1':
                    creds = assumerole('arn:aws:iam::'+event['AccountId']+':role/SL-ROL-'+event['BusinessUnit']+event['Csp']+event['Location']+'-'+event['Account']+'-'+'fargate-lambda-role')
                if event['awsregion'] == 'us-east-2':
                    creds = assumerole('arn:aws:iam::'+event['AccountId']+':role/SL-ROL-'+event['BusinessUnit']+event['Csp']+event['Location']+'-'+event['Account']+'-'+'fargate-lambda-role-us-east-2')
                if event['awsregion'] == 'eu-central-1':
                    creds = assumerole('arn:aws:iam::'+event['AccountId']+':role/SL-ROL-'+event['BusinessUnit']+event['Csp']+event['Location']+'-'+event['Account']+'-'+'fargate-lambda-role-eu-central-1')
            
                timenow = time.time()
    
                cname = event['BusinessUnit'] + event['Csp'] + event['Location'] + '-' + event['Account'] + '-' + event['Increment']  + '-' + event['clustername']
                print('clustername is '+str(cname))
    
                plvalue = 'NA'
                refid = event['refid']
                if event['awsregion'] == "us-east-1":
                    currentJson = downloadfroms3(event['referenceid']+'.json','saratestfargatetd')
                if event['awsregion'] == "us-east-2":
                    currentJson = downloadfroms3(event['referenceid']+'.json','saratestfargatetd-oh')
                if event['awsregion'] == "eu-central-1":
                    currentJson = downloadfroms3(event['referenceid']+'.json','saratestfargatetd-fr')
                content = currentJson['Body']
                currentDict = json.loads(content.read())
                currentJson = json.dumps(currentDict)
                out = json.loads(urllib.parse.unquote(str(currentJson)))
                for i in out['containerDefinitions']:
                    if 'ecs-service' in i['name']:
                        servicename = i['name']
                        if servicename.split('-')[3].isnumeric():
                            plvalue = servicename.split('-')[3]
                            refid = servicename.split('-ecs-service-')[1]
                print('PL Value found: '+ str(plvalue))
                print('serviceid is: '+ str(refid))
                if plvalue == 'NA':
                    prevsname = event['BusinessUnit'] + event['Csp'] + event['Location'] + '-' + event['Account'] + '-' + event['Increment']  + '-ecs-service-' + event['refid']
                if plvalue != 'NA':
                    prevsname = event['BusinessUnit'] + event['Csp'] + event['Location'] + '-' + event['Account'] + '-' + event['Increment']  + '-' + plvalue  + '-ecs-service-' + refid
                servicelist = listservices(event['BusinessUnit'],event['Csp'],event['Location'],event['Account'],event['Increment'],event['clustername'],refid,creds,plvalue)
                sname = servicelist[0]
    
                print("service name is " + str(sname))
                
                #Enable below line for testing only.. to switch service to the original service naming style.
                #sname = event['BusinessUnit'] + event['Csp'] + event['Location'] + '-' + event['Account'] + '-' + event['Increment']  + '-ecs-service-' +  event['refid']
                
                #enableautoscaling(cname,sname,creds,0,0)
                cpuout = setautoscalepolicy(cname,sname,'cpu',event['cputhreshold'],creds)
                time.sleep(3)
                memoryout = setautoscalepolicy(cname,sname,'memory',event['memorythreshold'],creds)
                
                if find_if_v000(str(sname)) == True:
                    print("First service from Spinnaker.. So using tags from original named service: "+str(prevsname))
                    tagout = describe_services_tags(cname,prevsname,creds)
                    if event['awsregion'] == 'us-east-1':
                        out = check_into_dynamodb_table(cname,sname,tagout,'wanv-sap-9-fargate-spinnaker-records')
                    if event['awsregion'] == 'us-east-2':
                        out = check_into_dynamodb_table(cname,sname,tagout,'waoh-sap-9-fargate-spinnaker-records')
                else:
                    print("Retrieve tags from Dynamo DB for the service..")
                    #tagout = describe_services_tags(cname,str(sname),creds)
                    #Do not uncomment below line.. check with Devop.
                    #tagout = describe_services_tags(cname,prevsname,creds)
                    sname000 = find_first_service(str(sname))
                    str1 = '-'
                    sname_first = str1.join(sname000)
                    print("sname000 is " + str(sname_first))
                    if event['awsregion'] == 'us-east-1':
                        tags = getrecord_dynamodb_table(cname,sname_first,'wanv-sap-9-fargate-spinnaker-records')
                    if event['awsregion'] == 'us-east-2':
                        tags = getrecord_dynamodb_table(cname,sname_first,'waoh-sap-9-fargate-spinnaker-records')
                    if event['awsregion'] == 'eu-central-1':
                        tags = getrecord_dynamodb_table(cname,sname_first,'wafr-sap-0-fargate-spinnaker-records')
                    if 'Itemnotfound' in tags:
                        tagout = describe_services_tags(cname,prevsname,creds)
                        if event['awsregion'] == 'us-east-1':
                            out = check_into_dynamodb_table(cname,sname_first,tagout,'wanv-sap-9-fargate-spinnaker-records')
                        if event['awsregion'] == 'us-east-2':
                            out = check_into_dynamodb_table(cname,sname_first,tagout,'waoh-sap-9-fargate-spinnaker-records')
                    else:  
                        tagout = tags['tagslist']
                print(tagout)
                if event['awsregion'] == 'us-east-1':
                    sarn = 'arn:aws:ecs:us-east-1:' + event['AccountId'] + ':service/' + cname + '/' + sname
                if event['awsregion'] == 'us-east-2':
                    sarn = 'arn:aws:ecs:us-east-2:' + event['AccountId'] + ':service/' + cname + '/' + sname
                if event['awsregion'] == 'eu-central-1':
                    sarn = 'arn:aws:ecs:eu-central-1:' + event['AccountId'] + ':service/' + cname + '/' + sname
                if event['awsregion'] == 'eu-west-1':
                    sarn = 'arn:aws:ecs:eu-west-1:' + event['AccountId'] + ':service/' + cname + '/' + sname
                out = update_service_with_tags(sarn,tagout,creds)
                out = list_tasks(cname,sname,creds)
                for i in out:
                    print("Now tagging task "+i)
                    out = update_service_with_tags(i,tagout,creds)
                #This section is called after the successful deploy at the end of Spinnaker pipeline.
                #----------------------------------------------------------------------------------
                if event['awsregion'] == 'us-east-1':
                    if 'ecr' not in event['jfrogPros'].lower():
                        out1 = setprops2jfrog(event['jfrogPros'],event['propskey'],event['propsvalue'])
                        if out1 == '<Response [204]>':
                            from datetime import datetime
                            datetime.utcnow()
                            utc_time = datetime.utcnow() 
                            timenow = utc_time.strftime('%Y%m%d %H%M%S')
                            out2 = setprops2jfrog(event['jfrogPros'],'lastSpinnakerUser',event['spinnakerUser']+' UTC: '+timenow)
                            if out2 == '<Response [204]>':
                                return { 'statusCode': 200, 'body': json.dumps(out) }
                        return { 'statusCode': 404, 'body': json.dumps("FAILED") }
            return { 'statusCode': 200, 'body': json.dumps(tagout) } 
                
        #---------------------------------------------------------------------
        if 'check_create_fargate_service' in event:
            print("clustername is: " + event['clustername'])
            print("servicename is: " + event['refid'])
            print("BusinessUnit is: " + event['BusinessUnit'])
            print("Csp is: " + event['Csp'])
            print("Location is: " + event['Location'])
            print("Increment is: " + event['Increment'])
            print("Account is: " + event['Account'])
            print("AccountId is: " + event['AccountId'])
            print("trackId is: " + event['trackId'])
            #Check if SHS runstacks created and codebuild and pipeline created and kicked off.
            if 'awsregion' in event:
                if event['awsregion'] == 'us-east-1':
                    creds = assumerole('arn:aws:iam::794393546049:role/SL-ROL-CANV-1NP-fargate-lambda-role')
                if event['awsregion'] == 'us-east-2':
                    creds = assumerole('arn:aws:iam::794393546049:role/SL-ROL-CANV-1NP-fargate-lambda-role-east-2')
                if event['awsregion'] == 'eu-central-1':
                    creds = assumerole('arn:aws:iam::794393546049:role/SL-ROL-CANV-1NP-fargate-lambda-role-eu-central-1')
                if event['awsregion'] == 'eu-west-1':
                    creds = assumerole('arn:aws:iam::794393546049:role/SL-ROL-CANV-1NP-fargate-lambda-role-eu-west-1')
                #Time to make sure runstacks created.. uncomment when live.
                time.sleep(30)
                out = check_fargate_create_run_stack(event['trackId'],creds)
                runstack_status = 'NA'
                for i in out:
                    print(i)
                    if 'CREATE_COMPLETE' not in i:
                        runstack_status = 'error'
                        return "ERROR 01: runstack failed"
                    else:
                        runstack_status = 'success'
                if runstack_status == 'success':
                    print("STAGE 1: SHS runstack success.. Proceeding further checks..")
                    out = check_fargate_create_codebuild_pipeline(event['trackId'],creds)
                    for i in out:
                        if 'CreateLambda' in i:
                            b1name = i
                        if 'TaskDefinition' in i:
                            b2name = i
                    build_status1 = check_fargate_create_codebuild_pipeline_jobs(b1name,creds)
                    count = 1
                    while build_status1 == 'IN_PROGRESS' and count <= 20:
                        build_status1 = check_fargate_create_codebuild_pipeline_jobs(b1name,creds)
                        print("Build still in progress: "+str(b1name))
                        count = count + 1
                        time.sleep(20)
                    if build_status1 == 'SUCCEEDED':
                        build_status2 = check_fargate_create_codebuild_pipeline_jobs(b2name,creds)
                        while build_status2 == 'IN_PROGRESS' and count <= 20:
                            build_status2 = check_fargate_create_codebuild_pipeline_jobs(b2name,creds)
                            print("Build still in progress: "+str(b2name))
                            count = count + 1
                            time.sleep(20)
                    codebuildpipelinestatus = []
                    codebuildpipelinestatus.append(b1name+':'+build_status1)
                    codebuildpipelinestatus.append(b2name+':'+build_status2)
                    if build_status1 != 'SUCCEEDED' and build_status2 != 'SUCCEEDED':
                        return "ERROR 02: codebuild and pipeline failed in Shared Service Account"
                    if build_status1 == 'SUCCEEDED' and build_status2 == 'SUCCEEDED':
                        print("STAGE 2: Codebuild and pipeline run success.. Proceeding further checks..")
                        if 'awsregion' in event:
                            if event['awsregion'] == 'us-east-1':
                                creds = assumerole('arn:aws:iam::'+event['AccountId']+':role/SL-ROL-'+event['BusinessUnit']+event['Csp']+event['Location']+'-'+event['Account']+'-'+'fargate-lambda-role')
                            if event['awsregion'] == 'us-east-2':
                                creds = assumerole('arn:aws:iam::'+event['AccountId']+':role/SL-ROL-'+event['BusinessUnit']+event['Csp']+event['Location']+'-'+event['Account']+'-'+'fargate-lambda-role-us-east-2')
                            if event['awsregion'] == 'eu-central-1':
                                creds = assumerole('arn:aws:iam::'+event['AccountId']+':role/SL-ROL-'+event['BusinessUnit']+event['Csp']+event['Location']+'-'+event['Account']+'-'+'fargate-lambda-role-eu-central-1')
                            if event['awsregion'] == 'eu-west-1':
                                creds = assumerole('arn:aws:iam::'+event['AccountId']+':role/SL-ROL-'+event['BusinessUnit']+event['Csp']+event['Location']+'-'+event['Account']+'-'+'fargate-lambda-role-eu-west-1')
                    out = check_taskandservice_stack_status(event['BusinessUnit'],event['Csp'],event['Location'],event['Account'],event['Increment'],event['refid'],creds)
                    count = 1
                    while out != 'CREATE_COMPLETE' and count <= 20:
                        count = count + 1
                        time.sleep(20)
                        print("Sleeping 20 seconds to check taskandservice stack..retry "+str(count))
                        out = check_taskandservice_stack_status(event['BusinessUnit'],event['Csp'],event['Location'],event['Account'],event['Increment'],event['refid'],creds)
                    if out != 'CREATE_COMPLETE':
                        return "ERROR 03: Task And Service Cloudformation failed in the target Account"
                    if out == 'CREATE_COMPLETE':
                        print("STAGE 3: BU TaskAndService Cloudformation success.. Proceeding further checks..")
                        if event['awsregion'] == 'us-east-1':
                            creds = assumerole('arn:aws:iam::'+event['AccountId']+':role/SL-ROL-'+event['BusinessUnit']+event['Csp']+event['Location']+'-'+event['Account']+'-'+'fargate-lambda-role')
                        if event['awsregion'] == 'us-east-2':
                            creds = assumerole('arn:aws:iam::'+event['AccountId']+':role/SL-ROL-'+event['BusinessUnit']+event['Csp']+event['Location']+'-'+event['Account']+'-'+'fargate-lambda-role-us-east-2')
                        if event['awsregion'] == 'eu-central-1':
                            creds = assumerole('arn:aws:iam::'+event['AccountId']+':role/SL-ROL-'+event['BusinessUnit']+event['Csp']+event['Location']+'-'+event['Account']+'-'+'fargate-lambda-role-eu-central-1')
                        if event['awsregion'] == 'eu-west-1':
                            creds = assumerole('arn:aws:iam::'+event['AccountId']+':role/SL-ROL-'+event['BusinessUnit']+event['Csp']+event['Location']+'-'+event['Account']+'-'+'fargate-lambda-role-eu-west-1')
                        timenow = time.time()
                        cname = event['BusinessUnit'] + event['Csp'] + event['Location'] + '-' + event['Account'] + '-' + event['Increment']  + '-' + event['clustername']
                        sname = event['BusinessUnit'] + event['Csp'] + event['Location'] + '-' + event['Account'] + '-' + event['Increment']  + '-ecs-service-' + event['refid']
                        cluster_status = "INACTIVE"
                        cluster_status = get_fargate_create_cluster_status(cname,creds)
                        fargate_status = []
                        if cluster_status == "ACTIVE":
                            fargate_status.append('cluster_status:'+ str(cluster_status))
                            timer = 1
                            service_status ="INACTIVE"
                            while timer <= 30 and service_status != "ACTIVE":
                                service_status = get_fargate_create_service_status(cname,sname,creds)
                                time.sleep(10)
                                print("Retrying attempt:" + str(timer))
                                timer = timer+1
                                #print(service_status)
                            print("STAGE 4: Cluster and Service check success.. All Done..")
                        if cluster_status != "ACTIVE" or service_status != "ACTIVE":
                            return 'ERROR 04: Cluster or Service Inactive in the Target Account'
                        if cluster_status == "ACTIVE" and service_status == "ACTIVE":
                            fargate_status.append('service_status:'+ str(service_status))
                        return fargate_status
        #This section is for adding AWS Secret Manager. Called from Jenkins job once the secret is initially created.e.
        #---------------------------------------------------------------------------------
        if 'awssecretsAdd' in event and event['awssecretsAdd'] == "true":
            print("username is: " + event['username'])
            #print("apikey is: " + event['apikey'])
            print("secretname is: " + event['secretname'])
            """
            print("loginname is: " + event['loginname'])
            print("AccountId is: " + event['AccountId'])
            print("awsregion is: " + event['awsregion'])
            if 'awsregion' in event:
                if event['awsregion'] == 'us-east-1':
                    creds = assumerole('arn:aws:iam::'+event['AccountId']+':role/SL-ROL-'+event['BusinessUnit']+event['Csp']+event['Location']+'-'+event['Account']+'-'+'fargate-lambda-role')
                if event['awsregion'] == 'us-east-2':
                    creds = assumerole('arn:aws:iam::794393546049:role/SL-ROL-CANV-1NP-fargate-lambda-role-east-2')
                if event['awsregion'] == 'eu-central-1':
                    creds = assumerole('arn:aws:iam::794393546049:role/SL-ROL-CANV-1NP-fargate-lambda-role-eu-central-1')
                if event['awsregion'] == 'eu-west-1':
                    creds = assumerole('arn:aws:iam::794393546049:role/SL-ROL-CANV-1NP-fargate-lambda-role-eu-west-1')
            """
            creds = assumerole('arn:aws:iam::517949891193:role/SL-ROL-WANV-SAP-fargate-lambda-role')
            out = create_update_aws_secrets_manager(event['username'],event['apikey'],event['secretname'],creds)
            print(out)
            return out
        #This section is for registering task definition. Called from Spinnaker job.
        #---------------------------------------------------------------------------------
        if 'RegisterTD' in event and event['RegisterTD'] == "true":
            print(event)
            if 'fulljson' not in event or event['fulljson'] == '':
                print("Printing supplied parameters (Not a full json)")
                print("taskname is: " + event['taskname'])
                print("taskRoleArn is: " + event['taskRoleArn'])
                print("executionRoleArn is: " + event['executionRoleArn'])
                print("networkMode is: " + event['networkMode'])
                print("requiresCompatibilities is: " + event['requiresCompatibilities'])
                print("cpu is: " + event['cpu'])
                print("memory is: " + event['memory'])
                print("awsregion is: " + event['awsregion'])
                print("pipelineaccountid is: " + event['pipelineaccountid'])
                print("Account is: " + event['Account'])
                print("BusinessUnit is: " + event['BusinessUnit'])
                print("Csp is: " + event['Csp'])
                print("Location  is: " + event['Location'])
                print("family  is: " + event['taskname'])
                print("containerport  is: " + event['containerport'])
                print("envvars  is: " + event['envvars'])
                print("imageurl  is: " + event['imageurl'])
                print("containername  is: " + event['containername'])
                print("secretmanagername is: " + event['secretmanagername'])
                
            if 'fulljson' in event and event['fulljson'] != '':
                print("Printing supplied parameters (Is a full json)")
                print("networkMode is: " + event['networkMode'])
                print("requiresCompatibilities is: " + event['requiresCompatibilities'])
                print("awsregion is: " + event['awsregion'])
                print("pipelineaccountid is: " + event['pipelineaccountid'])
                print("Account is: " + event['Account'])
                print("BusinessUnit is: " + event['BusinessUnit'])
                print("Csp is: " + event['Csp'])
                print("Location  is: " + event['Location'])
                print("imageurl  is: " + event['imageurl'])
                print("fulljson  is: " + event['fulljson'])
                print("envvars  is: " + event['envvars'])
                
            print("Spinnaker Ref ID  is: " + event['spinnakerRefId'])
            print("Register Task Definition invoked by : "+ str(event['spinnakerRefId']))
            print("Register Task Definition invoked by email : "+ str(event['spinnakerUser']))
            
            tagslist = []
            if 'tagsmap' in event:
                print("Tags are: "+ str(event['tagsmap']))
                tagsmap_out = json.loads(event['tagsmap'])
                tagskeys=tagsmap_out.keys()
                for i in tagskeys:
                    tagslist.append({'key': i, 'value': tagsmap_out[i]})
    
            finlist = []
            if 'ApplicationName' in event:
                print("Checking finops mandatory tags..")
                appname=event['ApplicationName']
                out = get_configuration_new()
                for i in list(out['GREENFIELD']):
                    #print(appname)
                    #print(i)
                    if i['ApplicationName'] == None:
                        continue
                    if appname in i['ApplicationName'] and appname == i['ApplicationName']:
                        fintagskeys = i
                        fintagskeys_new =  { }
                        for key, value in fintagskeys.items():
                            if value != '':
                                fintagskeys_new.update({key: str(value)})
                        fintagskeys = fintagskeys_new
                        if 'tagsmap' in event:
                            tagsmap_out.update(fintagskeys)
                            tagskeys=tagsmap_out.keys()
                            for j in tagskeys:
                                finlist.append({'key': j, 'value': str(tagsmap_out[j])})
                print("Tags ready to apply...")
                print(finlist)

            import datetime
            tnow = datetime.datetime.now()
            tstring = tnow.strftime("%d%m%Y%H%M%S%f")
            
            if 'fulljson' not in event or event['fulljson'] == '':
                print("This is not bring your own JSON.. So creating json sample json and customizing it...")
                with open('RegisterTD.json') as json_file:
                    fulljson = json.load(json_file)
                fulljson = remove_empty_from_dict(fulljson)
                family = event['taskname']
                taskRoleArn = event['taskRoleArn']
                executionRoleArn = event['executionRoleArn']
                networkMode = event['networkMode']
                containerDefinitions = fulljson['containerDefinitions']
                containerDefinitions[0]['portMappings'][0]['hostPort'] = int(event['containerport'])
                containerDefinitions[0]['portMappings'][0]['containerPort'] = int(event['containerport'])
                containerDefinitions[0]['image'] = event['imageurl']
                containerDefinitions[0]['name'] = event['containername']
                requiresCompatibilities = fulljson['requiresCompatibilities']
                containerDefinitions[0]['logConfiguration']['options']['awslogs-group'] = event['BusinessUnit']+event['Csp']+event['Location']+'-'+event['Account']+'-/ecs/taskdefinitionfargate'+'-'+event['taskname']
                containerDefinitions[0]['logConfiguration']['options']['awslogs-region'] = event['awsregion']
                if event['secretmanagername']:
                    containerDefinitions[0]['repositoryCredentials'].update({ "credentialsParameter": 'arn:aws:secretsmanager:'+event['awsregion']+':'+event['pipelineaccountid']+':secret:'+event['secretmanagername']})
                if event['envvars']:
                    envvars = json.loads(event['envvars'])
                containerDefinitions[0]['environment'] = []
                count = 0
                if event['envvars']:
                    for i in envvars:
                        containerDefinitions[0]['environment'].append({ "name": i, "value": envvars[i] })
                        count = count + 1
                print(containerDefinitions)
                cpu = event['cpu']
                memory = event['memory']
            
                if 'volumes' in fulljson:
                    volumes = fulljson["volumes"]
                else:
                    volumes = [ { "name": "novol" } ]
    
            if 'fulljson' in event and event['fulljson'] != '':
                print("This is bring your own JSON.. So creating task definition from it...")
                fulljson = json.loads(event['fulljson'])
                fulljson = remove_empty_from_dict(fulljson)
                print(fulljson)
                family = fulljson['family']
                taskRoleArn = fulljson['taskRoleArn']
                executionRoleArn = fulljson['executionRoleArn']
                networkMode = fulljson['networkMode']
                requiresCompatibilities = fulljson['requiresCompatibilities']
                containerDefinitions = fulljson['containerDefinitions']
                cpu = fulljson['cpu']
                memory = fulljson['memory']
                if 'imageurl' in event and event['imageurl'] != "":
                    print("substituting image with input image..")
                    if '/' not in event['imageurl']:
                        if ':' not in event['imageurl']:
                            print("Looks like image revision is supplied..")
                            templist = fulljson['containerDefinitions'][0]['image'].split(':')
                            templist.pop()
                            print(':'.join(templist))
                            fulljson['containerDefinitions'][0]['image'] = ':'.join(templist) + ':' + event['imageurl']
                            print(fulljson['containerDefinitions'][0]['image'])
                    else:
                        fulljson['containerDefinitions'][0]['image'] = event['imageurl']

                if 'envvars' in event and event['envvars'] != "":
                    envvars = json.loads(event['envvars'])
                    containerDefinitions[0]['environment'] = []
                    count = 0
                    print("Adding or updating environment variables")
                    for i in envvars:
                        containerDefinitions[0]['environment'].append({ "name": i, "value": envvars[i] })
                        count = count + 1

                if 'volumes' in fulljson:
                    volumes = fulljson["volumes"]
                else:
                    volumes = [ { "name": "novol" } ]
            
            if int(cpu) > 4096 or int(memory) > 8192:
            #if int(cpu) > 8192 or int(memory) > 16384:
                print(int(cpu))
                print(int(memory))
                error = {"limit_issue": "Pipeline cannot be used for requested cpu or memory settings. cpu limit 4096 and memory limit 8192"}
                return { 'statusCode': 502, 'body': json.dumps(error) }
            
            jfrog_patterns = ['artifactory.saratestreachprod', 'artifactory.saratestintranet.net']
            if 'artifactory.saratestreachprod' not in event['imageurl'] and 'artifactory.saratestreachprod' not in fulljson['containerDefinitions'][0]['image'] and 'artifactory.saratestintranet.net' not in event['imageurl'] and 'artifactory.saratestintranet.net' not in fulljson['containerDefinitions'][0]['image']:
                print(str(event['imageurl']))
                error = {"image_issue": "Pipeline cannot be used for adding non jfrog 2.0 docker images.. failing the pipeline.."}
                return { 'statusCode': 502, 'body': json.dumps(error) }
                    
            if 'awsregion' in event:
                if event['awsregion'] == 'us-east-1':
                    creds = assumerole('arn:aws:iam::'+event['pipelineaccountid']+':role/SL-ROL-'+event['BusinessUnit']+event['Csp']+event['Location']+'-'+event['Account']+'-'+'fargate-lambda-role')
                    #print(creds)
                if event['awsregion'] == 'us-east-2':
                    creds = assumerole('arn:aws:iam::'+event['pipelineaccountid']+':role/SL-ROL-'+event['BusinessUnit']+event['Csp']+event['Location']+'-'+event['Account']+'-'+'fargate-lambda-role-us-east-2')
                if event['awsregion'] == 'eu-central-1':
                    creds = assumerole('arn:aws:iam::'+event['pipelineaccountid']+':role/SL-ROL-'+event['BusinessUnit']+event['Csp']+event['Location']+'-'+event['Account']+'-'+'fargate-lambda-role-eu-central-1')
                if event['awsregion'] == 'eu-west-1':
                    creds = assumerole('arn:aws:iam::'+event['pipelineaccountid']+':role/SL-ROL-'+event['BusinessUnit']+event['Csp']+event['Location']+'-'+event['Account']+'-'+'fargate-lambda-role-eu-west-1')
                
                owner = str(event['spinnakerUser'])
                refid = event['spinnakerRefId']
                if 'awslogs-group' in containerDefinitions[0]['logConfiguration']['options']:
                    loggroupname = containerDefinitions[0]['logConfiguration']['options']['awslogs-group']
                    create_awsloggroup(loggroupname,owner,refid,creds,tagsmap_out)
                    retdays = 7
                    create_retention_policy(loggroupname,retdays,creds)
                else:
                    loggroupname = ''
                    retdays = ''

                if 'fulljson' not in event or event['fulljson'] == '':
                    print("Creating task definition from sample json customizing.. part 2...")
                    fulljson = setessential(fulljson)
                    containerDefinitions = fulljson['containerDefinitions']
                    cleandict = register_task_definition(event['taskname'],event['taskRoleArn'],event['executionRoleArn'],event['networkMode'],containerDefinitions,requiresCompatibilities,event['cpu'],event['memory'],volumes,creds,loggroupname)
                if 'fulljson' in event and event['fulljson'] != '':
                    print("Creating task definition from bring your own json.. part 2...")
                    fulljson = setessential(fulljson)
                    containerDefinitions = fulljson['containerDefinitions']
                    cleandict = register_task_definition(family,taskRoleArn,executionRoleArn,networkMode,containerDefinitions,requiresCompatibilities,cpu,memory,volumes,creds,loggroupname)
                print(cleandict)
                if cleandict[1] == 'ERROR_TD':
                    a = str(cleandict[0])
                    out = a.split(":",1)
                    print(out)
                    return { 'statusCode': 403, 'body': json.dumps(out) }
                #webhook_out = json.dumps(cleandict)
                webhook_out = json.dumps(cleandict, indent=4, sort_keys=True, default=str)
                print('debug1')
                print(webhook_out)
                if event['awsregion'] == "us-east-1":
                    out = uploadtos3('RegisterTD/'+event['spinnakerRefId']+'-'+event['spinnakerUser']+'.json','saratestfargatetd',json.dumps(webhook_out))
                if event['awsregion'] == "us-east-2":
                    out = uploadtos3('RegisterTD/'+event['spinnakerRefId']+'-'+event['spinnakerUser']+'.json','saratestfargatetd-oh',json.dumps(webhook_out))
                if event['awsregion'] == "eu-central-1":
                    out = uploadtos3('RegisterTD/'+event['spinnakerRefId']+'-'+event['spinnakerUser']+'.json','saratestfargatetd-fr',json.dumps(webhook_out))
                if 'tagsmap' in event and 'ApplicationName' not in event:
                    tagsarn = cleandict[0]['taskDefinition']['taskDefinitionArn']
                    print("Adding custom Tags to "+str(tagsarn))
                    update_service_with_tags(tagsarn,tagslist,creds)
                    time.sleep(1)
                    tag_resources_general(taskRoleArn,tagsmap_out,creds)
                    time.sleep(1)
                    tag_resources_general(executionRoleArn,tagsmap_out,creds)
                if 'ApplicationName' in event:
                    tagsarn = cleandict[0]['taskDefinition']['taskDefinitionArn']
                    print("Adding finops Tags and custom tags to "+str(tagsarn))
                    update_service_with_tags(tagsarn,finlist,creds)
                    time.sleep(1)
                    tag_resources_general(taskRoleArn,tagsmap_out,creds)
                    time.sleep(1)
                    tag_resources_general(executionRoleArn,tagsmap_out,creds)
                logging_info1 = {"AWS Account for debug logs": "saratestreachprod", "lambda_function": context.log_group_name, "cloudwatch_logstream": context.log_stream_name}
                logging_info2 = {"loggroup created in the target account": loggroupname, "logstream retention in target account(contact operations for changing this value)": retdays}
                webhook_out_new = json.loads(webhook_out)
                webhook_out_new.append(logging_info1)
                webhook_out_new.append(logging_info2)
                return { 'statusCode': 200, 'body': json.dumps(webhook_out_new) }
    except Exception as e:
        print(e)
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        return { 'statusCode': 502, 'body': json.dumps({ "message": str(e) }) }
