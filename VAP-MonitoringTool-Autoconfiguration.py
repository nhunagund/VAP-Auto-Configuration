'''
Created on Apr 26, 2018
@author: shivaprasad Hiremath
@email: shiremath@vmware.com

This is developed using python3.6
'''

import time
import logger
import requests
import json
import sys
from logger import logger
import paramiko
import re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_vap_token(ucp_ip, ucp_passwd):
    logger.info("Get TOKEN")
    logger.info('ucp_ip: %s', ucp_ip)
    logger.info('ucp_passwd: %s', ucp_passwd)
    logger.info('calling API for getting Token')
    url = "https://%s:9000/core/authn/basic" % ucp_ip
    data = '''{
                "requestType" : "LOGIN"
                }'''
    logger.info('data: %s', data)
    logger.info('url: %s', url)
    while True:
        try:
            response = requests.post(url, data=data, auth=('admin@ucp.local', '%s' % ucp_passwd), verify=False)
            break
        except:
            print("Connection refused by the server..")
            logger.error("Connection refused by the server..")
            time.sleep(10)
            logger.info("After sleep, trigger the post again")
            continue
    logger.info('response: %s', response)
    logger.info('response.status_code: %s', response.status_code)
    responseStatusCode = response.status_code
    if responseStatusCode != 200:
        logger.error('Received incorrect response, Generate Token again')
        time.sleep(5)
        while True:
            try:
                response = requests.post(url, data=data, auth=('admin@ucp.local', '%s' % ucp_passwd), verify=False)
                break
            except:
                logger.error("Connection refused by the server..")
                time.sleep(10)
                logger.info("After sleep, trigger the post again")
                continue
        responseStatusCode = response.status_code
        logger.info('response.headers: %s', response.headers['x-xenon-auth-token'])
        token = response.headers['x-xenon-auth-token']
        " ".join(token.split())
        return str(token)
    else:
        token = response.headers['x-xenon-auth-token']
        " ".join(token.split())
        return token

def test_connection_vap_to_wf(ucp_ip, token):
    logger.info('Test Connection from VAP to WaveFront')
    headers = {'x-xenon-auth-token': ''}
    headers['x-xenon-auth-token'] = token
    logger.info('headers: %s', headers)
    url = "https://"+ucp_ip+":9000/ucp/wavefront/testconnection"
    data = '''{
            "url":"https://appproxy.wavefront.com/",
            "apiToken":"0d073dd9-d0d8-45e4-becb-3b9aaa6ba6a9"
           }'''
    response = requests.post(url, data=data, headers=headers, verify=False)
    connection_status = json.loads(response.text)
    logger.info(connection_status["connected"])
    logger.info('response status code : %s', response.status_code)
    if response.status_code == 200 and connection_status["connected"] == True:
        return True
    else:
        return False

def register_vap_to_wf(ucp_ip, token):
    logger.info('Register VAP to WaveFront')
    headers = {'x-xenon-auth-token': ''}
    headers['x-xenon-auth-token'] = token
    logger.info('headers: %s', headers)
    url = "https://"+ucp_ip+":9000/ucp/wavefront/connection"
    data = '''{
            "url":"https://appproxy.wavefront.com/",
            "apiToken":"0d073dd9-d0d8-45e4-becb-3b9aaa6ba6a9",
            "action" :"REGISTER"
           }'''
    response = requests.post(url, data=data, headers=headers, verify=False)
    logger.info('response status code : %s', response.status_code)
    responseStatusCode = response.status_code
    if responseStatusCode == 200:
        return True
    else:
        return False

def ssh_connect(nimbusgatewayhost, nimbususer, nimbuspassword):
    print ("ssh to end point")
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect('%s'%nimbusgatewayhost, 22, '%s'%nimbususer, password='%s'%nimbuspassword)
        return ssh
    except paramiko.AuthenticationException:
        logger.info("Authentication failed when connecting to Host : {}".format(nimbusgatewayhost))
        sys.exit(1)
    except:
        print("Could not connect to host : ", nimbusgatewayhost)
        logger.info("Could not connect to host : {}".format(nimbusgatewayhost))
        sys.exit(1)

def send_command(ssh, command):
    logger.info("Executing Command : {}".format(command))
    stdin, stdout, stderr = ssh.exec_command('%s' % command)
    stdoutput = stdout.readlines()
    print("STDOUT : ", len(stdoutput))
    print(stdoutput)
    erroroutput = stderr.readlines()
    print("STDERR :", len(erroroutput))
    print(erroroutput)
    if '127' in erroroutput:
        logger.info("Command Execution Failed")
    else:
        pass
    return (stdoutput)

def deploy_packages(host, user, passwd, command):
    logger.info("Deploy packages for this Host : {}".format(host))
    print(command)
    ssh = ssh_connect(host, user, passwd)
    stdout = send_command(ssh, command)
    print(stdout)
    output = stdout
    time.sleep(10)
    disconnect_ssh(ssh)
    return output

def disconnect_ssh(ssh):
    logger.info("Disconnect ssh connection")
    ssh.close()

def check_dockers(vapip, vap_username, vap_passwd, command):
    containercount = 0
    logger.info('Getting number of docker containers running in VAP')
    logger.info(vapip)
    ssh = ssh_connect(vapip, vap_username, vap_passwd)
    output = send_command(ssh, command)
    logger.info('Check All 6 containers are running')
    # logger.info(output)
    # print(len(output))
    for container in output:
        if 'ucp-forwarder' in container:
            print("Found")
            containercount += 1
        elif 'wavefront-proxy' in container:
            containercount += 1
        elif 'ucp-apis' in container:
            containercount += 1
        elif 'ucp-dataplane-emqttserver' in container:
            containercount += 1
        elif 'ucp-controlplane-saltmaste' in container:
            containercount += 1
        elif 'ucp-nginx' in container:
            containercount += 1
    print(containercount)
    return containercount

def get_dashboard(url, waveFrontToken, dashboardID, telegrafConfName, vapip):
    logger.info("Get all the details about this Dashboard: {}".format(dashboardID))
    url = "https://appproxy.wavefront.com/api/v2/dashboard/" + dashboardID
    print("URL  :", url)
    print("telegrafConfName :", telegrafConfName)
    headers = {'Authorization': '', 'Accept': 'application/json'}
    headers['Authorization'] = "Bearer " + waveFrontToken
    logger.info('headers: %s', headers)
    response = requests.get(url, headers=headers, verify=False)
    print(type(response.text))
    print("Content :", type(response.content))
    logger.info('response status code : %s', response.status_code)
    responseStatusCode = response.status_code
    if responseStatusCode == 200:
        print("TRUE")
        responseBody = response.text
        responseJson = json.loads(responseBody)
        print(type(responseJson))
        sections = len((responseJson["response"]["sections"]))
        print("Sections :", sections)
        queriescount = 0
        for k in range(0, sections):
            print("Processing :", responseJson["response"]["sections"][k]["name"])
            rowsSystemMetrics = len(responseJson["response"]["sections"][k]["rows"])
            for i in range(0, rowsSystemMetrics):
                print(len(responseJson["response"]["sections"][k]["rows"][i]["charts"]))
                chartsSystemMetrics = len(responseJson["response"]["sections"][k]["rows"][i]["charts"])
                for j in range(0, chartsSystemMetrics):
                    print(responseJson["response"]["sections"][k]["rows"][i]["charts"][j]["name"])
                    print(responseJson["response"]["sections"][k]["rows"][i]["charts"][j]["sources"][0]["query"])
                    queriescount += 1
        logger.info(queriescount)
        with open('responseWf.txt', 'w') as outfile:
            json.dump(response.text, outfile)

        f = 'responseWf.txt'
        findname = '8june.vap1001.uptime.test.'
        replacename = telegrafConfName
        findip = "10.196.77.179"
        replaceip = vapip

        # with open(f, "r") as myfile:
        #     s = myfile.read()
        ret = re.sub(findname, replacename, responseBody)  # <<< This is where the magic happens
        ret = re.sub(findip, replaceip, ret)
        # with open('modresponseWf.json', 'w') as outfile:
        #     outfile.write(ret)
        #
        # with open('modresponseWf.json') as f:
        #     outputjson = json.load(f)
        outputjson = json.loads(ret)

        logger.info('After Processing all final content')
        print(type(outputjson))
        print(type(len(outputjson["response"]["sections"])))
        sectionsafter = len(outputjson["response"]["sections"])
        print("Sections :", sectionsafter)
        queriescountafter = 0
        for k in range(0, sectionsafter):
            print("Processing :", outputjson["response"]["sections"][k]["name"])
            rowsSystemMetrics = len(outputjson["response"]["sections"][k]["rows"])
            for i in range(0, rowsSystemMetrics):
                print(len(outputjson["response"]["sections"][k]["rows"][i]["charts"]))
                chartsSystemMetrics = len(outputjson["response"]["sections"][k]["rows"][i]["charts"])
                for j in range(0, chartsSystemMetrics):
                    print(outputjson["response"]["sections"][k]["rows"][i]["charts"][j]["name"])
                    print(outputjson["response"]["sections"][k]["rows"][i]["charts"][j]["sources"][0]["query"])
                    queriescountafter += 1
        logger.info(queriescountafter)

        with open('responsemodWf.txt', 'w') as outfile:
            json.dump(outputjson, outfile)
        return outputjson
    else:
        print("FALSE")
        return False

def create_dashBoard(url, waveFrontToken, dashboardname, jsonput):
    print("Create a new Dashboard: " + dashboardname)
    url = "https://appproxy.wavefront.com/api/v2/dashboard/"
    print("URL  :", url)
    headers = {"Authorization": " ", "Accept": "application/json", "Content-Type": "application/json"}
    headers['Authorization'] = "Bearer " + waveFrontToken
    logger.info('HEADERS: %s', headers)
    print(jsonput["response"])
    print(type(jsonput["response"]))
    print(jsonput["response"]["name"])
    print(jsonput["response"]["id"])
    print(jsonput["response"]["url"])

    jsonput["response"]["name"] = dashboardname
    jsonput["response"]["id"] = dashboardname
    jsonput["response"]["url"] = dashboardname

    print(jsonput["response"]["name"])
    print(jsonput["response"]["id"])
    print(jsonput["response"]["url"])

    print(jsonput["response"])
    sections = jsonput["response"]["sections"]
    # sections = json.dumps(jsonput["response"]["sections"])
    print(sections)

    bodydata = '''
        {
          "name": "example",
          "id": "example",
          "url": "example",
          "description": "Dashboard Description",
          "sections": []
        }'''

    findtext = "example"
    bodydata = re.sub(findtext, dashboardname, bodydata)

    body = json.loads(bodydata)
    print(body["name"])
    body["sections"] = sections
    print(body)

    finalbody = json.dumps(body)
    print(finalbody)
    print(type(finalbody))

    # Final Body is present, Please create a new DashBoard.
    response = requests.post(url, headers=headers, data=finalbody, verify=False)
    logger.info('response status code : %s', response.status_code)
    print(response.text)
    print(response.content)
    responseStatusCode = response.status_code
    if responseStatusCode == 200:
        print("TRUE")
    else:
        print("FALSE")

def main():
    logger.info("Configure WaveFront DashBoard for VAP Scale and Uptime")
    ucp_password = 'VMware@123' # Please provide VAP API Password
    vap_username = 'root'
    root_vap_passwd = 'VMware@123' # Please provide VAP root Password
    url = "https://appproxy.wavefront.com/api/v2/dashboard/" # Please provide WaveFront URL
    waveFrontToken = "" # Please provide WaveFront Token
    dashboardID = "ShivaUptimeTest" # Please do not change this value
    dashboardName = "19Dec_VAP1_2_UptimeTest" # Please provide new DashBoard Name
    telegrafConfName = "19Dec.VAP1.2.UptimeTest." # Please provide telegraf configuration name which is used as a prefix in telegraf.cong file
    vapip = "10.40.62.223" # Please provide VAP IP

    # time.sleep(200)
    # Register to VAP to WF
    token = get_vap_token(vapip, ucp_password)
    logger.info("Token : {}".format(token))

    if test_connection_vap_to_wf(vapip, token):
        if register_vap_to_wf(vapip, token):
            logger.info("Registered VAP to WF successfully")
            time.sleep(60)
        else:
            logger.info("Test connection succeeded but Registered VAP to WF Failed")
    else:
        logger.info("Test connection VAP to WF Failed")
        sys.exit(0)

    command = "docker ps -a;echo $?"
    container_count = check_dockers(vapip, vap_username, root_vap_passwd, command)
    logger.info(container_count)
    if container_count == 6:
        logger.info("All the 6 containers are running successfully")
    elif container_count == 0:
        logger.info("None of the containers are running")
    else:
        logger.info("Only some of the containers are running")

    time.sleep(60)

    cmdBeforeReboot1 = ['systemctl enable sshd',
                'wget http://10.126.37.161/ucp/ucptemplates/perfandscale/telegraf.conf; echo $?',
                'wget http://10.126.37.161/ucp/ucptemplates/perfandscale/telegraf-1.8.3_linux_amd64.tar.gz; echo $?',
                'wget http://10.126.37.161/ucp/ucptemplates/perfandscale/docker.service; echo $?',
                'tar -zxpf /root/telegraf-1.8.3_linux_amd64.tar.gz; echo $?']

    cmdBeforeReboot2 = 'sed -i \'/prefix = \"31May_VAP1.0.0.1_Uptime_Med_Test.\"/c \   prefix = "'+telegrafConfName+'"\' /root/telegraf.conf; echo $?'

    cmdBeforeReboot3 = ['mv /root/telegraf/etc/telegraf /etc; echo $?',
                'mv -f /root/telegraf.conf /etc/telegraf/; echo $?',
                'sed -i \'/ExecStart=/c \#ExecStart=/usr/bin/dockerd\' /usr/lib/systemd/system/docker.service; echo $?',
                'sed -i \'/#ExecStart=/ a ExecStart=/usr/bin/dockerd -H tcp://0.0.0.0:2376 -H unix:///var/run/docker.sock\' /usr/lib/systemd/system/docker.service; echo $?',
                'tdnf -y install dstat; echo $?',
                'vamicli version --appliance;echo $?']

    ucpapicommand1 = 'sed -i \'/export UCP_APIS_JAR=ucp-apis-1.0.0-SNAPSHOT.jar/a \export DEFAULT_OPTS="-Dcom.sun.management.jmxremote.port=5555 -Dcom.sun.management.jmxremote.ssl=false -Dcom.sun.management.jmxremote.local.only=false"\'  /ucp/ucpapis/start.sh; echo $?'
    ucpapicommand2 = 'sed -i \'/export DEFAULT_OPTS=/a \DEFAULT_OPTS="$DEFAULT_OPTS -Djava.rmi.server.hostname='+vapip+' -Dcom.sun.management.jmxremote.authenticate=false -Dcom.sun.management.jmxremote.rmi.port=5555"\'  /ucp/ucpapis/start.sh; echo $?'
    ucpapicommand3 = 'sed -i \'/DEFAULT_OPTS="$DEFAULT_OPTS/a \export GCLOG="-XX:-PrintGCCause -XX:+PrintGCDetails -XX:+PrintGCTimeStamps -XX:+PrintGCDateStamps -Xloggc:/ucp/ucpapis/log/ucpapi_gc.log -XX:+UseGCLogFileRotation"\' /ucp/ucpapis/start.sh; echo $?'
    ucpapicommand4 = 'sed -i \'/export GCLOG=/a \GCLOG="$GCLOG -XX:NumberOfGCLogFiles=10 -XX:GCLogFileSize=30M"\' /ucp/ucpapis/start.sh; echo $?'
    ucpapicommand5 = 'sed -i \'s/\\b\local\/bin\/java\\b/& $DEFAULT_OPTS $GCLOG/\' /ucp/ucpapis/start.sh; echo $?'
    ucpapicommand6 = 'sed -i \'s/\\b -p 9000:8000 -p 7777:7777\\b/& -p 5555:5555/\' /ucp/ucp-config-scripts/ucp-firstboot.sh ; echo $?'

    wavefrontproxycommand1 = 'sed -i \'/export WAVEFRONT_HOSTNAME/a \export DEFAULT_OPTS="-Dcom.sun.management.jmxremote.port=5556 -Dcom.sun.management.jmxremote.ssl=false -Dcom.sun.management.jmxremote.local.only=false"\' /ucp/wavefront-proxy/start.sh; echo $?'
    wavefrontproxycommand2 = 'sed -i \'/export DEFAULT_OPTS=/a \DEFAULT_OPTS="$DEFAULT_OPTS -Djava.rmi.server.hostname='+vapip+' -Dcom.sun.management.jmxremote.authenticate=false -Dcom.sun.management.jmxremote.rmi.port=5556"\' /ucp/wavefront-proxy/start.sh; echo $?'
    wavefrontproxycommand3 = 'sed -i \'/DEFAULT_OPTS="$DEFAULT_OPTS/a \export GCLOG="-XX:-PrintGCCause -XX:+PrintGCDetails -XX:+PrintGCTimeStamps -XX:+PrintGCDateStamps -Xloggc:/ucp/wavefront-proxy/log/wavefront_gc.log -XX:+UseGCLogFileRotation"\' /ucp/wavefront-proxy/start.sh; echo $?'
    wavefrontproxycommand4 = 'sed -i \'/export GCLOG=/a \GCLOG="$GCLOG -XX:NumberOfGCLogFiles=10 -XX:GCLogFileSize=30M"\' /ucp/wavefront-proxy/start.sh; echo $?'
    wavefrontproxycommand5 = 'sed -i \'s/\\b\local\/bin\/java\\b/& $DEFAULT_OPTS $GCLOG/\' /ucp/wavefront-proxy/start.sh; echo $?'
    wavefrontproxycommand6 = 'sed -i \'s/\\b JAVA_HEAP_USAGE=512m  -p 2878:2878\\b/& -p 5556:5556/\' /ucp/ucp-config-scripts/ucp-firstboot.sh; echo $?'

    forwardercommand1 = 'sed -i \'/export UCP_FORWARDER_JAR=ucp-forwarder.jar/a \export DEFAULT_OPTS="-Dcom.sun.management.jmxremote.port=5557 -Dcom.sun.management.jmxremote.ssl=false -Dcom.sun.management.jmxremote.local.only=false"\' /ucp/forwarder/start.sh; echo $?'
    forwardercommand2 = 'sed -i \'/export DEFAULT_OPTS=/a \DEFAULT_OPTS="$DEFAULT_OPTS -Djava.rmi.server.hostname='+vapip+' -Dcom.sun.management.jmxremote.authenticate=false -Dcom.sun.management.jmxremote.rmi.port=5557"\' /ucp/forwarder/start.sh; echo $?'
    forwardercommand3 = 'sed -i \'/DEFAULT_OPTS="$DEFAULT_OPTS/a \export GCLOG="-XX:-PrintGCCause -XX:+PrintGCDetails -XX:+PrintGCTimeStamps -XX:+PrintGCDateStamps -Xloggc:/ucp/forwarder/log/forwarder_gc.log -XX:+UseGCLogFileRotation"\' /ucp/forwarder/start.sh; echo $?'
    forwardercommand4 = 'sed -i \'/export GCLOG=/a \GCLOG="$GCLOG -XX:NumberOfGCLogFiles=10 -XX:GCLogFileSize=30M"\' /ucp/forwarder/start.sh; echo $?'
    forwardercommand5 = 'sed -i \'s/\\b\local\/bin\/java -Xms128m -Xmx256m\\b/& $DEFAULT_OPTS $GCLOG/\' /ucp/forwarder/start.sh; echo $?'
    forwardercommand6 = 'sed -i \'s/\\b 8696:8696\\b/& -p 5557:5557/\' /ucp/ucp-config-scripts/ucp-firstboot.sh; echo $?'

    restartcontainer = ['/ucp/ucp-config-scripts/ucp-firstboot.sh -a cleanup_dockers ; echo $?',
                        '/ucp/ucp-config-scripts/ucp-firstboot.sh ; echo $?',
                        'reboot']

    cmdAfterReboot = ['mkdir /data1/system_monitoring',
                      '/usr/bin/dstat -tlnr -c --top-cpu -dn --top-mem --top-io --top-bio -f --output /data1/system_monitoring/system_report.csv 10 > /dev/null 2>&1 &',
                      '/root/telegraf/usr/bin/telegraf > /dev/null 2>&1 &']

    # Install and Configure Monitoring Tools in VAP

    for i in cmdBeforeReboot1:
        deploy_packages(vapip, 'root', 'VMware@123', i)
        time.sleep(5)
    deploy_packages(vapip, 'root', 'VMware@123', cmdBeforeReboot2)
    for i in cmdBeforeReboot3:
        deploy_packages(vapip, 'root', 'VMware@123', i)
        time.sleep(5)

    deploy_packages(vapip, 'root', 'VMware@123', ucpapicommand1)
    deploy_packages(vapip, 'root', 'VMware@123', ucpapicommand2)
    deploy_packages(vapip, 'root', 'VMware@123', ucpapicommand3)
    deploy_packages(vapip, 'root', 'VMware@123', ucpapicommand4)
    deploy_packages(vapip, 'root', 'VMware@123', ucpapicommand5)
    deploy_packages(vapip, 'root', 'VMware@123', ucpapicommand6)
    time.sleep(30)

    deploy_packages(vapip, 'root', 'VMware@123', wavefrontproxycommand1)
    deploy_packages(vapip, 'root', 'VMware@123', wavefrontproxycommand2)
    deploy_packages(vapip, 'root', 'VMware@123', wavefrontproxycommand3)
    deploy_packages(vapip, 'root', 'VMware@123', wavefrontproxycommand4)
    deploy_packages(vapip, 'root', 'VMware@123', wavefrontproxycommand5)
    deploy_packages(vapip, 'root', 'VMware@123', wavefrontproxycommand6)
    time.sleep(30)

    deploy_packages(vapip, 'root', 'VMware@123', forwardercommand1)
    deploy_packages(vapip, 'root', 'VMware@123', forwardercommand2)
    deploy_packages(vapip, 'root', 'VMware@123', forwardercommand3)
    deploy_packages(vapip, 'root', 'VMware@123', forwardercommand4)
    deploy_packages(vapip, 'root', 'VMware@123', forwardercommand5)
    deploy_packages(vapip, 'root', 'VMware@123', forwardercommand6)
    time.sleep(30)

    for i in restartcontainer:
        deploy_packages(vapip, 'root', 'VMware@123', i)
        time.sleep(250)

    for i in cmdAfterReboot:
        deploy_packages(vapip, 'root', 'VMware@123', i)
        time.sleep(10)

    # wf = wavefront.waveFrontService()
    jsonoutput = get_dashboard(url, waveFrontToken, dashboardID, telegrafConfName, vapip)
    print(" IN MAIN")
    print(type(jsonoutput))
    print(jsonoutput["response"])
    create_dashBoard(url, waveFrontToken, dashboardName, jsonoutput)

if __name__ == '__main__':
    main()
