import requests
import smtplib
import argparse
import json
import re

from datetime import *
from email import encoders
from email.message import Message
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.header import Header

MAIL_SMTP = "smtp.mail.ru:587"
SUSPICIOUS_SUBJECT = "suspecious activity report!"
MIN_DELTA_DAYS_FOR_REQUEST = 7 
MIN_REQUESTS_TO_DROP = 50

tarball_regex = re.compile(r"e.mail.ru-f-(.+)-([^-]+)-(\d+)\.tgz")
api_token_regex = re.compile(r"(?:updateToken\(\")([0-9a-f]+:[0-9a-f]+)")
email_regex = re.compile(r"([^@]+)@(.+)")
user_profile_regex = re.compile(r"^([^\s]+)\s*([^\s]+)$")

def gen_auth_request(login,domain,password):
    return {
        "new_auth_form" : "1",
        "page" : "https://e.mail.ru/messages/inbox?back=1",
        "from" : "mail.login",
        "back" : "1",
        "FromAccount" : "v=0.3.13",
        "type" :"login",
        "allow_external" : "1",
        "opener":"mail.login",
        "modal" : "1",
        "Login" : "".join((login,"@",domain)),
        "Username" : login,
        "Password" : password,
        "saveauth" : "1",
    }

def gen_activity_request(login,domain,tarball,token,date_from,date_to):
    return "".join((
        "https://e.mail.ru/api/v1/user/activity"
        "?ajax_call=1",
        "".join(("&x-email={0}@".format(login),domain)),
        "&tarball={0}".format(tarball),
        "&email={0}@{1}".format(login,domain),
        "&htmlencoded=false",
        "&date_to={0}".format(str(date_to)),
        "&date_from={0}".format(str(date_from)),
        "&api=1",
        "&token={0}".format(token),
    ))

class TokenAcquireException(Exception):
    pass

class JsonConversionException(Exception):
    pass

class InvalidRequestException(Exception):
    pass

class User():
    def __init__(self,email,password):
        
        if re.match(email_regex,email):
            data = re.search(email_regex,email).groups()
            self.login = data[0]
            self.domain = data[1]
        else:
            self.login = email
            self.domain = "mail.ru"
            
        self.password = password
        self.has_active_session = 0
    
       
    def auth(self):
        session = requests.Session()
        session.post("https://auth.mail.ru/cgi-bin/auth",
			data=gen_auth_request(self.login,
						self.domain,
						self.password))
        self.has_active_session = 1
        self.session = session
    
    def check_session(self):
        return
    
def get_request_parameters(user):
    if user.has_active_session == 0:
        user.auth()
        
    response = user.session.get("https://e.mail.ru/settings/security")
        
    try:
        token = re.search(api_token_regex,response.text).groups()[0]
        tarball = re.search(tarball_regex,response.text).group()
    except:
        raise TokenAcquireException
    
    return token, tarball
  
def get_activities(user, date_from, date_to):
    token, tarball = get_request_parameters(user)
    response = user.session.get(gen_activity_request(user.login,
                                                     user.domain,
                                                     tarball,
                                                     token,
                                                     date_from,
                                                     date_to)) #460-2500ms
    try:
        data = json.loads(response.text)
    except:
        raise JsonConversionException
        
    if data["status"] != 200:
        raise InvalidRequestException
          
    return data["body"]

def send_report(user,mail_to,subject,data,server_name=MAIL_SMTP):
    server = smtplib.SMTP(server_name)
    server.starttls()
    
    user_email = "".join((user.login,"@",user.domain))
    server.login(user_email, user.password)

    mail_from = user_email
    msg = MIMEMultipart()
    msg["Subject"] = Header(subject,"utf-8")
    msg["From"] = mail_from
    msg["To"] = mail_to

    msg_text = MIMEText(data.encode("utf-8"), "plain", "utf-8")
    msg.attach(msg_text)
    
    server.sendmail(mail_from , mail_to, msg.as_string())
    server.quit()
   
def activity_to_text(record, email):
    active_from = datetime.fromtimestamp(int(record["from"]))
    active_to = datetime.fromtimestamp(int(record["to"]))
    
    ip = record["ip"].strip()
    agent = record["agent"].strip()
    agent_original = record["agent_original"].strip()
    region = record["region"].strip()
    title = record["title"].strip()
    activity = record["acca_title"].strip()
    
    text = u"".join((
                    u"In {0} there was follow activity: {1} {2}\n".format(email, activity,title),
                    u"IP:{0}\n".format(ip),
                    u"User agent: {0}, ({1})\n".format(agent,agent_original),
                    u"Region: {0}\n".format(region),
                    u"Lasted: {0} - {1}\n".format(active_from, active_to),
                   ))
    return text


def check_ips(activities,ips_to_check,check_time,last_ok_time):
    for item in activities["items"]:
        if item["ip"] in ips_to_check:
            if int(item["from"]) <= check_time - last_ok_time:
                ips_to_check.remove(item["ip"])
                if len(ips_to_check) == 0:
                    break
    
    return ips_to_check
    

def check_activity(user,whitelist_ips,last_ok_time,check_time):
    epoch = datetime.utcfromtimestamp(0)
    now = datetime.now()
    report = ""
    
    date_to = int((now-epoch).total_seconds())
    time_delta = int(timedelta(days=MIN_DELTA_DAYS_FOR_REQUEST).total_seconds())
    date_from = int(date_to - time_delta)
    
    try:
        activities = get_activities(user,date_from,date_to)
    except:
        user.auth()
        activities = get_activities(user,date_from,date_to)
        
    if len(activities["items"]) == 0:
        return report
        
    ips = [item["ip"] for item in activities["items"]]
    ips_to_check = check_ips(activities,
                             set(ips).difference(whitelist_ips),
                             check_time,
                             last_ok_time)
    
    if len(ips_to_check) == 0:
        return report
    
    recent_activities = activities
    min_date_from = activities["meta"]["min_date_from"]
    date_to = min([item["from"] for item in activities["items"]])
    user_email = "".join((user.login,"@",user.domain))
    n_requests = 0
    
    while date_to + 1 > min_date_from + time_delta and n_requests <= MIN_REQUESTS_TO_DROP:
        try:
            activities = get_activities(user,min_date_from,date_to)
        except:
            user.auth()
            activities = get_activities(user,min_date_from,date_to)
        
        n_requests += 1
            
        date_to = min([item["from"] for item in activities["items"]])  
        if len(activities["items"]) == 0:
            break  
            
        ips_to_check = check_ips(activities,
                             ips_to_check,
                             check_time,
                             last_ok_time)
    
        if len(ips_to_check) == 0:
            return report
        
        date_to = min([item["from"] for item in activities["items"]])
    
    for item in recent_activities["items"]:
        if item["ip"] in ips_to_check:
            report += activity_to_text(item,user_email)
    return report

def check_users(users,whitelist_ip,last_ok_time,report_user,report_emails):
    report = ""
    log = ""
    
    epoch = datetime.utcfromtimestamp(0)
    now = datetime.now()

    check_time = int((now-epoch).total_seconds())
    for user in users:
        try:
            check_report = check_activity(user,whitelist_ip,last_ok_time,check_time)
            report += check_report

        except TokenAcquireException:
            log += "Unknown error while token acquisition for user: {0}@{1}\n".format(user.login,user.domain)
            pass

        except JsonConversionException:
            log += "Unknown error while JSON conversion for user: {0}@{1}\n".format(user.login,user.domain)
            pass

        except InvalidRequestException:
            log += "Request to API failed for user: {0}@{1}\n".format(user.login,user.domain)
            pass
        
    if report == "" and log == "":
        print "Ok! Elapsed time: {0}\n".format((datetime.now() - now).total_seconds())
        return
    
    report += "Check start time {0}\n".format(str(now))
    report += "Elapsed time: {0}\n".format(str((datetime.now() - now).total_seconds()))
    
    if log != "":
        report += "Error log:\n"
        report += log
    
    for email in report_emails:
        send_report(report_user,email,SUSPICIOUS_SUBJECT,report,MAIL_SMTP)
        
    return
 
def read_users_from_file(filename):
    users = []
    with open(filename,"r") as f:
        for line in f:
            try:
                res = re.search(user_profile_regex,line).groups()
                user = User(res[0],res[1])
                users.append(user)
            except:
                pass
            
    return users

def main():
    parser = argparse.ArgumentParser(description='Simple Mail Monitor')
    parser.add_argument('--users', help='file with users logins/passwords')
    parser.add_argument('--whitelist', help='whitelist of ip addresess')
    parser.add_argument('--trusted_interval', help='trusted interval in hours')
    parser.add_argument('--notified_emails',help='list of emails which would recive reports')
    parser.add_argument('--notifier_account',help='file with notifier mail login/password')

    args = parser.parse_args()

    users = read_users_from_file(args.users)
    whitelist = []
    with open(args.whitelist,"r") as f:
        for lines in f:
            whitelist.append(lines.strip().strip(','))

    notified_emails = []

    with open(args.notified_emails,"r") as f:
        for lines in f:
            mail = lines.strip().strip(',')
            if re.match(email_regex,mail):
                notified_emails.append(mail)
    
    notifier_account = read_users_from_file(args.notifier_account)[0]
    last_ok_time = int(args.trusted_interval)*60*60 # in seconds
    check_users(users,whitelist,last_ok_time,notifier_account,notified_emails)
    return


if __name__ == "__main__":
    main()
