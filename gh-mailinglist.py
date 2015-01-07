#!/usr/bin/env python
#-*- coding:utf-8 -*-

import BaseHTTPServer
import sys
import time
import urlparse
import json
import hashlib
import hmac
from email.parser import Parser
import smtplib


HOST_NAME = sys.argv[1]
PORT_NUMBER = int(sys.argv[2])
SECRET_KEY = sys.argv[3]
DEBUG = len(sys.argv) >= 5;


# from https://stackoverflow.com/questions/1265665/python-check-if-a-string-represents-an-int-without-using-try-except
def is_int(s):
    try:
        int(s)
        return True
    except ValueError:
        return False

def send_email(to, subject, body):

    msg = Parser().parsestr('From: <github_notifications@lists.prplfoundation.org>\n' +
        'To: <'+ to + '>\n' +
        'Subject: '+ subject + '\n' +
        '\n' +
        '' + body + '\n')
    if not DEBUG:
        s = smtplib.SMTP('localhost')
        s.sendmail('github_notifications@lists.prplfoundation.org', [to], msg.as_string())
        s.quit()
    else:
        print msg

def is_pull_request_url(potential_url):
    try:
        parse_result = urlparse.urlparse(potential_url)
        path_array = parse_result[2].split('/')
        return (path_array[len(path_array) - 2] == 'pull') and is_int(path_array[len(path_array) - 1])
    except ValueError:
        return False


def handle_pull_request_opened(payload, repos):
    email_and_name = repos.get_email_and_name(payload['repository']['name'])
    body = 'There\'s a new pull request by %s on the prpl %s repository\n\n' % (payload['sender']['login'], email_and_name['name'])

    body = body + '%s\n%s\nDescription: %s\n' % (payload['pull_request']['title'], payload['pull_request']['html_url'], payload['pull_request']['body'])
    #add link
    send_email(email_and_name['email'], "New pull request - %s" % (payload['pull_request']['title']), body)

def handle_pull_request_closed(payload, repos):
    email_and_name = repos.get_email_and_name(payload['repository']['name'])

    was_merged = payload['pull_request']['merged']
    merged_or_closed = "merged" if was_merged else "closed"
    body = 'There\'s a %s pull request on the prpl %s repository\n\n' % (merged_or_closed, email_and_name['name'])

    body = body + '%s\n%s\nDescription: %s\n' % (payload['pull_request']['title'], payload['pull_request']['html_url'], payload['pull_request']['body'])
    merged_or_closed = "Merged" if was_merged else "Closed"
    send_email(email_and_name['email'], "%s pull request - %s" % (merged_or_closed, payload['pull_request']['title']), body)

def handle_pull_request_review(payload, repos):
    email_and_name = repos.get_email_and_name(payload['repository']['name'])
    body = 'New comment by %s on prpl %s repository\n\n%s\nDescription:%s\n' % (payload['comment']['user']['login'], email_and_name['name'], payload['comment']['html_url'], payload['comment']['body'])
    send_email(email_and_name['email'], 'New comment on pull request', body)

def handle_pull_request_comment(payload, repos):
    email_and_name = repos.get_email_and_name(payload['repository']['name'])
    body = 'New comment by %s on prpl %s repository\n\n%s\nDescription:%s\n' % (payload['comment']['user']['login'], email_and_name['name'], payload['comment']['html_url'], payload['comment']['body'])
    send_email(email_and_name['email'], 'New comment on pull request', body)

def handle_issue_comment(payload, repos):
    if is_pull_request_url(payload['issue']['html_url']):
        handle_pull_request_comment(payload, repos)

def handle_issue_opened(payload,repos):
    email_and_name = repos.get_email_and_name(payload['repository']['name'])
    body = 'New issue by %s on prpl %s repository\n\n%s\nDescription: %s\n' % (payload['issue']['user']['login'], email_and_name['name'], payload['issue']['html_url'], payload['issue']['body'])
    send_email(email_and_name['email'], 'New issue posted - %s' % (payload['issue']['title']), body)

def handle_issue_closed(payload,repos):
    email_and_name = repos.get_email_and_name(payload['repository']['name'])
    body = 'Closed issue by %s on prpl %s repository\n\n%s\nDescription: %s\n' % (payload['issue']['user']['login'], email_and_name['name'], payload['issue']['html_url'], payload['issue']['body'])
    send_email(email_and_name['email'], 'Issue Closed - %s' % (payload['issue']['title']), body)

def handle_hook(event, payload, repos):
    if event == 'pull_request':
        if payload['action'] == 'opened':
            return handle_pull_request_opened(payload, repos)
        elif payload['action'] == 'closed':
            return handle_pull_request_closed(payload, repos)
    elif event == 'pull_request_review_comment':
        return handle_pull_request_review(payload, repos)

    elif event == 'issue_comment':
        return handle_issue_comment(payload, repos)
    elif event == 'issues':
        if payload['action'] == 'opened':
            return handle_issue_opened(payload,repos)
        elif payload['action'] == 'closed':
            return handle_issue_closed(payload, repos)
    else:
        pass


def verify_signature(payload, hub_signature):
    signature = 'sha1=' + hmac.new(SECRET_KEY, payload, hashlib.sha1).hexdigest()
    #should use compare_digest but isn't in our current python implementation.
    #also, we're not protecting nuclear secrets so we should be fine
    return signature == hub_signature

class JsonRepos:
    def __init__(self,json_file):
        self.json_file = json_file
        self.json = json.load(open(json_file))

    def get_email_and_name(self, repo_name):
        return self.json[repo_name]

class HookHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    server_version = "HookHandler/0.1"
    def do_GET(s):
        s.send_response(200)

    def do_POST(s):
        repos = JsonRepos('repos.json')
        length = int(s.headers['Content-Length'])
        full_payload = s.rfile.read(length).decode('utf-8')
        post_data = urlparse.parse_qs(full_payload)
        payload = json.loads(post_data['payload'][0])
        if not DEBUG and not verify_signature(full_payload, s.headers['X-Hub-Signature']):
            s.send_error(403)
            return

        event = s.headers['X-GitHub-Event']
        handle_hook(event, payload, repos)

        s.send_response(200)


if __name__ == '__main__':
    server_class = BaseHTTPServer.HTTPServer
    httpd = server_class((HOST_NAME, PORT_NUMBER), HookHandler)
    print time.asctime(), "Server Starts - %s:%s" % (HOST_NAME, PORT_NUMBER)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print time.asctime(), "Server Stops - %s:%s" % (HOST_NAME, PORT_NUMBER)
