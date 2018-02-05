#!/usr/bin/python3
#
# imap2thehive.py - Poll a IMAP mailbox and create new cases/alerts in TheHive
#
# Author: Xavier Mertens <xavier@rootshell.be>
# Copyright: GPLv3 (http://gplv3.fsf.org)
# Fell free to use the code, but please share the changes you've made
#
# Todo:
# - Configuration validation
# - Make the alert keyword part of the config file
#

from __future__ import print_function
from __future__ import unicode_literals
import argparse
import configparser
import imaplib
import os,sys
import email
import email.header
import gnupg
import io
import chardet
import time,datetime
import json
import requests
import uuid

try:
    from thehive4py.api import TheHiveApi
    from thehive4py.models import Case, CaseTask, CustomFieldHelper
    from thehive4py.models import Alert, AlertArtifact
except:
    print("[ERROR] Please install thehive4py.")
    sys.exit(1)

# Default configuration 
args = ''
config = {
    'imapHost': '',
    'imapPort': '',
    'imapUser': '',
    'imapPassword': '',
    'imapFolder': '',
    'thehiveURL': '',
    'thehiveUser': '',
    'thehivePassword': '',
    'caseTLP': '',
    'caseTags': [],
    'caseTasks': [],
    'alertTLP': '',
    'alertTags': []
}

def mailConnect():

    ''' Connection to mailserver'''

    try:
        mbox = imaplib.IMAP4_SSL(config['imapHost'], config['imapPort'])
    except:
        typ,val = sys.exc_info()[:2]
        print("[ERROR] Cannot connect to IMAP server %s: %s" % (config['imapHost'],str(val)))
        mbox = None
        return

    try:
        typ,dat = mbox.login(config['imapUser'],config['imapPassword'])
    except:
        typ,dat = sys.exc_info()[:2]

    if typ != 'OK':
        print("[ERROR] Cannot open %s for %s@%s: %s" % (config['imapFolder'], config['imapUser'], config['imapHost'], str(dat)))
        mbox = None
        return

    if args.verbose:
        print('[INFO] Connected to IMAP server.')

    return mbox

def submitTheHive(message):

    '''Create a new case in TheHive based on the email'''

    # Decode email
    msg = email.message_from_bytes(message)
    decode = email.header.decode_header(msg['From'])[0]
    fromField = str(decode[0])
    decode = email.header.decode_header(msg['Subject'])[0]
    subjectField = str(decode[0])
    if args.verbose:
        print("[INFO] From: %s Subject: %s" % (fromField, subjectField))
    attachments = []
    body = ''
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            body = part.get_payload(decode=True).decode()
        else:
            filename = part.get_filename()
            if filename:
                print("[INFO] Found attachment: %s" % filename)
                attachments.append(filename)

    api = TheHiveApi(config['thehiveURL'], config['thehiveUser'], config['thehivePassword'], {'http': '', 'https': ''})

    if '[ALERT]' in subjectField:
        # Prepare the alert
        sourceRef = str(uuid.uuid4())[0:6]
        alert = Alert(title=subjectField.replace('[ALERT]', ''),
                      tlp = int(config['alertTLP']),
                      tags = config['alertTags'],
                      description=body,
                      type='external',
                      source=fromField,
                      sourceRef=sourceRef)

        # Create the Alert
        id = None
        response = api.create_alert(alert)
        if response.status_code == 201:
            if args.verbose:
                print('[INFO] Created alert %s' % response.json()['sourceRef'])
        else:
            print('[ERROR] Cannot create alert: %s (%s)' % (response.status_code, response.text))
            sys.exit(0)

    else:
        # Prepare the sample case
        tasks = []
        for task in config['caseTasks']:
             tasks.append(CaseTask(title=task))

        # Prepare the custom fields
        customFields = CustomFieldHelper()\
            .add_string('from', fromField)\
            .add_string('attachment', str(attachments))\
            .build()

        case = Case(title=subjectField,
                    tlp = int(config['caseTLP']), 
                    flag=False,
                    tags = config['caseTags'],
                    description=body,
                    tasks=tasks,
                    customFields=customFields)

        # Create the case
        id = None
        response = api.create_case(case)
        if response.status_code == 201:
            if args.verbose:
                print('[INFO] Created case %s' % response.json()['caseId'])
        else:
            print('[ERROR] Cannot create case: %s (%s)' % (response.status_code, response.text))
            sys.exit(0)
    return

def readMail(mbox):

    '''search for unread email in the forCIA mailbox, if mail contains attachment, decrypt it and save it in appropriate folder'''

    if not mbox:
        return

    #gpg = gnupg.GPG()
    mbox.select(config['imapFolder'])
    #typ, dat = mbox.search(None, '(ALL)')
    typ, dat = mbox.search(None, '(UNSEEN)')
    newEmails = len(dat[0].split())
    if args.verbose:
        print("[INFO] %d unread messages to process" % newEmails)
    for num in dat[0].split():
        typ, dat = mbox.fetch(num, '(RFC822)')
        if typ != 'OK':
            error(dat[-1])
        message = dat[0][1]
        submitTheHive(message)
    return newEmails

def main():
    global args
    global config

    parser = argparse.ArgumentParser(
        description = 'Process an IMAP folder to create TheHive alerts/cased.')
    parser.add_argument('-v', '--verbose',
        action = 'store_true',
        dest = 'verbose',
        help = 'verbose output',
        default = False)
    parser.add_argument('-c', '--config',
        dest = 'configFile',
        help = 'configuration file (default: /etc/imap2thehive.conf)',
        metavar = 'CONFIG')
    args = parser.parse_args()

    # Default values
    if not args.configFile:
        args.configFile = '/etc/imap2thehive.conf'
    if not args.verbose:
        args.verbose = False

    if not os.path.isfile(args.configFile):
        print('[ERROR] Configuration file %s is not readable.' % args.configFile)
        sys.exit(1);

    try:
        c = configparser.ConfigParser()
        c.read(args.configFile)
    except OSError as e:
        print('[ERROR] Cannot read config file %s: %s' % (args.configFile, e.errno))
        sys.exit(1)

    # IMAP Config
    config['imapHost']          = c.get('imap', 'host')
    config['imapPort']          = c.get('imap', 'port')
    config['imapUser']          = c.get('imap', 'user')
    config['imapPassword']      = c.get('imap', 'password')
    config['imapFolder']        = c.get('imap', 'folder')

    # TheHive Config
    config['thehiveURL']        = c.get('thehive', 'url')
    config['thehiveUser']       = c.get('thehive', 'user')
    config['thehivePassword']   = c.get('thehive', 'password')

    # New case config
    config['caseTLP']           = c.get('case', 'tlp')
    config['caseTags']          = c.get('case', 'tags').split(',')
    config['caseTasks']          = c.get('case', 'tasks').split(',')

    # New alert config
    config['alertTLP']          = c.get('alert', 'tlp')
    config['alertTags']         = c.get('alert', 'tags').split(',')


    if args.verbose:
        print('[INFO] Processing %s@%s:%s/%s' % (config['imapUser'], config['imapHost'], config['imapPort'], config['imapFolder']))

    readMail(mailConnect())
    return

if __name__ == '__main__':
	main()
	sys.exit(0)
