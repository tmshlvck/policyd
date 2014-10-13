#!/usr/bin/python
#
# policyd - Postfix Policy Daemon
# (C) 2014 Tomas Hlavacek (tmshlvck@gmail.com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import socket
import threading
import logging
import traceback
import re
import time


# Constants

RATE_PERIOD=300
MAX_DEFAULT_ADDRESS_RATE=200
MAX_DEFAULT_SASL_RATE=100

BLOCK_PERIOD=3600

WHITELIST_ADDRESS=['127.0.0.1',]
WHITELIST_SASL_USER=[]

BULK_ADDRESS_MAP={} # {'192.168.1.5':500, ...}
BULK_SASL_MAP={} # {'bot@something.com':100, ...}

WARN_ONLY=True # pass emails and generate warnings instead of blocking

DEFER_MESSAGE='Message not accepted. Contact administrators for explanation.'

BLOCK_REPORT='/tmp/policyd-block.txt'

LOGFILE='/tmp/policyd.log'
LOGLEVEL=logging.DEBUG
#LOGLEVEL=logging.INFO
LOGFORMAT='%(asctime)-15s %(module)s: %(message)s'




# Globals

log=None
address_cache={}
sasl_cache={}
cache_lock=threading.Lock()
address_block={}
sasl_block={}


# Functions

def address_block_hook(address):
    with open(BLOCK_REPORT,'a') as f:
        f.write(time.strftime("%d %b %Y %H:%M:%S", time.localtime())+" Address "+address+" blocked.\n")

def sasl_block_hook(username):
    with open(BLOCK_REPORT,'a') as f:
        f.write(time.strftime("%d %b %Y %H:%M:%S", time.localtime())+" SASL username "+username+" blocked.\n")


def cleanup_thread():
    global log
    global address_cache
    global sasl_cache
    global cache_lock
    global address_block
    global sasl_block

    def debug_ds():
        with cache_lock:
            log.debug("cleanup: address_cache="+str(address_cache))
            log.debug("cleanup: sasl_cache="+str(sasl_cache))
            log.debug("cleanup: address_block="+str(address_block))
            log.debug("cleanup: sasl_block="+str(sasl_block))        

    def clean_cache(cache):
        r=0
        for k in cache.keys():
            cache[k]=cleanup_series(cache[k])
            if len(cache[k]) == 0:
                del cache[k]
                r+=1
        return r

    def unblock(block):
        r=0
        limit=time.time()-BLOCK_PERIOD
        for k in block.keys():
            if block[k] < limit:
                del block[k]
                r+=1
        return r

    unblock_sched=BLOCK_PERIOD
    while True:
        time.sleep(RATE_PERIOD+1)
        log.debug("Cleanup thread wake up.")
        debug_ds()
        with cache_lock:
            acr=clean_cache(address_cache)
        with cache_lock:
            scr=clean_cache(sasl_cache)
        log.info("Cleanup complete. Removed AC:"+str(acr)+" SC:"+str(scr))

        if unblock_sched < 0:
            with cache_lock:
                abr=unblock(address_block)
            with cache_lock:
                sbr=unblock(sasl_block)
            log.info("Unblock complete. Removed AC:"+str(abr)+" SC:"+str(sbr))

            unblock_sched=BLOCK_PERIOD
        else:
            unblock_sched-=(RATE_PERIOD+2)


def cache_add(eid,count,cache):
    global cache_lock

    t=time.time()

    with cache_lock:
        if not eid in cache:
            cache[eid]=[]
        cache[eid]=cache[eid]+([t,]*count)
            

def cleanup_series(series):
    lim=time.time()-RATE_PERIOD
    return [t for t in series if t>lim]

def rate_check(eid,cache,limit):
    global cache_lock

    with cache_lock:
        if eid in cache:
            cache[eid]=cleanup_series(cache[eid])
            if len(cache[eid]) > limit:
                return False
        return True


def get_sasl_limit(sasl_username):
    if sasl_username in BULK_SASL_MAP:
        return BULK_SASL_MAP[sasl_username]
    else:
        return MAX_DEFAULT_SASL_RATE

def get_address_limit(address):
    if address in BULK_ADDRESS_MAP:
        return BULK_ADDRESS_MAP[address]
    else:
        return MAX_DEFAULT_ADDRESS_RATE


# Test message
# message: parsed message attribute=value dictionary
# return True = allow the message (send dunno), False = defer
def check_message(message,tid):
    global log
    global address_cache
    global sasl_cache
    global address_block
    global sasl_block

    if (not 'client_address' in message) or (not 'queue_id' in message) or (not 'sender' in message) or (not 'recipient' in message):
        log.error('Missing mandatry attributes in message: '+str(message))
        return False

    qid=message['queue_id']
    claddr=message['client_address']
    sender=message['sender']
    rcpt_count=int(message['recipient_count'])
    sasl_username=message['sasl_username']

    ll="tid="+str(tid)+" checking QID="+qid+" claddr="+claddr+" sender="+sender+" rcpt_count="+str(rcpt_count)

    if sasl_username:
        ll+=" sasl_username="+sasl_username

    log.info(ll)

    if claddr in WHITELIST_ADDRESS:
        log.info("tid="+str(tid)+" QID="+qid+" whitelisted. Accept.")
        return True

    with cache_lock:
        if claddr in address_block:
            log.info("tid="+str(tid)+" QID="+qid+" is address blocked. Defer.")
            return False

    cache_add(claddr,rcpt_count,address_cache)
    if not rate_check(claddr,address_cache,get_address_limit(claddr)):
        log.info("tid="+str(tid)+" QID="+qid+" failed address rate check. Defer and block.")
        with cache_lock:
            address_block[claddr]=time.time()
        address_block_hook(claddr)
        return False

    if sasl_username:
        if claddr in WHITELIST_SASL_USER:
            log.info("tid="+str(tid)+" QID="+qid+" whitelisted. Accept.")
            return True

        with cache_lock:
            if sasl_username in sasl_block:
                log.info("tid="+str(tid)+" QID="+qid+" is SASL blocked. Defer.")
                return False

        cache_add(sasl_username,rcpt_count,sasl_cache)
        if not rate_check(sasl_username,sasl_cache,get_sasl_limit(sasl_username)):
            log.info("tid="+str(tid)+" QID="+qid+" failed SASL rate check. Defer and block.")
            with cache_lock:
                sasl_block[sasl_username]=time.time()
            sasl_block_hook(sasl_username)
            return False

    log.info("tid="+str(tid)+" QID="+qid+" passed. Accept.")
    return True


# Test message based on header lines
# ml: lines of message definition [str,str,...]
# tid: thread ID (int)
# return True = allow the message (send dunno), False = defer
def process_message(ml,tid):
    global log

#    log.debug("Processing message: "+str(ml))

    rml = re.compile('^([^=]+)=(.*)$')

    message={}
    for l in ml:
        m=rml.match(l)
        if m:
            message[m.group(1)]=m.group(2)
        else:
            log.warn('tid='+str(tid)+' Line match error: '+l)

    return check_message(message,tid)


def connection_thread(sock,addr,tid):
    global log

    try:
        f=sock.makefile()
        
        ml=[]
        while True:
            l=f.readline()
            if l:
                l=l.strip()

                if l != '': # add line to the message
                    ml.append(l)
                else: # end of message headers
#                    log.debug("Client tid="+str(tid)+" addr="+str(addr)+" dispatched a message.")

                    if process_message(ml,tid) or WARN_ONLY:
                        f.write("action=dunno\n\n")
                    else:
                        f.write("action=defer_if_permit "+DEFER_MESSAGE+"\n\n")
                    ml=[]

                    f.flush()

            else:          # disconnect/EOF
                log.debug("Client tid="+str(tid)+" addr="+str(addr)+" disconnect.")
                break
    except:
        log.error(traceback.format_exc())
    finally:
        f.close()
        sock.close()
        log.debug("Closed connection to client tid="+str(tid)+" addr="+str(addr)+" .")



def start_daemon():
    global log

    t=threading.Thread(target=cleanup_thread)
    t.daemon=True
    t.start()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('localhost', 5011))
    s.listen(1)
    log.debug("Listen socket open.")

    tid=0
    try:
        while True:
            cs,addr = s.accept()
            log.debug("New connection accepted from "+str(addr)+" tid="+str(tid)+".")
            t=threading.Thread(target=connection_thread,args=(cs,addr,tid))
            t.daemon=True
            t.start()
            tid+=1
    except KeyboardInterrupt:
        pass
    except:
        log.error(traceback.format_exc())
    finally:
        s.close()
        


def main():
    logging.basicConfig(level=LOGLEVEL,format=LOGFORMAT,filename=LOGFILE)
    global log
    log = logging.getLogger("policyd")

    start_daemon()


if __name__=='__main__':
    main()
