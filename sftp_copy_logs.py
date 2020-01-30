# This script copies the log files modified or generated between the time interval given by 
# command line argument.
#
# Change the APPLICATION LOGS path below to use for new path.
#

#!/usr/bin/python
import sys
import getpass
import commands
import fcntl
import errno
import paramiko
import datetime
import logging
import logging.handlers
import time
import os
import subprocess
import shlex
import urllib
import time
import getopt
sys.path.append("/usr/local/ipcs/icu/pylib")
sys.path.append("/usr/local/ipcs/bin")

SFTPDetailLogFile = os.getcwd()+ 'sftp_copy.log'

## APPLICATION LOGS: 
ssyndi_logPath="/archive/log/ipcs/ss/logfiles/elog/SSYNDI/"
sysmon_logPath="/archive/log/ipcs/ss/logfiles/elog/SYSMON/"
turnServer_logPath="/archive/log/turnserver/"
nginx_logPath="/archive/log/nginx/"
scrubber_logPath="/archive/log/scrubber/"
tracesbc_logPath="/archive/log/tracesbc/tracesbc_sip/"
traceppm_logPath="/archive/log/tracesbc/tracesbc_ppm/"
pcap_logPath="/archive/pcapfiles/IPCS2/"

def initLogger():
        print ("Start Logger init done\n")
        global rollver
        rollver = logging.handlers.RotatingFileHandler(SFTPDetailLogFile,backupCount=5)
        if os.path.exists(SFTPDetailLogFile):
            rollver.doRollover()
        logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M',
                    filename=SFTPDetailLogFile,
                    filemode='w')

        logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
        rootLogger = logging.getLogger()
        logPath, fileName = os.path.split(SFTPDetailLogFile)

        fileHandler = logging.FileHandler("%s/%s" % (logPath, fileName))
        fileHandler.setFormatter(logFormatter)
        rootLogger.addHandler(fileHandler)
        print ("Logger init done\n")

#################################################################################
# Function to create log directory structure on remote server.
#################################################################################
def create_remote_dir_structure(sftpConn, remotepath):
        ''' This creates recuersive directory structure at remote server. 
            Make sure to have trailing '/' at the end pf remotepath. '''
        try:
           print ("Start create_remote_dir_structure\n")
           parts = remotepath.split('/')
           for n in range(3, len(parts)):
               path = '/'.join(parts[:n])
               try:
                   sftpConn.stat(path)
               except:
                   sftpConn.mkdir(path)
           print ("create_remote_dir_structure\n")
        except Exception,e:
           print('*** Exception create_remote_dir_structure: %s\n' %(e))

#################################################################################
# This function identifies the Application log files to be sent to remote log server.
#################################################################################
def get_app_logfiles(remoteDirPath, fromtime, totime):
    try:
       print ("Start get_app_logfiles\n")
       ssyndi_files = []		## 1
       sysmon_files = []		## 2
       turnserver_files = []		## 3
       nginx_files = []			## 4
       scrubber_files = []		## 5
       tracesbc_files = []		## 6
       traceppm_files = []		## 7
       pcap_files = []			## 8

       global logFilesArray
       global logFilesPathArray
       global logRemotePathArray

       logFilesArray  = [ ssyndi_files, 	\
                          sysmon_files,  	\
                          turnserver_files, 	\
                          nginx_files,   	\
                          scrubber_files,	\
                          tracesbc_files, 	\
                          traceppm_files, 	\
                          pcap_files ]

       logFilesPathArray = [ssyndi_logPath, 	\
	       	            sysmon_logPath,	\
			    turnServer_logPath,	\
		    	    nginx_logPath, 	\
		 	    scrubber_logPath, 	\
			    tracesbc_logPath, 	\
			    traceppm_logPath, 	\
			    pcap_logPath] 

       logRemotePathArray = [remoteDirPath+ssyndi_logPath, \
			     remoteDirPath+sysmon_logPath, \
	   		     remoteDirPath+turnServer_logPath, \
			     remoteDirPath+nginx_logPath,    \
			     remoteDirPath+scrubber_logPath, \
		  	     remoteDirPath+tracesbc_logPath, \
		  	     remoteDirPath+traceppm_logPath, \
			     remoteDirPath+pcap_logPath]

       ## Identify the logs files to be moved to remote server. 
       i = -1
       for path in logFilesPathArray:
          i=i+1
          print('get_app_logfiles logFilesPathArray:%s' %(logFilesPathArray[i]))
          for name in os.listdir(logFilesPathArray[i]):
              if os.path.isfile(os.path.join(logFilesPathArray[i], name)):
                   mtime= os.path.getmtime(os.path.join(logFilesPathArray[i], name))
                   filetime = datetime.datetime.fromtimestamp(mtime)
                   print('get_app_logfiles file: [%s]:[%s]' %(name, time.ctime(mtime)))
                   if (fromtime < filetime < totime):
                       print('get_app_logfiles file: %s IS IN RANGE'%(name))
                       logFilesArray[i].append(name)
                   else:
                       print('get_app_logfiles file: %s IS NOT IN RANGE'%(name))
           # end of else
          print('get_app_logfiles files present are: [%s]' %(logFilesArray[i]))
       ## End of For Loop
       print ("get_app_logfiles\n")
    except Exception,e:
        logging.critical('***Exception get_app_logfiles: %s' %(e))


#################################################################################
# Application log push to remote log server.
#################################################################################
def app_log_push_sftp(remoteIP, remotePort, userName, Passwd, remoteDirPath, fromtime, totime):
    try:
       print ("Start app_log_push_sftp\n")
       alarm = False

       # Get the logfiles to transfer.
       get_app_logfiles(remoteDirPath, fromtime, totime)

       try:
          t = paramiko.Transport((remoteIP,remotePort))
          t.connect(username= userName, password=Passwd)
          sftp = paramiko.SFTPClient.from_transport(t)
          i=-1
          ## THIS LOOP IS FOR EACH TYPE OF LOG LIKE: SSYNDI LOGS.
          for logFiles in logFilesArray:
            i=i+1
            # CREATE FOLDERS IN REMOTE SERVER FOR RESPECTIVE LOGFILES.
            create_remote_dir_structure(sftp, logRemotePathArray[i])
            # THIS LOOP COPIES ALL LOG FILES FROM LOCAL SSYNDI LOGS FOLDER TO REMOTE SERVER
            for f in logFiles:
              try:
                 localFilePath = logFilesPathArray[i] + '/' + f
                 print('app_log push %s file to Remote SFTP log server' %localFilePath)
                 ret = sftp.put(localFilePath, "%s/%s" %(logRemotePathArray[i], f))
                 print('app_log push return Status = %s' %ret)
              except Exception,e:
                  alarm = True
                  logging.critical('*** Caught exception: %s' %(e))

       except Exception,e:
           alarm = True
           logging.critical('*** Caught exception: %s' %(e))

       t.close()
       sftp.close()
       print ("app_log_push_sftp\n")
    except Exception,e:
        logging.critical('*** Exception app_log_push_sftp: %s' %(e))

#################################################################################
# Function main
#################################################################################
def main(argv):
    try:
       print ("Start Main...\n")
       # Reduce the process priority
       os.nice(19)

       initLogger()
       print('Transferring Application Log Files to Remote Server.')
       # Flag to disable debug logs
       disableDebug=False

       remoteIP = '192.168.0.10'
       remotePort = '22'
       userName = 'ipcs'
       Passwd = 'SIPera_123'
       remoteDirPath = '/tmp/'
       ftime='2018-11-02 08:15:27.0'
       ttime='2018-11-04 04:52:27.0'

       try:
          options, remainder = getopt.getopt(sys.argv[1:], 's:o:u:p:l:f:t:', ['server',
                                                         'port',
                                                         'user',
                                                         'password',
                                                         'location',
                                                         'fromtime',
                                                         'totime',
                                                         ])
          for opt, arg in options:
              if opt in ('-s', '--server'):
                  remoteIP = arg
              elif opt in ('-o', '--port'):
                  remotePort = int(arg)
              elif opt in ('-u', '--user'):
                  userName = arg
              elif opt in ('-p', '--password'):
                  Passwd = arg
              elif opt in ('-l', '--location'):
                  remoteDirPath =  arg
              elif opt in ('-f', '--fromtime'):
                  ftime =  arg
              elif opt in ('-t', '--totime'):
                  ttime = arg
              else:
                  print('USAGE: \n')
                  print("\t./arguments.py -s 1.1.1.1 -o 22 -u ipcs -p SIPera_123 -l /tmp/ -f \'2019-11-02 08:15:27.0\' -t \'2019-11-02 08:30:27.0\'")
       except getopt.GetoptError:
          print('USAGE: \n')
          print("\t./arguments.py -s 1.1.1.1 -o 22 -u ipcs -p SIPera_123 -l /tmp/ -f \'2019-11-02 08:15:27.0\' -t \'2019-11-02 08:30:27.0\'")
          logging.critical('*** Exception Argument Error:')
          sys.exit(2)


       print('server:[%s] port:[%s] user:[%s] passwd:[%s]\n' %(remoteIP, remotePort, userName, Passwd))
       print('remotePath:[%s] from time:[%s] to time:[%s]\n' %(remoteDirPath, ftime, ttime))

       fromtime=datetime.datetime.strptime(ftime, '%Y-%m-%d %H:%M:%S.%f')
       totime=datetime.datetime.strptime(ttime, '%Y-%m-%d %H:%M:%S.%f')
       nowtime = datetime.datetime.now()

       ## GUI should also check below condition.
       if fromtime > totime:
          print('from-time is more than to-time; Returning...')
          sys.exit(0)
       
       duration = totime - nowtime
       print('duration=%d' %(duration.total_seconds()))
       if (duration.total_seconds() > 0):
          print('totime is in future; Sleeping for %d seconds' %(duration.total_seconds()))
          time.sleep(duration.total_seconds())

       print('Transferring logs to remote server.')
       app_log_push_sftp(remoteIP, remotePort, userName, Passwd, remoteDirPath, fromtime, totime)
       print ("Main...\n")
           
    except ImportError, e:
       print("[Main]: Error %s" % e)
       sys.exit(0)
# End of Main
#################################################################################
# Function main
#################################################################################
if __name__ == "__main__":
    main(sys.argv[1:])
