# -*- coding: utf-8 -*-
"""
 Copyright © 2012 TechSure<http://www.techsure.com.cn/>
"""


import codecs
import re
import time
import traceback
import os
import sys
import subprocess

from lib import plugin, util
from collections import namedtuple, defaultdict


try:
    import urllib2
except ImportError:
    import urllib.request as urllib2

import logging
logger = logging.getLogger()


class ContainerMonitorPlugin(plugin.plugin):

    last_val = defaultdict(lambda: None)

    def __init__(self, jobConf):
        plugin.plugin.__init__(self, jobConf)

    #容器CPU使用率算法
    def getStat(self, metricList, collectTime):
        stealCpu, guestCpu = 0, 0
        file_proc_stat = '/proc/stat'
        file_cpuacct = '/sys/fs/cgroup/cpuacct/cpuacct.usage'

        if os.path.exists(file_proc_stat) and os.path.exists(file_cpuacct):
            f_proc = open(file_proc_stat, 'r')
            f_cpuacct = open(file_cpuacct, 'r')

            try:
                contentArray = f_proc.readlines()

                cpuLine = contentArray[0]
                kv = cpuLine.strip().split()

                userCpu = int(kv[1])
                niceCpu = int(kv[2])
                sysCpu  = int(kv[3])
                idleCpu = int(kv[4])
                iowaitCpu = int(kv[5])
                hardIRQ = int(kv[6])
                softIRQ = int(kv[7])

                if len(kv) >= 10:
                    stealCpu = int(kv[8])
                    guestCpu = int(kv[9])

                totalCpuTime = int(
                    userCpu + niceCpu + sysCpu + idleCpu + iowaitCpu + hardIRQ + softIRQ + stealCpu + guestCpu) * 10 ** 7

                containerCpuTime = int(f_cpuacct.readline().strip())

            finally:
                f_proc.close()
                f_cpuacct.close()

            cmd = 'cat /sys/fs/cgroup/cpuacct/cpuacct.usage_percpu |wc -w'
            p = os.popen(cmd)

            cmd = "cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us|awk '{print $1}'"
            p_ = os.popen(cmd)

            try:
                res = p.read()
                cpuCores = res.strip()
                cfs_quota_us = float(p_.read().strip())/100000

                metric = self.getMetricValue('CPU.CpuCores', '-', collectTime, str(cpuCores))
                metricList.append(metric)

                if self.last_val['totalCpuTime'] is not None \
                        and self.last_val['containerCpuTime'] is not None:
                    containerCpuTime_last = self.last_val['containerCpuTime']
                    totalCpuTime_last = self.last_val['totalCpuTime']

                    CpuUsagePercent = round((float(containerCpuTime) - float(containerCpuTime_last)) / (
                        float(totalCpuTime) - float(totalCpuTime_last)) * int(cpuCores)/cfs_quota_us, 2) * 100

                    metric = self.getMetricValue('CPU.CpuUsagePercent', '-', collectTime,
                                                 str(CpuUsagePercent))
                    metricList.append(metric)

                # refresh current value into last
                self.last_val.update({'totalCpuTime': totalCpuTime,
                                      'containerCpuTime': containerCpuTime})
            finally:
                p.close()

    #容器MEM 使用率算法
    def getContainerMem(self,metricList,collectTime):
        mem_limit, mem_usage = 0, 0
        fileinfo = '/sys/fs/cgroup/memory/memory.limit_in_bytes'

        if os.path.exists(fileinfo):
            f = open(fileinfo, 'r')
            try:
                mem_limit = int(f.readline().strip())
                metric = self.getMetricValue('Memory.limit_in_bytes', '-', collectTime, str(mem_limit))#Unit : Byte
                metricList.append(metric)
            finally:
                f.close()

        fileinfo = '/sys/fs/cgroup/memory/memory.stat'

        if os.path.exists(fileinfo):
            f = open(fileinfo, 'r')
            try:
                for line in f.readlines():
                    if line.find('rss') >= 0:
                        item = line.split(' ')
                        if item[0] == 'rss':
                            mem_usage = int(item[1].strip())
                            break

                metric = self.getMetricValue('Memory.usage_in_bytes', '-', collectTime, str(mem_usage))#Unit : Byte
                metricList.append(metric)
            finally:
                f.close()

        if mem_limit and mem_usage:
            metric = self.getMetricValue('Memory.usage_percent', '-', collectTime, round(float(mem_usage) / mem_limit,4) * 100)
            metricList.append(metric)


    #网络流量算法
    def getNetworkTraffic(self, metricList,collectTime):
        netCard='eth1'
        fileinfo = '/proc/net/dev'
        if os.path.exists(fileinfo):
            f = open(fileinfo, 'r')
            try:
                lines = f.readlines()
                columnLine = lines[1]
                _, receiveCols, transmitCols = columnLine.split("|")
                receiveCols = map(lambda a: "recv_" + a, receiveCols.split())
                transmitCols = map(lambda a: "trans_" + a, transmitCols.split())

                cols = receiveCols + transmitCols

                faces = {}

                for line in lines[2:]:
                    if line.find(":") < 0:
                        continue
                    face, data = line.strip().split(":")
                    faceData = dict(zip(cols, data.split()))
                    faces[face] = faceData

                recv_bytes = faces[netCard]['recv_bytes']
                trans_bytes = faces[netCard]['trans_bytes']
                current_time = int(time.time())

                if self.last_val['network_time']:

                    timeInterval = current_time - self.last_val['network_time']

                    if self.last_val['recv_bytes'] is not None:
                        RXDiff = round((float(recv_bytes) - float(self.last_val['recv_bytes'])) / timeInterval / 1024, 2)
                        metric = self.getMetricValue('Network.RXDiff', netCard, collectTime, str(RXDiff))
                        metricList.append(metric)

                    if self.last_val['trans_bytes'] is not None:
                        TXDiff = round((float(trans_bytes) - float(self.last_val['trans_bytes'])) / timeInterval / 1024, 2)
                        metric = self.getMetricValue('Network.TXDiff', netCard, collectTime, str(TXDiff))
                        metricList.append(metric)

                self.last_val.update({'network_time': current_time,
                                      'recv_bytes': recv_bytes,
                                      'trans_bytes': trans_bytes})
            finally:
                f.close()

    def getblkio(self, metricList, collectTime):

        file = '/sys/fs/cgroup/blkio/blkio.throttle.io_service_bytes'
        total_now = defaultdict(lambda: 0)
        with open(file) as fp:
            for line in fp.readlines():
                if line.find('Read') >= 0 or line.find('Write') >= 0:
                    item = line.split(' ')
                    total_now[item[1]] += int(item[2])

        current_time = int(time.time())

        try:
            if self.last_val['blkio_time']:

                timeInterval = current_time - self.last_val['blkio_time']

                if self.last_val['blkread'] is not None:
                    total_last = self.last_val['blkread']
                    metric = self.getMetricValue('Blkio.Read', '-', collectTime, (total_now['Read']-total_last)/2)
                    metricList.append(metric)
                if self.last_val['blkwrite'] is not None:
                    total_last = self.last_val['blkwrite']
                    metric = self.getMetricValue('Blkio.Write', '-', collectTime, (total_now['Write']-total_last)/2)
                    metricList.append(metric)

            self.last_val.update({'blkio_time': current_time,
                                  'blkread': total_now['Read'],
                                  'blkwrite': total_now['Write']
                                  })

        except Exception, e:
            logger.error(e)

    def getSsBacklog(self, metricList, collectTime):
        try:
            cmd_str = "ss -lnt |awk '{if (NR>2){print $2, $3, $4}}'"
            p = subprocess.Popen(cmd_str, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            p.wait()
            out = p.stdout.read().strip()
            if not out:
                return

            # ss_dict = dict()
            for ss_li in out.split("\n"):
                item = ss_li.split(" ")
                if len(item) < 3:
                    continue

                if item[-1].split(":")[-2]:
                    k = "ss_" + str(item[-1].split(":")[-2]) + ":" + str(item[-1].split(":")[-1])
                else:
                    k = "ss_" + str(item[-1].split(":")[-1])

                v = float(item[0]) / float(item[1])
                # ss_dict[k] = v

                metric = self.getMetricValue('backlog.accept', k, collectTime, v)  # Unit : Byte
                metricList.append(metric)

            # print ss_dict
        except Exception, e:
            logger.error(e)

    def getNetstat(self, metricList, collectTime):

        try:

            cmd_str = "netstat -s |grep 'times the listen queue of a socket overflowed'|awk '{print $1}'"
            p = subprocess.Popen(cmd_str, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            p.wait()
            out = p.stdout.read().strip()
            socketOverflowed = 0
            if out:
                socketOverflowed = int(out)

            metric = self.getMetricValue('netstat.Overflowed', '-', collectTime, socketOverflowed)  # Unit : Byte
            metricList.append(metric)

            # print ss_dict
        except Exception, e:
            logger.error(e)

        try:
            cmd_str = "netstat -s |grep 'SYN to LISTEN sockets ignored'|awk '{print $1}'"
            p = subprocess.Popen(cmd_str, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            p.wait()
            out = p.stdout.read().strip()
            socketIgnored = 0
            if out:
                socketIgnored = int(out)

            metric = self.getMetricValue('netstat.ignored', '-', collectTime, socketIgnored)  # Unit : Byte
            metricList.append(metric)

            # print ss_dict
        except Exception, e:
            logger.error(e)

    def collectData(self):
        try:
            startTime=self.getCurTime()
            self.intStatus()
            data = {}
            data["jobId"] = str(self.jobId)
            metricList = []
            try:
                self.getStat(metricList, startTime)
            except:
                logger.error(self.logHeader + traceback.format_exc())

            try:
                self.getContainerMem(metricList, startTime)
            except:
                logger.error(self.logHeader + traceback.format_exc())

            try:
                self.getNetworkTraffic(metricList, startTime)
            except:
                logger.error(self.logHeader + traceback.format_exc())

            try:
                self.getblkio(metricList, startTime)
            except:
                logger.error(self.logHeader + traceback.format_exc())

            try:
                self.getSsBacklog(metricList, startTime)
            except:
                logger.error(self.logHeader + traceback.format_exc())

            try:
                self.getNetstat(metricList, startTime)
            except:
                logger.error(self.logHeader + traceback.format_exc())

            endTime=long(self.getCurTime())
            metricResponse=self.getMetricValue("Status.ResponseTime","-",startTime,str(endTime-long(startTime)))
            metricList.append(metricResponse)

            data["data"]=metricList

        except:
            logger.error(self.logHeader + traceback.format_exc())
            self.setError(self.logHeader + traceback.format_exc())
            metricAvail=self.getMetricValue("Status.Availability","-",startTime,traceback.format_exc())
            metricList.append(metricAvail)
            data["data"] = metricList

        self.addMonData(data)

if __name__ == "__main__":
    jobConf = {"jobId":1412,"pluginClass":"LinuxMonitorPlugin","interval":5,"runConf":[{"File":"/var/log/message"},{"Process":"java"}]}
    plugin = LinuxMonitorPlugin(jobConf)
    plugin.start()

