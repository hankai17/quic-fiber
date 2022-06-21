#!/usr/bin/python3
#coding=utf8

import matplotlib.pyplot as plt
import os, sys

cong_win_x = []
cong_win_y = []
onpacketacked_x = []
onpacketacked_y = []
onpacketlost_x = []
onpacketlost_y = []
offset_x = []
offset_y = []
send_pn_x = []
send_pn_y = []
largest_ack_x = []
largest_ack_y = []
stream_send_win_x = []
stream_send_win_y = []
infly_x = []
infly_y = []
update_send_win_x = []
update_send_win_y = []
rtt_x = []
rtt_y = []
srtt_x = []
srtt_y = []
mdev_x = []
mdev_y = []
ackdelay_x = []
ackdelay_y = []

recv_win_x = []
recv_win_y = []

filename = sys.argv[1]
role = sys.argv[2]

fd = open(filename, 'r')
for line in fd.readlines():
    if line.find('trace') == -1:
        continue
    fields = line.strip().split()
    #keyword trace
    time_ns = int(fields[9])
    time_us = time_ns / 1000
    time_ms = time_ns / 1000 / 1000
    time = time_ms

    if role == 'server':
        #offset
        if line.find('offset') != -1 and line.find('handleStreamFrame') != -1:
            offset = int(fields[12])
            offset_x.append(time)
            offset_y.append(offset)
            continue
        #winUpdate
        if line.find('getWinUpdate') != -1:
            recv_win = int(fields[12])
            recv_win_x.append(time)
            recv_win_y.append(recv_win)
            continue
    else:
        #onpacketacked
        if line.find('onPacketAcked') != -1:
            cwin = int(fields[11])
            onpacketacked_x.append(time)
            onpacketacked_y.append(cwin)
            continue
        #onpacketlost
        if line.find('onPacketLost') != -1:
            cwin = int(fields[11])
            onpacketlost_x.append(time)
            onpacketlost_y.append(cwin)
            continue
        #cong_win
        if line.find('congestion_win') != -1:
            cwin = int(fields[11])
            cong_win_x.append(time)
            cong_win_y.append(cwin)
            continue
        #offset
        if line.find('offset') != -1:
            offset = int(fields[12])
            offset_x.append(time)
            offset_y.append(offset)
            continue
        #send pn
        if line.find('send_pn') != -1:
            pn = int(fields[11])
            send_pn_x.append(time)
            send_pn_y.append(pn)
            continue
        #largest_ack
        if line.find('largest_ack') != -1:
            ack = int(fields[11])
            largest_ack_x.append(time)
            largest_ack_y.append(ack)
            continue
        #win
        if line.find('stream_send_win') != -1:
            send_win = int(fields[11])
            stream_send_win_x.append(time)
            stream_send_win_y.append(send_win)
            continue
        #infly
        if line.find('inflight') != -1:
            infly = int(fields[12])
            infly_x.append(time)
            infly_y.append(infly)
            continue
        #update_send_win
        if line.find('updateSendWin') != -1:
            update_win = int(fields[12])
            update_send_win_x.append(time)
            update_send_win_y.append(update_win)
            continue

        #rtt
        if line.find('real_rtt') != -1:
            rtt = int(fields[11])
            rtt_x.append(time)
            rtt_y.append(rtt)
            ackdelay = int(fields[13])
            ackdelay_x.append(time)
            ackdelay_y.append(ackdelay)
            srtt = int(fields[19])
            srtt_x.append(time)
            srtt_y.append(srtt)
            mdev = int(fields[21])
            mdev_x.append(time)
            mdev_y.append(mdev)

if role == 'server':
    plt.plot(offset_x, offset_y, label='offset')
    plt.scatter(recv_win_x, recv_win_y, label='recv_win')
    plt.legend()

else:
    #plt.subplot(1, 2, 1)
    #plt.plot(offset_x, offset_y, label='offset')
    #plt.plot(stream_send_win_x, stream_send_win_y, label='send_win')
    #plt.plot(infly_x, infly_y, label='inflight')
    #plt.scatter(update_send_win_x, update_send_win_y, label='update_send_win')
    #plt.legend()
    
    #plt.subplot(2, 2, 2)
    #plt.scatter(send_pn_x, send_pn_y, label='send_pn')
    #plt.scatter(largest_ack_x, largest_ack_y, label='ack')
    #plt.legend()

    plt.subplot(1, 1, 1)
    plt.scatter(onpacketacked_x, onpacketacked_y, label='onpacketacked', color='g')
    plt.scatter(onpacketlost_x, onpacketlost_y, label='onpacketlost', color='r')
    plt.plot(cong_win_x, cong_win_y, label='congestion_win', color='b')
    plt.legend()
    
    #plt.subplot(1, 2, 2)
    #plt.plot(rtt_x, rtt_y, label='rtt line')
    #plt.plot(srtt_x, srtt_y, label='srtt line')
    #plt.plot(mdev_x, mdev_y, label='mdev line')
    #plt.plot(ackdelay_x, ackdelay_y, label='ack_delay line')
    #plt.legend()

plt.show()

