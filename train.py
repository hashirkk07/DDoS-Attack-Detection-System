#!/usr/bin/env python
# coding: utf-8

# In[42]:


import os
from scapy.all import *
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

import pickle
import sklearn.ensemble as ske
from sklearn import tree, linear_model
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import SelectFromModel

from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.datasets import make_classification

from sklearn.feature_selection import SelectFromModel


# In[60]:


def SaveData():
    
    Ddos_attack_files = []
    benign_file_path = []
    count = 0
    
    for i in os.listdir('/media/amit/New/Ddos_Detection_Dataset/Ddos_benign'):
        if(i[-1] != 't'):
            for j in os.listdir('/media/amit/New/Ddos_Detection_Dataset/Ddos_benign' + '/' + i):
                benign_file_path.append('/media/amit/New/Ddos_Detection_Dataset/Ddos_benign' + '/' + i + '/' + j)
                
    for i in os.listdir('/media/amit/New/Ddos_Detection_Dataset/Ddos_Attack_data/'):
        Ddos_attack_files.append('/media/amit/New/Ddos_Detection_Dataset/Ddos_Attack_data/' + i)

    for i in os.listdir('/home/amit/Downloads/Ddos_Detection_Dataset_Part2/Ddos_benign'):
        benign_file_path.append('/home/amit/Downloads/Ddos_Detection_Dataset_Part2/Ddos_benign' + '/' + i )
        
    for i in os.listdir('/media/amit/New/Ddos_Detection_Dataset/Ddos_Attack_data/'):
        Ddos_attack_files.append('/media/amit/New/Ddos_Detection_Dataset/Ddos_Attack_data/' + i)
            
    X = []
    Y = []
    
    k = 0
    for i in Ddos_attack_files:
        packet_count = 0
        feature = []
        feature.append(0)
        feature.append(0)
        #feature.append(0)
        time_intervel_count = 0  #  less than 10^-4 
        src_ip = set()
        dst_ip = set()
        src_port = set()
        dst_port = set()
        packet_len = []
        prev_time = 0
        for pkt_data, metadata in  RawPcapReader(i):
            packet_count += 1
            packet = Ether(pkt_data)

            if(packet_count == 1):
                prev_time = packet.time
            else:
                time_intervel_count += ((packet.time - prev_time) < 0.0003)
                prev_time = packet.time

            if(packet.haslayer(UDP)):
                feature[0] += 1
                src_port.add(packet.sport)
                dst_port.add(packet.dport)

            elif(packet.haslayer(TCP)):
                feature[1] += 1
                src_port.add(packet.sport)
                dst_port.add(packet.dport)

            elif packet.haslayer(IP):
                feature[0] += (packet.proto == 17)
                feature[1] += (packet.proto == 6)

            if(packet.haslayer(IP)):
                src_ip.add(packet[1].src)
                dst_ip.add(packet[1].dst)
                packet_len.append(packet.len)





        feature[0] = feature[0]*100/packet_count
        feature[1] = feature[1]*100/packet_count

        feature.append(min(packet_len))
        feature.append(max(packet_len))

        if(len(packet_len) != 0):
            feature.append(sum(packet_len)/len(packet_len))
        else:
            feature.append(0)
        feature.append(len(src_ip))
        feature.append(len(dst_ip))
        feature.append(len(src_port))
        feature.append(len(dst_port))
        feature.append(time_intervel_count*100/packet_count)
        feature.append(packet_count)


        X.append(feature)
        Y.append(1)
        k += 1
        
        
        k = 0
    for i in benign_file_path:
        packet_count = 0
        feature = []
        feature.append(0)
        feature.append(0)
        #feature.append(0)
        time_intervel_count = 0  #  less than 10^-4 
        src_ip = set()
        dst_ip = set()
        src_port = set()
        dst_port = set()
        packet_len = []
        prev_time = 0
        for pkt_data, metadata in  RawPcapReader(i):
            packet_count += 1
            packet = Ether(pkt_data)

            if(packet_count == 1):
                prev_time = packet.time
            else:
                time_intervel_count += ((packet.time - prev_time) < 0.0003)
                prev_time = packet.time

            if(packet.haslayer(UDP)):
            	feature[0] += 1
                src_port.add(packet.sport)
                dst_port.add(packet.dport)

            elif(packet.haslayer(TCP)):
                feature[1] += 1
                src_port.add(packet.sport)
                dst_port.add(packet.dport)

            elif packet.haslayer(IP):
                feature[0] += (packet.proto == 17)
                feature[1] += (packet.proto == 6)

            if(packet.haslayer(IP)):
                src_ip.add(packet[1].src)
                dst_ip.add(packet[1].dst)
                packet_len.append(packet.len)





        feature[0] = feature[0]*100/packet_count
        feature[1] = feature[1]*100/packet_count

        feature.append(min(packet_len))
        feature.append(max(packet_len))

        if(len(packet_len) != 0):
            feature.append(sum(packet_len)/len(packet_len))
        else:
            feature.append(0)
        feature.append(len(src_ip))
        feature.append(len(dst_ip))
        feature.append(len(src_port))
        feature.append(len(dst_port))
        feature.append(time_intervel_count*100/packet_count)
        feature.append(packet_count)


        X.append(feature)
        Y.append(0)
        k += 1
       
        
    header = ['udp_percent' , 'tcp_percent' , 'packet_len_min' , 'packet_len_max' , 'packet_len_mean' , 'no_of_different_source_ip' , 'no_of_differnet_destination_ip' , 'no_of_differnet_source_port', 'no_of_different_destination_port' , 'time_intervel_between_packet' , 'no_of_packet']

    X1 = pd.DataFrame(X, columns = header)
    Y1 = pd.DataFrame(Y, columns = ['Ddos_attack'])
    
    final = pd.concat([X1,Y1] , axis = 1)
    (final).to_csv('/home/amit/Videos/hackthon2/data.csv', index=False)
    


        


# In[61]:


def SaveModal():
    
    df = pd.read_csv('/home/amit/Videos/hackthon2/data.csv')
    X = df.iloc[ : , :11]
    Y = df.iloc[ : , 11:]
    
    clf = ske.RandomForestClassifier(n_estimators=100)
    clf.fit(X, Y.values.ravel())
    
    filename = '/home/amit/Videos/hackthon2/model.sav'
    pickle.dump(clf, open(filename, 'wb'))
    
    


# In[62]:


if __name__ == '__main__':
    
    SaveData()
    SaveModal()


