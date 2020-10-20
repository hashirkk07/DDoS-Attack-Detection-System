#!/usr/bin/env python
# coding: utf-8

# In[49]:


import os
from scapy.all import *

import pandas as pd
import numpy as np
import pickle


# In[50]:


def matrix(path):
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
    for pkt_data, metadata in  RawPcapReader(path):
        packet_count += 1
        packet = Ether(pkt_data)
        
        if(packet_count == 1):
            prev_time = packet.time
        else:
            time_intervel_count += ((packet.time - prev_time) < 0.0003)
            prev_time = packet.time
            
        if(packet.haslayer(UDP)):
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
    
    
    return(feature)
    


# In[54]:


def writeTxt(path):
    file_object = open('output.txt', 'a')
    file_object.write("output  :  DDos_attack \n" )
    file_object.close()
    
    prev_time = 0
    curr_time = 0
    
    pkt_count = 1
    total_time = 0
    prev_dst_ip = 0
    prev_src_ip = 0
    

    melicious_ip = set()
    k = 0
    for pkt_data, metadata in  RawPcapReader(path):
        
        k += 1
        packet = Ether(pkt_data)
        
        if(pkt_count == 1):
            prev_time = packet.time
            curr_time = packet.time
            if(packet.haslayer(IP)):
                prev_dst_ip = packet[1].dst
                prev_src_ip = packet[1].src
            pkt_count += 1
        else:
            
            
            if(packet.haslayer(IP)):
                curr_time = packet.time
                curr_src_ip = packet[1].src
                curr_dst_ip = packet[1].dst
                if(curr_src_ip == prev_src_ip and curr_dst_ip == prev_dst_ip):
                    pkt_count += 1
                    total_time += curr_time - prev_time
                   
                    
                else:
                    mean_time = total_time/(pkt_count - 1)
                    
                    if(mean_time < 0.0004 and pkt_count > 10):
                        melicious_ip.add(prev_src_ip)
                                   
                                
                    total_time = 0
                    pkt_count = 2
                    
                    
                prev_time = curr_time
                prev_src_ip = curr_src_ip
                pre_dst_ip = curr_dst_ip
                
    if(total_time != 0 ):
        
        mean_time = total_time/(pkt_count - 1)
       
        if(mean_time < 0.0004 and pkt_count > 10):
            melicious_ip.add(prev_src_ip)
                
                        
    k = 0     
    melicious_data = []
    ben = []
    for pkt_data, metadata in  RawPcapReader(path):
        packet = Ether(pkt_data)
        
        k += 1
        
        if(packet.haslayer(IP)):
            src_ip = packet[1].src
            dst_ip = packet[1].dst
            
            if((src_ip in melicious_ip) or (dst_ip in melicious_ip)):
                melicious_data.append(str(k) + "    " + str(src_ip) + "     " +  str(dst_ip) + '\n' )
            else:
                ben.append(str(k) + "    " + str(src_ip) + "     " +  str(dst_ip) + '\n' )
        else:
            melicious_data.append(str(k) + "      IP layer not present    \n" ) 
                
     
    
    file_object = open('output.txt', 'a')
    file_object.write("\n \n \n   ---------- melicious IP's ----------- \n")
    file_object.close()
    
    for i in melicious_ip:
        file_object = open('output.txt', 'a')
        file_object.write("          "  + i  + '\n')
        file_object.close()
        
        
    file_object = open('output.txt', 'a')
    file_object.write("\n \n \n   ---------- melicious data ----------- \n")
    file_object.write("Frame_no     Source IP       Destination IP \n")
    file_object.close()
        
    
    for i in melicious_data:
        file_object = open('output.txt', 'a')
        file_object.write(i)
        file_object.close()
    
    file_object = open('output.txt', 'a')
    file_object.write("\n \n \n \n \n \n  ------ benign part -------  \n")
    file_object.write("Frame_no     Source IP       Destination IP \n")
        
    for i in ben:
        file_object = open('output.txt', 'a')
        file_object.write(i)
        file_object.close()
    
             


# In[ ]:



if __name__== '__main__':
    
    path =   sys.argv[1]
    data = []
    data.append(matrix(path))
    
    header = ['udp_percent' , 'tcp_percent' , 'packet_len_min' , 'packet_len_max' , 'packet_len_mean' , 'no_of_different_source_ip' , 'no_of_differnet_destination_ip' , 'no_of_differnet_source_port', 'no_of_different_destination_port' , 'time_intervel_between_packet' , 'no_of_packet']
    X = pd.DataFrame(data, columns = header) 
    model = pickle.load(open('model.sav', 'rb'))
    
    Y_pred = model.predict(X)
    
    file_object = open('output.txt', 'a')
    if(Y_pred[0] == 0):
        file_object.write("output : Benign   \n")
        file_object.close()
    else:
        writeTxt(path)
    
        


# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:




