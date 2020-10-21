# DDoS-Attack-Detection-System

Note: python scripts are written in python3. Hence we recommend the use of python3, and pip3 for installing the additional libraries.
________________________________
### What's in the repo?

ddosdetect.py ( python script to test for malicious traffic in the input pcap file )
model.sav ( the trained model )
train.py ( the python script to train the model )
data.csv ( the preprocessed data )
__________________
### Libraries Used

1. os
2. scapy (can install with the command: pip3 install scapy)
3. pandas (can install with the command: pip3 install pandas)
4. numpy (can install with the command: pip3 install numpy)
5. sklearn (can install with the command: pip3 install sklearn)
6. pickle (can install with the command: pip3 install pickle-mixin)

________________
### How to Run ?

Install python3, if not already present.

run the ddosdetect.py by typing the following command in a terminal opened in the same folder of
ddosdetect.py file.

	$ python3 ddosdetect.py absolute_path_for_pcap_file

________________
### Output

When the testing gets over, required output.txt file will be generated in the same folder as that of ddosdetect.py,
which contains:
the malicious IP
malicious traffic listed first ( with corresponding frame number in the pcap file, source IP and destination IP)
and then the benign traffic listed ( with corresponding frame number in the pcap file, source IP and destination IP).
