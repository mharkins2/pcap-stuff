#!/usr/bin/env python3

'''
This script is used to take an input pcap file and parse it for specific parameters, then filter the pcap into a smaller pcap.
'''

#Imports for parsing pcap
import os
import os.path
import argparse
import logging
import logging.handlers
from scapy.all import *
import time
import random

# Used for glob searching directories
from glob import glob

# Imports for S3 Uploads
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

# Constants
ACCESS_KEY = "API-KEY"
SECRET_KEY = "API-SECRET-KEY"
S3_BUCKET = "Bucket-name"
IP_PROTOCOL_TCP = 6
IP_PROTOCOL_UDP = 17
IP_PROTOCOL_ICMP = 1

def pcap_pull(filename, output_file, destinationIP, destinationPort, sourceIP, sourcePort, protocol, S3, requestID):
    '''
    Script takes arguments and uses it to parse pcap for specific parameters
    '''

    execution_time = time.time()

    # Initial IP Protocol variables
    if protocol == IP_PROTOCOL_TCP:
        search_protocol = "TCP"
    elif protocol == IP_PROTOCOL_UDP:
        search_protocol = "UDP"
    elif protocol == IP_PROTOCOL_ICMP:
        search_protocol = "ICMP"
    else:
        raise ValueError(msg=f"Invalid protocol entered, exiting. Protocol: {protocol}")
    
    # Return a list of pkts from specified pcap.
    pkt_list = []
    try:
        pkts = PcapReader(filename)
        filtered = (pkt for pkt in pkts if
                    search_protocol in pkt and
                    (sourceIP in pkt[IP].src and destinationIP in pkt[IP].dst and str(sourcePort) in str(pkt[search_protocol].sport) and str(destinationPort) in str(pkt[search_protocol].dport)))
        pkt_list.append(filtered)
        wrpcap(output_file, pkt_list)

        if S3:
            if os.path.exists(output_file):
                upload_pcap_to_s3 = pcap_s3_upload(file=output_file, bucket=S3_BUCKET, object_name=None)
                if upload_pcap_to_s3 == None:
                    logging.info(f"{execution_time} | {requestID} | PCAP successfully uploaded to S3 Bucket.")
    except AttributeError as e:
        raise AttributeError("There doesn't appear to be any packets that match the input filter!")
    
def pcap_s3_upload(file, bucket, object_name=None):

    '''
    Uploads pcap file to S3

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 Object name. If not specified, the file_name is used.
    :return: True if file was uploaded, else False
    '''

    # if S3 object_name was not specified, use file_name
    if object_name is None:
        object_name=os.path.basename(file)

    # Need to add API key for pcap_upload with only PUT actions
    s3_client = boto.client(
        's3',
        aws_access_key_id = ACCESS_KEY,
        aws_secret_access_key = SECRET_KEY,
    )

    try:
        response = s3_client.upload_file(file, bucket, object_name)
        print(response)
    except ClientError as e:
        logging.error(e)
        return False
    return True

if __name__ == "__main__":
    
    # Intialize Argument Parser
    parser = argparse.ArgumentParser(description="Parses script command line options.")

    # Setup Arguments and assign to variables
    parser.add_argument("-r", "--filename", action="store", required=True, dest="filename", help="File name to read into script")
    parser.add_argument("-o", "--output", action="store", required=True, dest="output_file", help="Output file name.")
    parser.add_argument("-dip", "--destinationIP", action="store", required=True, dest="destinationIP", help="The destination ip")
    parser.add_argument("-dport", "--destinationPort", action="store", required=True, dest="destinationPort", help="The destination port")
    parser.add_argument("-sip", "--sourceIP", action="store", required=True, dest="sourceIP", help="The source ip")
    parser.add_argument("-sport", "--sourcePort", action="store", required=True, dest="sourcePort", help="The source port")
    parser.add_argument("-prot", "--protocol", action="store", required=True, dest="protocol", type=int, help="Protocol used i.e TCP(6), UDP(17), or ICMP(1).")
    parser.add_argument("-s3", action="store", required=True, dest="S3", type=bool, help="True or False to upload to S3.")

    requestID = random.getrandbits(128)

    # Parse arguments and start pcap_pull
    args = parser.parse_args()

    try:
        if os.path.exists(args.filename):
            pcap_pull(args.filename, args.output_file, args.destinationIP, args.destinationPort, args.sourceIP, args.sourcePort, args.protocol, args.S3, requestID)

    except FileNotFoundError:
        print("Input File does not exist")
    





    

    
