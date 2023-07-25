# pcap-stuff


### pcap_pull.py
A script I made that utilizes the Scapy python module to read in a pcap and filters it based on the command line inputs for Source and Destination IP/Port combo then outputs it to a file. It will output the resulting filtered packets to an output file and allows for the option to upload the pcap to an S3 bucket. Globlal VARS are included for AWS API Keys for testing purposes, but it is recommended to utilize python-dotenv with a .env file or using environment variables to not directly expose your API keys within the script. This Youtube video provides a good tutorial on how to do so: [Hide API keys in Python scripts using python-dotenv, .env, and .gitignore](https://www.youtube.com/watch?v=YdgIWTYQ69A)
