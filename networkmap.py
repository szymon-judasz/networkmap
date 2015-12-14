import subprocess
import re
__author__ = 'kolesnikov'


filename = "dump.txt"
tempname = "temp.txt"
machine_ip = "192.168.57.130"
# UNSAFE CODE BELOW
# EASY SHELL SCRIPT INJECTION?

def catch_network(file_output_name):
    # run under root

    #tcpdump -Q inout -v -w dump.p
    command = ["tcpdump", "-Q", "inout", "-v", "-w", file_output_name + ".pcap"]
    print "SIGINT to stop capturing"
    subprocess.call(command)

    #tcpdump -r dump.p > temp.txt
    command = ["tcpdump", "-r", file_output_name + ".pcap"]
    outputstream = open(file_output_name + ".txt", "w")
    subprocess.call(command, stdout=outputstream)
    outputstream.close()

def tracert(ip):
    command = ["tracert", ip]
    outputstream = open("tracert.txt", "w")
    subprocess.call(command, stdout=outputstream)
    outputstream.close()


def strip_unimportant_data():
    input_stream = open(filename)
    output_stream = open(tempname, "w")
    command = ["awk", "{print $3 \"\t\" $5}"]
    subprocess.call(command, stdin=input_stream, stdout=output_stream)
    # tempname contains only 2 ip + port
    input_stream.close()
    output_stream.close()

    #  striping ports
    input_stream = open(tempname)
    output_stream = open(tempname + "1", "w")
    while (1):
        line = input_stream.readline()
        if(len(line) == 0):
            break
        line = re.sub(r'\.[A-Za-z0-9]+\t', r'\t', line)
        line = re.sub(r'\.[A-Za-z0-9]+:', r'', line)
        output_stream.write(line)
    input_stream.close()
    output_stream.close()

    #  striping machine adress
    input_stream = open(tempname + "1")
    output_stream = open(tempname + "2", "w")
    while (1):
        line = input_stream.readline()
        if(len(line) == 0):
            break
        line = re.sub(r'\t' + machine_ip, r'', line)
        line = re.sub(machine_ip + r'\t', r'', line)
        output_stream.write(line)
    input_stream.close()
    output_stream.close()

    # only one ip address but some are repeating
    # sorting it
    input_stream = open(tempname + "2")
    output_stream = open("sorted", "w")
    command = ["sort"]
    subprocess.call(command, stdin=input_stream, stdout=output_stream)
    input_stream.close()
    output_stream.close()
    # and removing duplicates
    input_stream = open("sorted")
    output_stream = open("map", "w")
    command = ["uniq", "-c"]
    subprocess.call(command, stdin=input_stream, stdout=output_stream)


strip_unimportant_data()



line = "192.168.57.130.54115	192.168.57.2.domain:"
line = re.sub(r'\.[A-Za-z0-9]+\t', r'\t', line)
line = re.sub(r'\.[A-Za-z0-9]+:', r'', line)
print line
