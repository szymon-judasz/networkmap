import multiprocessing
from multiprocessing.pool import Pool
import subprocess
import re
import os.path
import numpy as np
import array
import geoip2.database
from PIL import Image, ImageDraw
import matplotlib.pyplot as plt

__author__ = 'kolesnikov'

reader = geoip2.database.Reader('GeoLite2-City.mmdb')

filename = "dump.txt"
tempname = "temp.txt"
machine_ip = "192.168.57.130"
# UNSAFE CODE BELOW
# EASY SHELL SCRIPT INJECTION?

# run under linux
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


# run under windows
def tracert(ip):
    output_filename = ip + '.txt'
    if not os.path.isfile(output_filename):
        command = ["tracert","-d", "-w", "500", ip]
        output_stream = open(output_filename, "w")
        subprocess.call(command, stdout=output_stream)
        output_stream.close()
    else :
        print ip + ' found in cache'
    result = ""
    input_stream = open(output_filename)
    line = input_stream.readline()
    line = input_stream.readline()
    line = input_stream.readline()
    line = input_stream.readline()
    while (1):
        line = input_stream.readline()
        if line == "\n" or line == "":
            break
        line = line.rstrip(' \n')
        #line = re.sub(r'[.]*([A-Za-z0-9\.]+$)', r'\1', line)
        line = re.findall(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$', line)
        if(len(line)==0):
            continue
        result += ' ' + line[0]
        #print line

    input_stream.close()
    result = result.lstrip(' ')
    return result



def attach_routes():
    multiprocessing.freeze_support()
    input_stream = open("map")
    output_stream = open("routedmapsynchro", "w")
    while (1):
        line = input_stream.readline()
        if(len(line) == 0):
            break
        ip = line.lstrip(' ')
        ip = re.sub(r'^[0-9]+ ', r'', ip)
        route = tracert(ip.rstrip('\n'))
        print(line.rstrip('\n') + ' ' + route)
        output_stream.write(line.rstrip('\n') + ' ' + route + '\n') # double ip in one line



def attach_routes2():
    multiprocessing.freeze_support()
    input_stream = open("map")
    output_stream = open("routedmapasync", "w")
    ip_list = list()
    while (1):
        line = input_stream.readline()
        if(len(line) == 0):
            break
        ip = line.lstrip(' ')
        ip = re.sub(r'^[0-9]+ ', r'', ip)
        ip_list.append(ip.rstrip('\n'))
    x = [1, 2, 3]
    pool = Pool(32)

    pool.map(tracert, ip_list)
        # line format:
        # <number of connections> <destination> <gateway> <route> <destination>
        # has to strip first destination

        # drawing be like
        # first draw paths
        # second indicate somehow volume
        # draw circles from minsize to maxsize with linear adjusting


    input_stream.close()
    output_stream.close()

#  run under linux
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
    # now is ""

def get_ip_location(ip_address):
    response = reader.city(ip_address)
    return response.location.latitude, response.location.longitude

def normalize():
    input_stream = open('routedmapsynchro')
    output_stream = open('traces.txt', 'w')
    while True:
        line = input_stream.readline()
        if line == '':
            break
        line = line.lstrip(' ')
        amount = re.findall('^[0-9]+', line)[0]
        traces = line.lstrip(amount)
        ip_list = re.findall('[A-Za-z0-9\.\-]+', traces)
        source = ip_list[0]
        last_ip = ip_list[len(ip_list)-1]
        if(source == last_ip or len(re.findall('[A-Za-z]', traces)) > 0):
            route = ' '.join(ip_list[1:])

        else:
            ip_list[0] = ip_list[len(ip_list)-1]
            ip_list[len(ip_list)-1] = source
            route = ' '.join(ip_list)
        if len(route) > 0:
            output_stream.write(amount + ' ' + route + '\n')
    input_stream.close()
    output_stream.close()

# TODO
def compute_connections():
    result = dict()
    input_stream = open('traces.txt')
    while True:
        line = input_stream.readline()
        if line == '':
            break
        line = line.rstrip('\n')
        amount = re.findall(r'^[0-9]+', line)[0]
        traces = line.lstrip(amount + ' ')
        ip_list = re.findall('[0-9\.]+', traces)
        for ip in ip_list:
            if result.has_key(ip):
                result[ip] += amount
            else:
                result[ip] = amount
    input_stream.close()
    return result

def draw_map(volumes):
    im = Image.open('map3.jpg')
    width = im.size[0]
    height = im.size[1]
    draw = ImageDraw.Draw(im)
    height_val = [85., 75., 60., 45., 30., 15., 0., -15., -30., -45., -60., -75.]
    height_pix = [0., 243., 520., 734., 919., 1087., 1248., 1412., 1580., 1765., 1981., 2253.]
    height_pix.reverse()
    height_val.reverse()

    #xvals = np.linspace(-75.0, 85.0, 10).tolist()
    #yinterp = np.interp(xvals, height_val, height_pix)
    #plt.plot(height_val, height_pix, 'o')
    #plt.plot(xvals, yinterp, '-x')
    #plt.show()

    input_stream = open('traces.txt')
    while True:
        line = input_stream.readline()
        if line == '':
            break
        line = line.rstrip('\n')
        amount = re.findall(r'^[0-9]+', line)[0]
        traces = line.lstrip(amount + ' ')
        ip_list = re.findall('[0-9\.]+', traces)
        #prev_pos = get_ip_location(ip_list[0])
        #prevx = (prev_pos[1] + 180) * width / 360
        #prevy = height - ((prev_pos[0] + 90) * height / 180)
        cords = list()
        for ip in ip_list:
            try:
                cur_pos = get_ip_location(ip)
            except:
                continue
            curx = (cur_pos[1] + 180) * width / 360
            #cury = height - ((cur_pos[0] + 90) * height / 180)
            cury = np.interp(cur_pos[0], height_val, height_pix)
            cords.append(curx)
            cords.append(cury)
        draw.line(cords, fill=127, width=2)
    input_stream.close()
    del draw
    im.save('result.jpg', 'JPEG')


if __name__ == '__main__':
    multiprocessing.freeze_support()

    volumes = compute_connections()
    draw_map(volumes)
    print(get_ip_location('89.234.223.9'))

#strip_unimportant_data()


#print tracert("onet.pl")

reader.close()
