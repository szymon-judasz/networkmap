import multiprocessing
from multiprocessing.pool import Pool
import socket
import subprocess
import re
import os
import shlex
import shutil
import random
import hashlib
import numpy as np
import geoip2.database
from PIL import Image, ImageDraw
import matplotlib.pyplot as plt
import pyshark
import time
import ctypes
import sys

__author__ = 'kolesnikov'

reader = geoip2.database.Reader('GeoLite2-City.mmdb')

filename = "dump.txt"
tempname = "temp.txt"
machine_ip = "192.168.57.130"  # used in tracert

def generate_temp_filename():
    seed = 42
    while True:
        hasher = hashlib.new('md5')
        hasher.update(str(seed))
        y = hasher.hexdigest()
        temp_filename = y + '.txt'
        if not os.path.isfile(temp_filename):
            return temp_filename
        seed = random.randint(0, 10000)



# run under linux
def catch_network(file_output_name):
    # run under root

    # tcpdump -Q inout -v -w dump.p
    command = ["tcpdump", "-Q", "inout", "-v", "-w", file_output_name + ".pcap"]
    print "SIGINT to stop capturing"
    subprocess.call(command)

    # tcpdump -r dump.p > temp.txt
    command = ["tcpdump", "-r", file_output_name + ".pcap"]
    output_stream = open(file_output_name + ".txt", "w")
    subprocess.call(command, stdout=output_stream)
    output_stream.close()



#  wireshark must have been installed
def catch_network_windows(file_output_name, timeout, drawhead=True):

    capture = pyshark.LiveCapture(interface='Wi-Fi')
    output_stream = open(file_output_name, "w")
    if drawhead:
        output_stream.write("len, destination, source\n")

    def packet_arrived_handler(pkt):
        line = ''
        try:
            line += pkt.length + ' ' + pkt.ip.dst + ' ' + pkt.ip.src
            print line
            output_stream.write(line + '\n')
        except:
            pass

    try:
        capture.apply_on_packets(packet_arrived_handler, timeout)
    except:
        pass
    output_stream.close()




def strip_local_address(filename, ip_addr):
    temp_filename = generate_temp_filename()
    shutil.copy2(filename, temp_filename)
    input_stream = open(temp_filename)
    output_stream = open(filename, 'w')

    while True:
        line = input_stream.readline()
        if line == '':
            break
        if len(re.findall(ip_addr, line)) == 0:
            continue
        line = re.sub(ip_addr, '', line)
        output_stream.write(line)

    output_stream.close()
    input_stream.close()
    os.remove(temp_filename)


def cached_tracert(ip):
    output_filename = ip + '.txt'
    if not os.path.isfile(output_filename):
        command = ["tracert", "-d", "-w", "500", ip]
        output_stream = open(output_filename, "w")
        subprocess.call(command, stdout=output_stream)
        output_stream.close()


def parse_tracert_output(filename):
    input_stream = open(filename)
    first_line = input_stream.readline()
    ip_destination = input_stream.readline()
    ip_destination = re.findall(r'\[.+\]', ip_destination)
    if len(ip_destination) == 0:
        host_name = re.findall(r'.\.$', first_line)
        return host_name[0] if len(host_name) != 0 else '127.0.0.1'
    ip_destination = ip_destination[0].lstrip('[').rstrip(']')
    for i in range(2):
        input_stream.readline()
    ip_list = ''
    while 1:
        line = input_stream.readline()
        if line == "\n" or line == "":
            break
        ip = line.rstrip(' \n')
        ip = re.findall(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$', ip)
        if len(ip) == 0:
            continue
        ip_list += ' ' + ip[0]
    if len(ip_list) == 0:
        return ip_destination

    input_stream.close()
    ip_list = ip_list.lstrip(' ')
    return ip_list
    input_stream.close()

# run under windows
def tracert(ip):
    output_filename = ip + '.txt'
    if not os.path.isfile(output_filename):
        command = ["tracert", "-d", "-w", "500", ip]
        output_stream = open(output_filename, "w")
        subprocess.call(command, stdout=output_stream)
        output_stream.close()
    else:
        print ip + ' found in cache'
    result = ""
    input_stream = open(output_filename)
    input_stream.readline()
    input_stream.readline()
    input_stream.readline()
    input_stream.readline()
    while 1:
        line = input_stream.readline()
        if line == "\n" or line == "":
            break
        line = line.rstrip(' \n')
        # line = re.sub(r'[.]*([A-Za-z0-9\.]+$)', r'\1', line)
        line = re.findall(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$', line)
        if len(line) == 0:
            continue
        result += ' ' + line[0]
        # print line

    input_stream.close()
    result = result.lstrip(' ')
    return result


def attach_routes():
    multiprocessing.freeze_support()
    input_stream = open("map")
    output_stream = open("routedmapsynchro", "w")
    while 1:
        line = input_stream.readline()
        if len(line) == 0:
            break
        ip = line.lstrip(' ')
        ip = re.sub(r'^[0-9]+ ', r'', ip)
        route = tracert(ip.rstrip('\n'))
        print(line.rstrip('\n') + ' ' + route)
        output_stream.write(line.rstrip('\n') + ' ' + route + '\n')  # double ip in one line

def make_routes(filename):
    multiprocessing.freeze_support()
    temp_filename = generate_temp_filename()
    shutil.copy2(filename, temp_filename)
    input_stream = open(temp_filename)

    pool = Pool(20)

    ip_list = list()
    while True:
        line = input_stream.readline()
        if line == '':
            break
        ip = re.sub(r'^[0-9]+ ', '', line).rstrip(' \n')
        ip_list.append(ip.lstrip(' ').rstrip(' '))

    x = pool.map(cached_tracert, ip_list)
    pool.close()
    input_stream.close()
    input_stream = open(temp_filename)

    output_stream = open(filename, "w")
    while 1:
        line = input_stream.readline()
        if len(line) == 0:
            break
        ip = line.lstrip('\n').lstrip(' ')
        ip = re.sub(r'^[0-9]+ ', r'', ip).rstrip('\n')
        amount = re.sub(ip, '', line.lstrip(' ').rstrip(' ')).lstrip(' ').rstrip(' \n')
        route = tracert(ip.rstrip('\n')).rstrip('\n')
        if len(route) < 4:
            output_stream.write(amount + ' ' + ip + '\n')
        else:
            output_stream.write(amount + ' ' + route + '\n')
    output_stream.close()
    input_stream.close()


def attach_routes2():
    multiprocessing.freeze_support()
    input_stream = open("map")
    output_stream = open("routedmapasync", "w")
    ip_list = list()
    while 1:
        line = input_stream.readline()
        if len(line) == 0:
            break
        ip = line.lstrip(' ')
        ip = re.sub(r'^[0-9]+ ', r'', ip)
        ip_list.append(ip.rstrip('\n'))
    pool = Pool(20)

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
    while 1:
        line = input_stream.readline()
        if len(line) == 0:
            break
        line = re.sub(r'\.[A-Za-z0-9]+\t', r'\t', line)
        line = re.sub(r'\.[A-Za-z0-9]+:', r'', line)
        output_stream.write(line)
    input_stream.close()
    output_stream.close()

    #  striping machine address
    input_stream = open(tempname + "1")
    output_stream = open(tempname + "2", "w")
    while 1:
        line = input_stream.readline()
        if len(line) == 0:
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
        last_ip = ip_list[len(ip_list) - 1]
        if source == last_ip or len(re.findall('[A-Za-z]', traces)) > 0:
            route = ' '.join(ip_list[1:])

        else:
            ip_list[0] = ip_list[len(ip_list) - 1]
            ip_list[len(ip_list) - 1] = source
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


def draw_map(filename, map_name, map_output_name):
    im = Image.open(map_name)
    width = im.size[0]
    height = im.size[1]
    draw = ImageDraw.Draw(im)
    height_val = [85., 75., 60., 45., 30., 15., 0., -15., -30., -45., -60., -75.]
    height_pix = [0., 243., 520., 734., 919., 1087., 1248., 1412., 1580., 1765., 1981., 2253.]
    height_pix.reverse()
    height_val.reverse()

    # xvals = np.linspace(-75.0, 85.0, 10).tolist()
    # yinterp = np.interp(xvals, height_val, height_pix)
    # plt.plot(height_val, height_pix, 'o')
    # plt.plot(xvals, yinterp, '-x')
    # plt.show()

    input_stream = open(filename)
    while True:
        line = input_stream.readline()
        if line == '':
            break
        line = line.rstrip('\n')
        amount = re.findall(r'^[0-9]+', line)[0]
        traces = line.lstrip(amount + ' ')
        ip_list = re.findall('[0-9\.]+', traces)
        # prev_pos = get_ip_location(ip_list[0])
        # prevx = (prev_pos[1] + 180) * width / 360
        # prevy = height - ((prev_pos[0] + 90) * height / 180)
        cords = list()
        for ip in ip_list:
            try:
                cur_pos = get_ip_location(ip)
            except:
                continue
            curx = (cur_pos[1] + 180) * width / 360
            # cury = height - ((cur_pos[0] + 90) * height / 180)
            cury = np.interp(cur_pos[0], height_val, height_pix)
            cords.append(curx)
            cords.append(cury)
        draw.line(cords, fill=127, width=2)
    input_stream.close()
    del draw
    im.save(map_output_name, 'JPEG')


def aggregate_conncections(filename):
    temp_filename = generate_temp_filename()
    shutil.copy2(filename, temp_filename)
    input_stream = open(temp_filename)
    output_stream = open(filename, 'w')
    connection_dict = dict()
    while True:
        line = input_stream.readline()
        if line == '':
            break
        amount = re.findall(r'^[0-9]+', line)[0]
        ip = re.findall(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', line)[0]
        if ip in connection_dict:
            connection_dict[ip] += int(amount)
        else:
            connection_dict[ip] = int(amount)
    for ip in connection_dict:
        output_stream.write(str(connection_dict[ip]) + ' ' + ip + '\n')
    output_stream.close()
    input_stream.close()
    os.remove(temp_filename)


def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("gmail.com", 80))
    result = s.getsockname()
    s.close()
    return result[0]

if __name__ == '__main__':
    multiprocessing.freeze_support()
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    if not is_admin:
        print 'Aborting... Script has to be executed as Admin'
        sys.exit()

    local_machine_address = get_ip_address()
    filename = "windows.txt"
    timeout = 60
    catch_network_windows(filename, timeout, False)
    strip_local_address(filename, local_machine_address)
    aggregate_conncections(filename)
    make_routes(filename)
    draw_map(filename, 'map3.jpg', 'windows.jpeg')


    pass
# strip_unimportant_data()


# print tracert("onet.pl")

reader.close()
