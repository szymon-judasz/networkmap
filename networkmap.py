import multiprocessing
from multiprocessing.pool import Pool
import socket
import subprocess
import re
import os
import shutil
import random
import hashlib
import numpy as np
import geoip2.database
from PIL import Image, ImageDraw
import pyshark
import ctypes
import sys

__author__ = 'Szymon Judasz'

reader = geoip2.database.Reader('GeoLite2-City.mmdb')


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


def aggregate_connections(filename):
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


def cached_tracert(ip):
    output_filename = ip + '.txt'
    if not os.path.isfile(output_filename):
        command = ["tracert", "-d", "-w", "500", ip]
        output_stream = open(output_filename, "w")
        subprocess.call(command, stdout=output_stream)
        output_stream.close()


def tracert(ip):
    output_filename = ip + '.txt'
    if not os.path.isfile(output_filename):
        command = ["tracert", "-d", "-w", "500", ip]
        output_stream = open(output_filename, "w")
        subprocess.call(command, stdout=output_stream)
        output_stream.close()
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
        line = re.findall(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$', line)
        if len(line) == 0:
            continue
        result += ' ' + line[0]
    input_stream.close()
    result = result.lstrip(' ')
    return result


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


def get_ip_location(ip_address):
    response = reader.city(ip_address)
    return response.location.latitude, response.location.longitude


def draw_map(filename, map_name, map_output_name):
    im = Image.open(map_name)
    width = im.size[0]
    height = im.size[1]
    draw = ImageDraw.Draw(im)
    height_val = [85., 75., 60., 45., 30., 15., 0., -15., -30., -45., -60., -75.]
    height_pix = [0., 243., 520., 734., 919., 1087., 1248., 1412., 1580., 1765., 1981., 2253.]
    height_pix.reverse()
    height_val.reverse()

    input_stream = open(filename)
    while True:
        line = input_stream.readline()
        if line == '':
            break
        line = line.rstrip('\n')
        amount = re.findall(r'^[0-9]+', line)[0]
        traces = line.lstrip(amount + ' ')
        ip_list = re.findall('[0-9\.]+', traces)
        cords = list()
        for ip in ip_list:
            try:
                cur_pos = get_ip_location(ip)
            except:
                continue
            try:
                curx = (cur_pos[1] + 180) * width / 360
                cury = np.interp(cur_pos[0], height_val, height_pix)
            except:
                pass
            cords.append(curx)
            cords.append(cury)
        draw.line(cords, fill=127, width=2)
    input_stream.close()
    del draw
    im.save(map_output_name, 'JPEG')


def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("gmail.com", 80))
    result = s.getsockname()
    s.close()
    return result[0]

#  entry point
if __name__ == '__main__':
    multiprocessing.freeze_support()
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    if not is_admin:  # pyshark will not work unless is run as admin
        print 'Aborting... Script has to be executed as Admin'
        sys.exit()

    local_machine_address = get_ip_address()
    filename = "windows.txt"
    timeout = 60 * 10
    catch_network_windows(filename, timeout, False)
    strip_local_address(filename, local_machine_address)
    aggregate_connections(filename)
    make_routes(filename)
    draw_map(filename, 'map3.jpg', 'windows.jpeg')

reader.close()
