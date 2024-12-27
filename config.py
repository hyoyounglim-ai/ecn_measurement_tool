#!/usr/bin/env python3

# Copyright 2021 Cable Television Laboratories, Inc. (CableLabs)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys, os, binascii, time
import socket, struct
import threading
import numpy
from numpy import loadtxt
import subprocess
import sh
from datetime import datetime
from datetime import date
from requests import get
from os import path
import logging
import random
import ftplib
import tcppacket as rs
import argparse
from scapy.all import *
import netaddr
import getpass

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

MyIP = get('https://api.ipify.org').text
logging.info('[Client] My public IP address is: %s', MyIP)  # check my public IP

# data_dir = 'data'

src_dir = path.abspath(path.join(path.dirname(__file__), os.pardir))
home_dir = path.abspath(path.join(src_dir, 'ecn_measurement_tool'))
data_dir = path.join(home_dir, 'ecnserver')
traceroute_data_dir = path.join(home_dir, 'traceroute')

logging.info("[Client] home_dir %s", home_dir)
logging.info("[Client] data_dir %s", traceroute_data_dir)
logging.info("[Client] data_dir %s", data_dir)
# logging.info(home_dir)
# logging.info(data_dir)

if not os.path.exists(data_dir+'/'):
    os.makedirs(data_dir+'/')

if not os.path.exists(traceroute_data_dir+'/'):
    os.makedirs(traceroute_data_dir+'/')
    
today = date.today()  

logging.info("[Client] Today's date: %s", today)
