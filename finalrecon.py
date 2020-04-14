#!/usr/bin/env python3

import os
import sys
import atexit
import importlib.util

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white

fail = False

if os.geteuid() != 0:
	print('\n' + R + '[-]' + C + ' Mohon Dijalankan sebagai Sistem Akar!' + '\n')
	sys.exit()
else:
	pass

with open('requirements.txt', 'r') as rqr:
	pkg_list = rqr.read().strip().split('\n')

print('\n' + G + '[+]' + C + ' Memeriksa Cantolan...' + W + '\n')

for pkg in pkg_list:
	spec = importlib.util.find_spec(pkg)
	if spec is None:
		print(R + '[-]' + W + ' {}'.format(pkg) + C + ' belum diinstall!' + W)
		fail = True
	else:
		pass
if fail == True:
	print('\n' + R + '[-]' + C + ' Mohon Eksekusi Perintah > ' + W + 'pip3 install -r requirements.txt' + C + ' to Install Missing Packages' + W + '\n')
	exit()

import argparse

version = '1.0.3'

parser = argparse.ArgumentParser(description='FinalRecon - OSINT Tool for All-In-One Web Recon | v{}'.format(version))
parser.add_argument('url', help='URL Target')
parser.add_argument('--headers', help='Informasi Judul', action='store_true')
parser.add_argument('--sslinfo', help='Informasi SSL Sertifikat', action='store_true')
parser.add_argument('--whois', help='Whois Pencarian', action='store_true')
parser.add_argument('--crawl', help='Merobek Target', action='store_true')
parser.add_argument('--dns', help='DNS Enumeration', action='store_true')
parser.add_argument('--sub', help='Sub-Domain Enumeration', action='store_true')
parser.add_argument('--trace', help='Traceroute', action='store_true')
parser.add_argument('--dir', help='Lokasi Pencarian', action='store_true')
parser.add_argument('--ps', help='Pindai Jalur Cepat', action='store_true')
parser.add_argument('--full', help='Recon Penuh', action='store_true')

ext_help = parser.add_argument_group('Extra Options')
ext_help.add_argument('-t', type=int, help='Nomor dari Thread [ Bawaan : 50 ]')
ext_help.add_argument('-T', type=float, help='Permintaan Waktu Habis [ Bawaan : 10.0 ]')
ext_help.add_argument('-w', help='Path ke Daftar Kata [ Bawaan : wordlists/dirb_common.txt ]')
ext_help.add_argument('-r', action='store_true', help='Izin Pengalihan [ Bawaan : False ]')
ext_help.add_argument('-s', action='store_false', help='Beralih ke Verifikasi SSL [ Bawaan : True ]')
ext_help.add_argument('-d', help='Custom DNS Servers [ Bawaan : 1.1.1.1 ]')
ext_help.add_argument('-m', help='Traceroute Mode [ Bawaan : UDP ] [ Tersedia : TCP, ICMP ]')
ext_help.add_argument('-p', type=int, help='Jalur untuk Traceroute [ Bawaan : 80 / 33434 ]')
ext_help.add_argument('-tt', type=float, help='Waktu Habis Traceroute [ Bawaan : 1.0 ]')
ext_help.add_argument('-o', help='Ekspor Keluaran [ Bawaan : txt ] [ Bawaan : xml, csv ]')
ext_help.set_defaults(
	t=50,
	T=10.0,
	w='wordlists/dirb_common.txt',
	r=False,
	s=True,
	d='1.1.1.1',
	m='UDP',
	p=33434,
	tt=1.0,
	o='txt')

args = parser.parse_args()
target = args.url
headinfo = args.headers
sslinfo = args.sslinfo
whois = args.whois
crawl = args.crawl
dns = args.dns
trace = args.trace
dirrec = args.dir
pscan = args.ps
full = args.full
threads = args.t
tout = args.T
wdlist = args.w
redir = args.r
sslv = args.s
dserv = args.d
subd = args.sub
mode = args.m 
port = args.p
tr_tout = args.tt
output = args.o

import socket
import requests
import datetime
import ipaddress
import tldextract

type_ip = False
data = {}
meta = {}

def banner():
	os.system('clear')
	banner = r'''
 ______  __   __   __   ______   __
/\  ___\/\ \ /\ "-.\ \ /\  __ \ /\ \
\ \  __\\ \ \\ \ \-.  \\ \  __ \\ \ \____
 \ \_\   \ \_\\ \_\\"\_\\ \_\ \_\\ \_____\
  \/_/    \/_/ \/_/ \/_/ \/_/\/_/ \/_____/
 ______   ______   ______   ______   __   __
/\  == \ /\  ___\ /\  ___\ /\  __ \ /\ "-.\ \
\ \  __< \ \  __\ \ \ \____\ \ \/\ \\ \ \-.  \
 \ \_\ \_\\ \_____\\ \_____\\ \_____\\ \_\\"\_\
  \/_/ /_/ \/_____/ \/_____/ \/_____/ \/_/ \/_/'''
	print (G + banner + W + '\n')
	print (G + '[>]' + C + ' Dibuat oleh : ' + W + 'thewhiteh4t')
	print (G + '[>]' + C + ' Diedit oleh : ' + G + 'Dicer-TDP')
	print (G + '[>]' + G + ' Modify by   : ' + G + 'Dicer-TDP')
	print (G + '[>]' + C + ' Versi       : ' + W + version + '\n')
	print (G + '[>]' + R + ' NB: ' + R + ' Penambahan Struktur DNS ')
	print (G + '[>]' + R + '     ' + R + ' Penambahan Metode Crawler ')
	print (G + '[>]' + R + '     ' + R + ' Penambahan Jalur/Port scan ')
	print (G + '[>]' + R + '     ' + R + ' Penerjemahan Bahasa ')
	print (G + '[>]' + G + ' Ikuti Author: ' + G + 'https://github.com/thewhiteh4t')
	print (G + '[>]' + G + ' Ikuti Editor: ' + G + 'https://github.com/Dicer-TDP')

def ver_check():
	print(G + '[+]' + C + ' Memeriksa Pembaharuan...', end='')
	ver_url = 'https://raw.githubusercontent.com/thewhiteh4t/finalrecon/master/version.txt'
	try:
		ver_rqst = requests.get(ver_url, timeout=5)
		ver_sc = ver_rqst.status_code
		if ver_sc == 200:
			github_ver = ver_rqst.text
			github_ver = github_ver.strip()
			if version == github_ver:
				print(C + '[' + G + ' Ter-Ba-Ru ' + C +']' + '\n')
			else:
				print(C + '[' + G + ' Tersedia : {} '.format(github_ver) + C + ']' + '\n')
		else:
			print(C + '[' + R + ' Status : {} '.format(ver_sc) + C + ']' + '\n')
	except Exception as e:
		print('\n\n' + R + '[-]' + C + ' Exception : ' + W + str(e))
		sys.exit()

def full_recon():
	from modules.sslinfo import cert
	from modules.crawler import crawler
	from modules.headers import headers
	from modules.dns import dnsrec
	from modules.traceroute import troute
	from modules.whois import whois_lookup
	from modules.dirrec import hammer
	from modules.portscan import ps
	from modules.subdom import subdomains
	headers(target, output, data)
	cert(hostname, output, data)
	whois_lookup(ip, output, data)
	dnsrec(domain, output, data)
	if type_ip == False:
		subdomains(domain, tout, output, data)
	else:
		pass
	troute(ip, mode, port, tr_tout, output, data)
	ps(ip, output, data)
	crawler(target, output, data)
	hammer(target, threads, tout, wdlist, redir, sslv, dserv, output, data)

try:
	banner()
	ver_check()

	if target.startswith(('http', 'https')) == False:
		print(R + '[-]' + C + ' Perintah Gagal, Kecuali ' + W + 'http://' + C + ' or ' + W + 'https://' + '\n')
		sys.exit()
	else:
		pass

	if target.endswith('/') == True:
		target = target[:-1]
	else:
		pass

	print (G + '[+]' + C + ' Target : ' + W + target)
	ext = tldextract.extract(target)
	domain = ext.registered_domain
	hostname = '.'.join(part for part in ext if part)

	try:
		ipaddress.ip_address(hostname)
		type_ip = True
		ip = hostname
	except:
		try:
			ip = socket.gethostbyname(hostname)
			print ('\n' + G + '[+]' + C + ' Alamat IP : ' + W + str(ip))
		except Exception as e:
			print ('\n' + R + '[+]' + C + ' Gagal meminta IP : ' + W + str(e))
			if '[Errno -2]' in str(e):
				sys.exit()
			else:
				pass
	
	start_time = datetime.datetime.now()

	meta.update({'Versi': str(version)})
	meta.update({'Waktu': str(datetime.date.today())})
	meta.update({'Target': str(target)})
	meta.update({'Alamat IP': str(ip)})
	meta.update({'Waktu Mulai': str(start_time.strftime('%I:%M:%S %p'))})
	data['module-FinalRecon'] = meta

	if output != 'None':
		fname = os.getcwd() + '/dumps/' + hostname + '.' + output
		output = {
			'format': output,
			'file': fname,
			'export': False
			}

	from modules.export import export

	if full == True:
		full_recon()

	if headinfo == True:
		from modules.headers import headers
		headers(target, output, data)

	if sslinfo == True:
		from modules.sslinfo import cert
		cert(hostname, output, data)

	if whois == True:
		from modules.whois import whois_lookup
		whois_lookup(ip, output, data)

	if crawl == True:
		from modules.crawler import crawler
		crawler(target, output, data)

	if dns == True:
		from modules.dns import dnsrec
		dnsrec(domain, output, data)

	if subd == True and type_ip == False:
		from modules.subdom import subdomains
		subdomains(domain, tout, output, data)
	elif subd == True and type_ip == True:
		print(R + '[-]' + C + ' Sub-Domain Enumeration tidak mendukung pada Alamat IP' + W + '\n')
		sys.exit()
	else:
		pass

	if trace == True:
		from modules.traceroute import troute
		if mode == 'TCP' and port == 33434:
			port = 80
			troute(ip, mode, port, tr_tout, output, data)
		else:
			troute(ip, mode, port, tr_tout, output, data)

	if pscan == True:
		from modules.portscan import ps
		ps(ip, output, data)

	if dirrec == True:
		from modules.dirrec import hammer
		hammer(target, threads, tout, wdlist, redir, sslv, dserv, output, data)

	if any([full, headinfo, sslinfo, whois, crawl, dns, subd, trace, pscan, dirrec]) != True:
		print ('\n' + R + '[-] Kesalahan : ' + C + 'Setidaknya Satu Argumen URL Diperlukan' + W)
		output = 'None'
		sys.exit()
	
	end_time = datetime.datetime.now() - start_time
	print ('\n' + G + '[+]' + C + ' Selesaikan Mulai ' + W + str(end_time) + '\n')

	@atexit.register
	def call_export():
		meta.update({'Waktu Akhir': str(datetime.datetime.now().strftime('%I:%M:%S %p'))})
		meta.update({'Waktu Penyelesaian': str(end_time)})
		if output != 'None':
			output['export'] = True
			export(output, data)

	sys.exit()
except KeyboardInterrupt:
	print (R + '[-]' + C + ' Keyboard Memutuskan.' + W + '\n')
	sys.exit()
