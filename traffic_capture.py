'''
    program maps network activity on a specified port 
    use to map simple behviors on network, 
    process captured data,
    and identify specific hosts and supprted services
''' 

import socket #network interface library
import os # oeprating system functions
import sys # system level functions
from struct import * # handle strings as binary data
PROTOCOL_TCP = 6 # TCP protocol for IP layer

'''
    packet extractor function
    purpose: extract fields from IP and TCP header
    input: packet: buffer from socket.recvfrom() method
    output: list: serverIP, clientIP, serverPort
    >> and << are bit shift operators
'''

def packet_extractor(packet):
	strip_packet = packet[0:20] # strip off first 20 characters for ip header
	ip_header_tuple = unpack('!BBHHHBBH4s4s', strip_packet) # unpack header, unpack returns a tuple
	ver_len = ip_header_tuple[0]        # field: version and length
	TOS = ip_header_tuple[1]            # field: type of service
	packet_length = ip_header_tuple[2]  # field: packet length
	packet_id = ip_header_tuple[3]      # field: packet identification
	flag_frag = ip_header_tuple[4]      # field: flags/fragment offset
	RES = (flag_frag >> 15) & 0x01      # field: reserved
	DF = (flag_frag >> 14) & 0x01       # field: don't fragment
	MF = (flag_frag >> 13) & 0x01       # field: more fragments
	time_to_live = ip_header_tuple[5]   # field: time to tlive(ttl)
	protocol = ip_header_tuple[6]       # field: protocol number
	check_sum = ip_header_tuple[7]      # field: header checksum
	source_ip = ip_header_tuple[8]      # field: source ip
	dest_ip = ip_header_tuple[9]        # field: destination IP
	
	# calculate and convert to extracted values
	version = ver_len >> 4              # upper nibble is version number
	length = ver_len & 0x0F             # lower nibble represents size
	ip_header_length = length * 4       # calculate header length in bytes
	
	# convert the source and destination address to dotted notation strings
	source_address = socket.inet_ntoa(source_ip)
	destination_address = socket.inet_ntoa(dest_ip)
	
	if protocol == PROTOCOL_TCP:
		strip_tcp_header = packet[ip_header_length:ip_header_length + 20]
		tcp_header_buffer = unpack('!HHLLBBHHH', strip_tcp_header) # unpack returns a tuple
		# each individual value using unpack() function
		source_port = tcp_header_buffer[0]
		destination_port = tcp_header_buffer[1]
		sequence_number = tcp_header_buffer[2]
		acknowledgement = tcp_header_buffer[3]
		data_offset_and_reserve = tcp_header_buffer[4] 
		tcp_header_length = (data_offset_and_reserve >> 4) * 4
		flags = tcp_header_buffer[5]
		FIN = flags & 0x01
		SYN = (flags >> 1) & 0x01
		RST = (flags >> 2) & 0x01
		PSH = (flags >> 3) & 0x01
		ACK = (flags >> 4) & 0x01
		URG = (flags >> 5) & 0x01
		ECE = (flags >> 6) & 0x01
		CWR = (flags >> 7) & 0x01
		window_size = tcp_header_buffer[6]
		tcp_check_sum = tcp_header_buffer[7]
		urgent_pointer = tcp_header_buffer[8]
		
		if source_port < 1024:
			server_ip = source_address
			client_ip = destination_address
			server_port = source_port
		
		elif destination_port < 1024:
			server_ip = destination_address
			client_ip = source_address
			server_port = destination_port
		
		else:
			server_ip = 'filter'
			client_ip = 'filter'
			server_port = 'filter'
		
		return([server_ip, client_ip, server_port], [SYN, server_ip, TOS, time_to_live, DF, window_size])
	
	else:
		return(['filter', 'filter', 'filter'], [NULL, Null, Null, Null])
#
if __name__ == '__main__':
	# note must run as sudo
	# sudo python ...
	# enable promiscious mode
	# make system call
	ret = os.system('ifconfig en1 promisc')
	if ret == 0:
		print('en1 configured in promisc. mode')
		# create new socket using python module
		# af_inet: address family internet
		# sock_raw: raw protocol at the network layer
		# ipproto_tcp: specifies the socket transport layer is tcp
		# attempt to open socket
		try:
			my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
			# if successful, post result
			print('raw socket\topen')
		except:
			# if socket fails
			print('raw socket\tfailed')
			sys.exit()
		# create a list to hold the results from packet capture
		# only save server ip, client ip, and server port
		ip_observations = []
		os_observations = []
		max_observations = 500
		# port filter set to 443
		# tcp port 443 defined as http protocol over tls/ssl
		port_value = 443
		try:
			while max_observations > 0:
				# attempt to receive (this call is a'sync, and will wait)
				recv_buffer, addr = my_socket.recvfrom(255)
				# decode recevied packet
				# call the local packet extract function
				content, finger_print = packet_extractor(recv_buffer)
				if content[0] != 'filter':
					if content[2] == port_value: # if port match
						ip_observations.append(content) # append results to list
						max_observations = max_observations - 1
						if finger_print[0] == 1: # if SYN flag is set
						    # record fingerprint data in os observations
							os_observations.append([finger_print[1], finger_print[2], finger_print[3], finger_print[4], finger_print[5]])
						else:
							# not port
							continue
					else:
						# not valid packet
						continue
		except:
			print('socket failure')
			exit()
		# capture complete
		# disable promisc. mode
		ret = os.system('ifconfig en1 -promisc')
		my_socket.close() # close the raw socket
		# create unique sorted list
		# convert list into a set to eliminate duplicate entries
		# convert set back into list for sorting
		unique_src = set(map(tuple, ip_observations))
		final_list = list(unique_src)
		final_list.sort()
		unique_fingerprints = set(map(tuple, os_observations))
		final_fingerprint_list = list(unique_fingerprints)
		final_fingerprint_list.sort()
		# print out combinations
		print('unique packets')
		for packet in final_list:
			print(packet)
		print('unique fingerprints')
		for os_finger in final_fingerprint_list:
			print(os_finger)
	else:
		print('promisc. mode not set')
