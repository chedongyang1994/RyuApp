"""
	this application is used to avoid multicast storm which is solved by the STP
	protocol in traditional network.in SDN,this problem is easily to solved.

""" 

#chedongyang  UESTC  ChengDu
#2018.11.6
#from :muzixing

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER,MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp

ETHERNET=ethernet.ethernet.__name__
ETHERNET_MULTICAST="ff:ff:ff:ff:ff:ff"
ARP=arp.arp.__name__

class arp_proxy(app_manager.RyuApp):
	OFP_VERSIONS=[ofproto_v1_3.OFP_VERSION]
	
	def __init__(self,*args,**kwargs):
		super(arp_proxy,self).__init__(*args,**kwargs)
		self.mac_to_port={}
		self.arp_table={}
		self.switch={}

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures,CONFIG_DISPATCHER)
	def switch_feathres_handler(self,ev):
		datapath=ev.msg.datapath
		ofproto=datapath.ofproto
		parser=datapath.ofproto_parser
		
		#install the table-miss flow entry
		match=parser.OFPMatch()
		actions=[parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath,0,match,actions)

	def add_flow(self,datapath,priority,match,actions):
		ofproto=datapath.ofproto
		parser=datapath.ofproto_parser
	
		inst=[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
		
		mod=parser.OFPFlowMod(datapath=datapath,priority=priority,
				match=match,instructions=inst)
		datapath.send_msg(mod)

	@set_ev_cls(ofp_event.EventOFPPacketIn,MAIN_DISPATCHER)
	def _packet_in_handler(self,ev):
		msg=ev.msg
		datapath=msg.datapath
		ofproto=datapath.ofproto
		parser=datapath.ofproto_parser
		in_port=msg.match['in_port']

		pkt=packet.Packet(msg.data)
		
		eth=pkt.get_protocols(ethernet.ethernet)[0]
		dst=eth.dst
		src=eth.src
		dpid=datapath.id

		#a method to get all protocols in header.
		header_list=dict(
			(p.protocol_name,p) for p in pkt.protocols if type(p)!=str)
		if ARP in header_list:
			self.arp_table[header_list[ARP].src_ip]=src  #start ARP learning
	
		self.mac_to_port.setdefault(dpid,{})
		self.logger.info("Ryu-message-PacketIn : %s %s %s %s",dpid,src,dst,in_port)
		
		self.mac_to_port[dpid][src]=in_port

		if dst in self.mac_to_port[dpid]:
			out_port=self.mac_to_port[dpid][dst]
		else:
			if self.arp_handler(header_list,datapath,in_port,msg.buffer_id):
				#1:reply or drop;0:flood
				print ("ARP_PROXY")
				return None
			else:
				out_port=ofproto.OFPP_FLOOD
				print ("OFPP_FLOOD")
	
		actions=[parser.OFPActionOutput(out_port)]
		
		if out_port!=ofproto.OFPP_FLOOD:
			match=parser.OFPMatch(in_port=in_port,eth_dst=dst)
			self.add_flow(datapath,1,match,actions)

		data=None
		if msg.buffer_id ==ofproto.OFP_NO_BUFFER:
			data=msg.data
		out=parser.OFPPacketOut(datapath=datapath,buffer_id=msg.buffer_id,
					in_port=in_port,actions=actions,data=data)
		datapath.send_msg(out)

	def arp_handler(self,header_list,datapath,in_port,msg_buffer_id):
		header_list=header_list
		datapath=datapath
		in_port=in_port

		if ETHERNET in header_list:
			eth_dst=header_list[ETHERNET].dst
			eth_src=header_list[ETHERNET].src

		if eth_dst == ETHERNET_MULTICAST and ARP in header_list:
			arp_dst_ip=header_list[ARP].dst_ip
			if(datapath.id,eth_src,arp_dst_ip) in self.switch:   #break the loop
				if self.switch[(datapath.id,eth_src,arp_dst_ip)] !=in_port:
					out=datapath.ofproto_parser.OFPPacketOut(
						datapath=datapath,
						buffer_id=datapath.ofproto.OFP_NO_BUFFER,
						in_port=in_port,actions=[],data=None)
					datapath.send_msg(out)
					return True
			else:
				self.switch[(datapath.id,eth_src,arp_dst_ip)]=in_port

		if ARP in header_list:
			hwtype=header_list[ARP].hwtype
			proto=header_list[ARP].proto
			hlen=header_list[ARP].hlen
			plen=header_list[ARP].plen
			opcode=header_list[ARP].opcode
			
			arp_src_ip=header_list[ARP].src_ip
			arp_dst_ip=header_list[ARP].dst_ip
		
			actions=[]

			if opcode==arp.ARP_REQUEST:
				if arp_dst_ip in self.arp_table: #arp reply
					actions.append(datapath,ofproto_parser.OFPActionOutput(
							in_port))

					ARP_Reply=packet.Packet()
					ARP_Reply.add_protocol(ethernet.ethernet(
						ethertype=header_list[ETHERNET].ethertype,
						dst=eth_src,
						src=self.arp_table[arp_dst_ip]))
					ARP_Reply.add_protocol(arp.arp(
						opcode=arp.ARP_REPLY,
						src_mac=self.arp_table[arp_dst_ip],
						src_ip=arp_dst_ip,
						dst_mac=eth_src,
						dst_ip=arp_src_ip))

					ARP_Reply.serialize()

					
					
					out=datapath.ofproto_parser.OFPPacketOut(
						datapath=datapath,
						buffer_id=datapath.ofproto.OFP_NO_BUFFER,
						in_port=datapath.ofproto.OFPP_CONTROLLER,
						actions=actions,data=ATP_Reply.data)
					datapath.send_msg(out)
					return True
		return False


















