from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER,DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ether_types
from ryu.lib.packet import *
from ryu.lib.packet import ethernet

class analysis_proto(simple_switch_13.SimpleSwitch13):
	def __init__(self,*args,**kwargs):
		super(analysis_proto,self).__init__(*args,**kwargs)
		self.protocols={}
		

	@set_ev_cls(ofp_event.EventOFPPacketIn,MAIN_DISPATCHER)
	def packet_in_handler(self,ev):
		msg=ev.msg
		dp=msg.datapath
		dpid=dp.id
		ofproto=dp.ofproto
		parser=dp.ofproto_parser

		pkt=packet.Packet(msg.data)
		
		pkt_eth=pkt.get_protocols(ethernet.ethernet)[0]
		pkt_ipv6=pkt.get_protocol(ipv6.ipv6)
		pkt_icmpv6=pkt.get_protocol(icmpv6.icmpv6)
		pkt_tcp=pkt.get_protocol(tcp.tcp)
		pkt_udp=pkt.get_protocol(udp.udp)
		if pkt_eth:
			self.logger.info('ethernet : dst=%s  ethertype=0x%4x src=%s'%(pkt_eth.dst,pkt_eth.ethertype,pkt_eth.src))
		if pkt_ipv6:
			self.logger.info('   ipv6  : version=%d  src=%s dst=%s'%(pkt_ipv6.version,pkt_ipv6.src,pkt_ipv6.dst))
		if pkt_icmpv6:
			self.logger.info('  icmpv6 : code=%s  data=%s'%(pkt_icmpv6.code,pkt_icmpv6.data))
		if pkt_tcp:
			self.logger.info('   tcp   :src_port=%d  dst_port=%d  seq=%d'%(pkt_tcp.src_port,pkt_tcp.dst_port,pkt_tcp.seq))
		if pkt_udp:
			self.logger.info('   udp   :src_port=%d  dst_port=%d'%(pkt_udp.src_port,pkt_udp.dst_port))
		self.logger.info('---------------------------------------------')
		
































