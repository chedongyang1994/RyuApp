#OpenFlow Version:1.3
from operator import attrgetter

import switch_controller
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER,DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

class traffic_monitor(switch_controller.switch_controller):

	


	def __init__(self,*args,**kwargs):
		super(traffic_monitor,self).__init__(*args,**kwargs)
		self.datapaths={}
		self.monitor_thread=hub.spawn(self._monitor)

	@set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER,DEAD_DISPATCHER])
	def _state_change_handler(self,ev):
		datapath=ev.datapath
		if ev.state==MAIN_DISPATCHER:
			if datapath.id not in self.datapaths:
				self.logger.debug('register datapath:%016x',datapath.id)
				self.datapaths[datapath.id]=datapath
		elif ev.state==DEAD_DISPATCHER:
			if datapath.id in self.datapaths:
				self.logger.debug('unregister datapath:%016x',datapath.id)
				del self.datapaths[datapath.id]

	#send status requestion per 10 sec.
	def _monitor(self):
		while True:
			for dp in self.datapaths.values():
				self._request_status(dp)
			hub.sleep(10)

	def _request_status(self,datapath):
		self.logger.debug('sending stats request to :%016x',datapath.id)
		ofproto=datapath.ofproto
		parser=datapath.ofproto_parser

		req=parser.OFPPortStatsRequest(datapath,0,ofproto.OFPP_ANY)
		datapath.send_msg(req)
		
		req=parser.OFPFlowStatsRequest(datapath)
		datapath.send_msg(req)

	#get the reply
	@set_ev_cls(ofp_event.EventOFPFlowStatsReply,MAIN_DISPATCHER)
	def _flow_stats_reply_handler(self,ev):
		body=ev.msg.body	
		self.logger.info('datapath	'
				'     in-port  eth-dst     	'
				'out-port packets  bytes')
		self.logger.info('--------------'	
				'-------- -------- --------'
				'-------- -------- --------')
		for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            		self.logger.info('%016x %8x %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)
		
	@set_ev_cls(ofp_event.EventOFPPortStatsReply,MAIN_DISPATCHER)
	def _port_stats_reply_handler(self,ev):
		body=ev.msg.body

		self.logger.info('datapath	     port	'
				'rx-pkts rx-bytes rx-error '
				'tx-pkts tx-bytes tx-error')
		self.logger.info('--------------  --------'
				'------- -------- -------- '
				'------- -------- --------')
		for stat in sorted(body, key=attrgetter('port_no')):
            		self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)














