from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
## Note: this code uses verision 1 of openflow protocol because the given topo file is not compatible with version3
class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.in_port  # OpenFlow 1.0 uses msg.in_port, not msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # ignoring LLDP packets
        if eth.ethertype == 0x88cc:
            return

        # the source and destination MAC addresses
        src = eth.src
        dst = eth.dst
        dpid = datapath.id

        # learning the source MAC address to avoid flooding next time
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # If the destination MAC is known, forward the packet to the correct port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            # else, flood the packet
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, dl_dst=dst, dl_src=src)  # OpenFlow 1.0 uses dl_dst and dl_src
            self.add_flow(datapath, match, actions)

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=msg.data
        )
        datapath.send_msg(out)

    def add_flow(self, datapath, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # OpenFlow 1.0 does not have instructions; use actions directly in the flow mod
        mod = parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0, command=ofproto.OFPFC_ADD,
            idle_timeout=0, hard_timeout=0, priority=1, flags=ofproto.OFPFF_SEND_FLOW_REM,
            actions=actions  # actions are added directly here
        )
        datapath.send_msg(mod)
