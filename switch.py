from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)
        # MAC to port mapping (MAC address table)
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

        # Ignore LLDP packets
        if eth.ethertype == 0x88cc:
            return

        # Get the source and destination MAC addresses
        src = eth.src
        dst = eth.dst
        dpid = datapath.id

        # Learn the source MAC address to avoid flooding next time
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # If the destination MAC is known, forward the packet to the correct port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            # Otherwise, flood the packet
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow to avoid future packet-in events for this flow
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, dl_dst=dst, dl_src=src)  # OpenFlow 1.0 uses dl_dst and dl_src
            self.add_flow(datapath, match, actions)

        # Send the packet out
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
            actions=actions  # Actions are added directly here
        )
        datapath.send_msg(mod)
