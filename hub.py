from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

class HubController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(HubController, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)    
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.in_port  # For OFP v1.0, the field is msg.in_port, not msg.match['in_port']
        
        # Get the packet data
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        # Ignore LLDP packets
        if eth.ethertype == 0x88cc:
            return

        # Flood the packet to all ports
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        
        # Create the PacketOut message
        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=msg.data
        )
        dp.send_msg(out)
