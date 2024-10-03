from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet, ethernet
from ryu.topology.api import get_switch, get_link
from ryu.topology import event
from ryu.topology.switches import Switches  # Import switches module for topology discovery

class SpanningTreeLearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SpanningTreeLearningSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}  # MAC to port mapping
        self.graph = {}  # Network topology graph
        self.spanning_tree = {}  # Spanning tree
        self.tree_computed = False  # Flag to check if spanning tree is computed
        self.topology_api_app = self  # Register topology app

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.in_port

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP packets to avoid processing them
        if eth.ethertype == 0x88cc:
            return

        src = eth.src
        dst = eth.dst
        dpid = datapath.id

        # Learn the source MAC to avoid flooding next time
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(in_port=in_port, dl_dst=dst, dl_src=src)
            self.add_flow(datapath, match, actions)
        else:
            # Handle broadcast packets
            if eth.dst == "ff:ff:ff:ff:ff:ff":
                # Compute the spanning tree if it hasn't been done
                if not self.tree_computed:
                    self.compute_spanning_tree()
                    self.tree_computed = True
                # Broadcast only on open ports in the spanning tree
                self.broadcast(datapath, msg, in_port)
                return
            else:
                # Flood if destination MAC is not known
                out_port = ofproto.OFPP_FLOOD

        # Forward the packet
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=msg.data
        )
        datapath.send_msg(out)

    def add_flow(self, datapath, match, actions):
        """Add a flow entry."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0, command=ofproto.OFPFC_ADD,
            idle_timeout=0, hard_timeout=0, priority=1, flags=ofproto.OFPFF_SEND_FLOW_REM,
            actions=actions
        )
        datapath.send_msg(mod)

    @set_ev_cls(event.EventSwitchEnter)
    def _get_topology_data(self, ev):
        """Listen to topology changes and build the graph."""
        self.graph.clear()  # Clear old topology data
        switches = get_switch(self, None)
        links = get_link(self, None)

        # Add switches and links to the graph
        for sw in switches:
            self.graph[sw.dp.id] = []

        for link in links:
            self.graph[link.src.dpid].append((link.dst.dpid, link.src.port_no))
            self.graph[link.dst.dpid].append((link.src.dpid, link.dst.port_no))

        self.logger.info("Topology graph: %s", self.graph)

    def compute_spanning_tree(self):
        """Compute the spanning tree using Prim's algorithm or a simple BFS."""
        visited = set()
        root = list(self.graph.keys())[0]  # Arbitrarily select the first node as root
        visited.add(root)
        self.spanning_tree[root] = []

        while len(visited) < len(self.graph):
            min_edge = None
            for node in visited:
                for neighbor, port in self.graph[node]:
                    if neighbor not in visited:
                        if min_edge is None or (node, neighbor) < min_edge:
                            min_edge = (node, neighbor, port)
            if min_edge:
                u, v, port = min_edge
                self.spanning_tree.setdefault(u, []).append((v, port))
                self.spanning_tree.setdefault(v, []).append((u, port))
                visited.add(v)

        self.logger.info("Spanning tree constructed: %s", self.spanning_tree)

    def broadcast(self, datapath, msg, in_port):
        """Forward broadcast packets only to the links in the spanning tree."""
        dpid = datapath.id
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Get neighbors in the spanning tree
        neighbors = self.spanning_tree.get(dpid, [])

        for neighbor, out_port in neighbors:
            if out_port != in_port:
                actions = [parser.OFPActionOutput(out_port)]
                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id,
                    in_port=in_port, actions=actions, data=msg.data
                )
                datapath.send_msg(out)
