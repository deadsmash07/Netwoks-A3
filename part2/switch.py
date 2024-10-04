from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.topology import event
from ryu.topology import switches
from ryu.topology.api import get_all_switch, get_all_link, get_all_host
from collections import deque
from ryu.lib import hub

class SpanningTreeSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'topology_api_app': switches.Switches}

    def __init__(self, *args, **kwargs):
        super(SpanningTreeSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.spanning_tree = {}
        self.datapaths = {}
        self.topology = {}
        self.spanning_tree_computed = False
        self.topology_api_app = kwargs['topology_api_app']
        self.lock = hub.Event()  # This can be removed if not used elsewhere

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install the table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        self.datapaths[dpid] = datapath
        self.logger.info(f"Switch {dpid} connected.")

    def add_flow(self, datapath, priority, match, actions, table_id=0, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow mod message
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath, buffer_id=buffer_id, priority=priority,
                match=match, instructions=inst, table_id=table_id)
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority, match=match,
                instructions=inst, table_id=table_id)
        datapath.send_msg(mod)

    @set_ev_cls(event.EventSwitchEnter)
    @set_ev_cls(event.EventLinkAdd)
    def _topology_discovered(self, ev):
        """Wait a few seconds after link discovery before computing the spanning tree"""
        if not self.spanning_tree_computed:
            hub.spawn_after(5, self.compute_spanning_tree)

    def compute_spanning_tree(self):
        self.logger.info("Computing spanning tree...")
        switches = get_all_switch(self.topology_api_app)
        links = get_all_link(self.topology_api_app)
        hosts = get_all_host(self.topology_api_app)

        self.logger.info(f"Discovered Switches: {[s.dp.id for s in switches]}")
        self.logger.info(f"Discovered Links: {[(l.src.dpid, l.dst.dpid) for l in links]}")
        self.logger.info(f"Discovered Hosts: {[(h.mac, h.port.dpid) for h in hosts]}")

        if not switches or not links:
            self.logger.error("No topology discovered. Aborting spanning tree computation.")
            return

        self.topology.clear()
        self.spanning_tree.clear()

        # Build the network graph
        for link in links:
            s1 = link.src.dpid
            s2 = link.dst.dpid
            src_port = link.src.port_no
            dst_port = link.dst.port_no
            self.topology.setdefault(s1, []).append((s2, src_port, dst_port))
            self.topology.setdefault(s2, []).append((s1, dst_port, src_port))

        for host in hosts:
            host_mac = host.mac
            host_port = host.port.port_no
            dpid = host.port.dpid
            self.topology.setdefault(dpid, []).append((host_mac, host_port, None))

        visited = set()
        root = min(self.topology.keys())  # Choose the switch with the lowest DPID as root
        self.logger.info(f"Root of Spanning Tree: Switch {root}")

        queue = deque([root])
        visited.add(root)

        while queue:
            node = queue.popleft()
            for neighbor, src_port, dst_port in self.topology[node]:
                if isinstance(neighbor, int) and neighbor not in visited:  # Handle switch neighbors
                    visited.add(neighbor)
                    self.spanning_tree.setdefault(node, []).append((neighbor, src_port))
                    self.spanning_tree.setdefault(neighbor, []).append((node, dst_port))
                    queue.append(neighbor)
                elif not isinstance(neighbor, int):  # Handle host neighbors
                    self.spanning_tree.setdefault(node, []).append((neighbor, src_port))

        self.spanning_tree_computed = True
        self.logger.info("Spanning Tree Computed:")
        for switch, neighbors in self.spanning_tree.items():
            self.logger.info(f"Switch {switch}: {neighbors}")

        # Install flow entries to block non-spanning tree links
        self.install_spanning_tree_flows()

    def install_spanning_tree_flows(self):
        for dpid, datapath in self.datapaths.items():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            # Get all ports connected to other switches
            all_ports = set()
            if dpid in self.topology:
                for neighbor, src_port, dst_port in self.topology[dpid]:
                    if isinstance(neighbor, int):
                        all_ports.add(src_port)

            # Get ports in the spanning tree
            tree_ports = set()
            if dpid in self.spanning_tree:
                for neighbor, port_no in self.spanning_tree[dpid]:
                    if isinstance(neighbor, int):
                        tree_ports.add(port_no)

            # Block ports not in the spanning tree
            blocked_ports = all_ports - tree_ports
            for port_no in blocked_ports:
                # Install a drop flow for packets coming from blocked ports
                match = parser.OFPMatch(in_port=port_no)
                actions = []
                self.add_flow(datapath, 10, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # Implement packet handling logic here, such as MAC learning
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        # Learn the source MAC to avoid flooding next time
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # Decide the output port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            # Flood if destination is unknown
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions)

        # Send packet out
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)
