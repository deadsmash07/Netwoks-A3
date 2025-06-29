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
        self.host_ports = {}  
        self.spanning_tree_computed = False
        self.topology_api_app = kwargs['topology_api_app']

        #  a 10 second timer to compute the spanning tree once all switches are connected
        hub.spawn_after(10, self.compute_spanning_tree)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        self.datapaths[dpid] = datapath
        self.logger.info(f"Switch {dpid} connected.")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority,
                                    match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def compute_spanning_tree(self):
        self.logger.info("Computing spanning tree after waiting for 10 seconds...")
        switches = get_all_switch(self.topology_api_app)
        links = get_all_link(self.topology_api_app)
        hosts = get_all_host(self.topology_api_app)

        self.store_host_ports(hosts)

        self.logger.info(f"Discovered Switches: {[s.dp.id for s in switches]}")
        self.logger.info(f"Discovered Links: {[(l.src.dpid, l.dst.dpid) for l in links]}")
        self.logger.info(f"Discovered Hosts: {[(h.mac, h.port.dpid) for h in hosts]}")

        if not switches or not links:
            self.logger.error("No topology discovered. Aborting spanning tree computation.")
            return

        self.topology.clear()
        self.spanning_tree.clear()

        # building the network graph using only switches and links between switches
        for link in links:
            s1 = link.src.dpid
            s2 = link.dst.dpid
            src_port = link.src.port_no
            dst_port = link.dst.port_no
            self.topology.setdefault(s1, []).append((s2, src_port, dst_port))
            self.topology.setdefault(s2, []).append((s1, dst_port, src_port))

        # taking the switch with the lowest DPID as root
        visited = set()
        root = min(self.topology.keys())
        self.logger.info(f"Root of Spanning Tree: Switch {root}")

        #using BFS to compute the spanning tree
        queue = deque([root])
        visited.add(root)

        while queue:
            node = queue.popleft()
            for neighbor, src_port, dst_port in self.topology[node]:
                if isinstance(neighbor, int) and neighbor not in visited:
                    visited.add(neighbor)
                    self.spanning_tree.setdefault(node, []).append((neighbor, src_port))
                    self.spanning_tree.setdefault(neighbor, []).append((node, dst_port))
                    queue.append(neighbor)

        self.spanning_tree_computed = True
        self.logger.info("Spanning Tree Computed:")
        for switch, neighbors in self.spanning_tree.items():
            self.logger.info(f"Switch {switch}: {neighbors}")

        # intalling flow entries to block non-spanning tree links
        self.install_spanning_tree_flows()

    def store_host_ports(self, hosts):
        """Store the ports where hosts are connected."""
        for host in hosts:
            host_mac = host.mac
            host_port = host.port.port_no
            dpid = host.port.dpid
            self.host_ports.setdefault(dpid, []).append((host_mac, host_port))

    def install_spanning_tree_flows(self):
        for dpid, datapath in self.datapaths.items():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            all_ports = set()
            if dpid in self.topology:
                for neighbor, src_port, dst_port in self.topology[dpid]:
                    if isinstance(neighbor, int):
                        all_ports.add(src_port)

            tree_ports = set()
            if dpid in self.spanning_tree:
                for neighbor, port_no in self.spanning_tree[dpid]:
                    if isinstance(neighbor, int):
                        tree_ports.add(port_no)

            # blocking ports not in the spanning tree
            blocked_ports = all_ports - tree_ports
            for port_no in blocked_ports:
                match = parser.OFPMatch(in_port=port_no)
                actions = []
                self.add_flow(datapath, 10, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        # learning the source MAC to avoid flooding next time
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            # do flooding if destination MAC is not in the MAC table
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # installing flow to avoid packet_in next time if the out_port is not flood
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions)

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)
