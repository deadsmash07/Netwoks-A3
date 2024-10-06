from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology import switches
from ryu.lib.packet import packet, ethernet, lldp, ether_types, arp
from ryu.topology.api import get_all_switch
from collections import defaultdict
from ryu.lib import hub
import time

class ShortestPathSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'topology_api_app': switches.Switches}

    LLDP_PERIOD = 2  # Send LLDP packets every 2 seconds
    LLDP_INTERVAL = 10  # Run LLDP for 10 seconds to measure delays
    DISCOVERY_WAIT_TIME = 10  # Wait 10 seconds for topology discovery

    def __init__(self, *args, **kwargs):
        super(ShortestPathSwitch, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.mac_to_port = {}  # Mapping of switch DPID to {MAC: port}
        self.topology_api_app = kwargs['topology_api_app']
        self.topology = defaultdict(dict)  # Nested dict to store link info
        self.hosts = {}  # Mapping of host MAC to (switch DPID, port)
        self.lldp_delay = {}  # To store LLDP timestamps for delay calculation
        self.link_to_port = {}  # Mapping of links to ports: {(src_dpid, dst_dpid): (src_port, dst_port)}
        self.discovery_complete = False
        self.start_time = time.time()
        self.lldp_thread = None
        self.LINK_DISCOVERY = True

        # Start LLDP measurement after waiting for 10 seconds to allow topology discovery
        self.monitor_thread = hub.spawn(self._wait_for_discovery)

    def _wait_for_discovery(self):
        """Wait for 10 seconds for topology discovery before starting LLDP measurement."""
        self.logger.info("Waiting for topology discovery for 10 seconds.")
        hub.sleep(self.DISCOVERY_WAIT_TIME)  # Wait for discovery to complete

        self.logger.info("Starting LLDP measurement after discovery wait.")
        # Start the LLDP packet sending in a separate thread
        self.lldp_thread = hub.spawn(self._send_lldp_packets)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch features reply and install table-miss flow entry."""
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        # Install table-miss flow entry
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """Add a flow entry to the switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id and buffer_id != ofproto.OFP_NO_BUFFER:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority,
                                    match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def _send_lldp_packets(self):
        """LLDP packet sending thread for link delay measurement."""
        while True:
            self.logger.info(f"Sending LLDP packets at time {time.time() - self.start_time}")
            switches = get_all_switch(self.topology_api_app)
            for switch in switches:
                self.send_lldp(switch.dp)
            hub.sleep(self.LLDP_PERIOD)

            if time.time() - self.start_time > self.LLDP_INTERVAL:
                self.LINK_DISCOVERY = False
                self.logger.info("Link discovery complete at time(sec): %s", time.time() - self.start_time)
                self.create_shortest_path_tree()
                self.lldp_thread = None
                break

    def send_lldp(self, datapath):
        """Send LLDP packets to measure link delays."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for port_no in datapath.ports:
            if port_no > ofproto.OFPP_MAX:
                continue
            # Build and send LLDP packet
            pkt = self.build_lldp_packet(datapath, port_no)
            actions = [parser.OFPActionOutput(port_no)]
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=ofproto.OFPP_CONTROLLER,
                                      actions=actions,
                                      data=pkt.data)
            datapath.send_msg(out)
            key = (datapath.id, port_no)
            self.lldp_delay[key] = time.time()  # Record timestamp for delay calculation

    def build_lldp_packet(self, datapath, port_no):
        """Build an LLDP packet with a timestamp."""
        dpid = datapath.id
        eth = ethernet.ethernet(
            dst=lldp.LLDP_MAC_NEAREST_BRIDGE,
            src=datapath.ports[port_no].hw_addr,
            ethertype=ether_types.ETH_TYPE_LLDP
        )

        chassis_id = lldp.ChassisID(
            subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED,
            chassis_id=('dpid:%016x' % dpid).encode('utf-8')
        )
        port_id = lldp.PortID(
            subtype=lldp.PortID.SUB_LOCALLY_ASSIGNED,
            port_id=('port:%d' % port_no).encode('utf-8')
        )
        ttl = lldp.TTL(ttl=120)

        tlvs = (chassis_id, port_id, ttl, lldp.End())
        lldp_pkt = packet.Packet()
        lldp_pkt.add_protocol(eth)
        lldp_pkt.add_protocol(lldp.lldp(tlvs))
        lldp_pkt.serialize()

        return lldp_pkt

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle incoming packets, including LLDP packets for delay measurement."""
        msg = ev.msg
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dpid = datapath.id
        in_port = msg.match['in_port']

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # Process LLDP packets for delay calculation
            self.handle_lldp_packet(msg, pkt)
            return

        # Ignore IPv6 multicast packets (e.g., MLD packets)
        if eth.dst.startswith('33:33'):
            return

        # Learn the source MAC address to avoid FLOOD next time
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        # Add host to self.hosts if not already known
        if eth.src not in self.hosts:
            self.hosts[eth.src] = (dpid, in_port)
            self.logger.info(f"Host {eth.src} is attached to Switch {dpid}, Port {in_port}")

        # Handle packets after discovery is complete
        if self.discovery_complete:
            self.handle_packet_in(msg, pkt)

    def handle_lldp_packet(self, msg, pkt):
        """Process LLDP packet and calculate the one-way link delay."""
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']
        lldp_pkt = pkt.get_protocol(lldp.lldp)

        chassis_id = None
        port_id = None

        # Extract chassis ID and port ID from LLDP packet
        for tlv in lldp_pkt.tlvs:
            if isinstance(tlv, lldp.ChassisID):
                chassis_id_bytes = tlv.chassis_id
                chassis_id_str = chassis_id_bytes.decode('utf-8')
                if chassis_id_str.startswith('dpid:'):
                    # Strip the 'dpid:' prefix and convert from hex to int
                    chassis_id = int(chassis_id_str[5:], 16)
            elif isinstance(tlv, lldp.PortID):
                port_id_bytes = tlv.port_id
                port_id_str = port_id_bytes.decode('utf-8')
                if port_id_str.startswith('port:'):
                    # Strip the 'port:' prefix and convert to int
                    port_id = int(port_id_str[5:])

        if chassis_id is not None and port_id is not None:
            src_dpid = chassis_id
            src_port = port_id
            dst_dpid = dpid
            dst_port = in_port
            key = (src_dpid, src_port)

            if key in self.lldp_delay:
                delay = time.time() - self.lldp_delay[key]
                self.logger.info(f"One-way delay from Switch {src_dpid} to Switch {dst_dpid}: {1000 * delay:.6f} milliseconds")
                # Store link information with delay and port numbers
                self.topology[src_dpid][dst_dpid] = {'delay': delay, 'src_port': src_port, 'dst_port': dst_port}
                self.link_to_port[(src_dpid, dst_dpid)] = (src_port, dst_port)

    def create_shortest_path_tree(self):
        """Compute shortest paths using Dijkstra's algorithm based on LLDP delays."""
        self.logger.info("Creating shortest path tree using calculated delays.")
        self.paths = {}
        for src in self.topology:
            self.paths[src] = self.dijkstra(src)
        self.discovery_complete = True

        # Print the shortest paths
        self.print_shortest_paths()

    def dijkstra(self, src):
        """Dijkstra's algorithm to compute shortest paths."""
        import heapq
        distances = {node: float('inf') for node in self.topology}
        previous = {node: None for node in self.topology}
        distances[src] = 0
        queue = [(0, src)]

        while queue:
            current_distance, current_node = heapq.heappop(queue)

            if current_distance > distances[current_node]:
                continue

            for neighbor in self.topology[current_node]:
                link_info = self.topology[current_node][neighbor]
                delay = link_info['delay']
                distance = current_distance + delay
                if distance < distances[neighbor]:
                    distances[neighbor] = distance
                    previous[neighbor] = current_node
                    heapq.heappush(queue, (distance, neighbor))

        paths = {}
        for dest in self.topology:
            if distances[dest] < float('inf'):
                path = self.build_path(previous, dest)
                paths[dest] = path
        return paths

    def print_shortest_paths(self):
        """Print the shortest paths between all pairs of switches."""
        self.logger.info("\nShortest paths between all pairs of switches:")
        for src in sorted(self.paths.keys()):
            for dest in sorted(self.paths[src].keys()):
                if src != dest:
                    path = self.paths[src][dest]
                    total_delay = sum(self.topology[path[i]][path[i + 1]]['delay'] for i in range(len(path) - 1))
                    self.logger.info(f"Shortest path from Switch {src} to Switch {dest}: {path} with total delay {1000 * total_delay:.6f} milliseconds")

    def build_path(self, previous, dest):
        """Build the path based on Dijkstra's output."""
        path = []
        while dest is not None:
            path.insert(0, dest)
            dest = previous[dest]
        return path

    def handle_packet_in(self, msg, pkt):
        """Handle incoming packets after shortest paths are computed."""
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        src = eth.src
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # If destination MAC is known, compute path
        if dst in self.hosts:
            dst_dpid, dst_port = self.hosts[dst]
            path = self.paths.get(dpid, {}).get(dst_dpid)
            if path:
                # Install flow entries along the path
                self.install_path(path, src, dst)
                # Get the next hop in the path and the output port
                if dpid != dst_dpid:
                    next_hop = path[path.index(dpid) + 1]
                    out_port = self.link_to_port[(dpid, next_hop)][0]
                else:
                    # If the packet is already at the destination switch
                    out_port = dst_port
            else:
                out_port = ofproto.OFPP_FLOOD
        else:
            out_port = ofproto.OFPP_FLOOD

        # Send packet out
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)

    def install_path(self, path, src_mac, dst_mac):
        """Install flow entries along the path."""
        for i in range(len(path) - 1):
            dpid = path[i]
            next_dpid = path[i + 1]
            datapath = self.datapaths[dpid]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            # Get the output port to the next switch
            out_port = self.link_to_port[(dpid, next_dpid)][0]
            # Get the input port from the previous switch
            if i == 0:
                in_port = self.mac_to_port[dpid][src_mac]
            else:
                prev_dpid = path[i - 1]
                in_port = self.link_to_port[(dpid, prev_dpid)][1]

            # Install flow entry
            match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)

        # Install flow entry on the destination switch
        dst_dpid = path[-1]
        datapath = self.datapaths[dst_dpid]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        out_port = self.mac_to_port[dst_dpid][dst_mac]
        if len(path) > 1:
            in_port = self.link_to_port[(dst_dpid, path[-2])][1]
        else:
            in_port = self.mac_to_port[dst_dpid][src_mac]
        match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
        actions = [parser.OFPActionOutput(out_port)]
        self.add_flow(datapath, 1, match, actions)
