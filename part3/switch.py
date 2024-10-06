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
        self.mac_to_port = {}
        self.topology_api_app = kwargs['topology_api_app']
        self.topology = defaultdict(dict)
        self.hosts = {}
        self.lldp_delay = {}  # To store LLDP timestamps for delay calculation
        self.discovery_complete = False
        self.start_time = time.time()
        self.lldp_thread = None

        self.link_to_port = {}  # For storing port mappings between switches

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
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """Install a flow entry on the switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
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
            self.logger.info(
                f"Sending LLDP packets at time {time.time() - self.start_time}")
            switches = get_all_switch(self.topology_api_app)
            for switch in switches:
                self.send_lldp(switch.dp)
            hub.sleep(self.LLDP_PERIOD)

            if time.time() - self.start_time > self.LLDP_INTERVAL:
                self.logger.info("Link discovery complete at time(sec): %s",
                                 time.time() - self.start_time)
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
        """Handle incoming packets, including LLDP and ARP packets."""
        msg = ev.msg
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # Process LLDP packets for delay calculation
            self.handle_lldp_packet(msg, pkt)
            return

        # Ignore IPv6 multicast packets (destination MAC starting with 33:33)
        if eth.dst.startswith('33:33'):
            # These are IPv6 multicast packets; we can choose to flood or drop them
            # For now, we'll ignore them
            return

        src_mac = eth.src
        dst_mac = eth.dst
        dpid = datapath.id
        in_port = msg.match['in_port']

        # Ignore packets with invalid MAC addresses
        if src_mac == 'ff:ff:ff:ff:ff:ff':
            return

        # Learn the source MAC address
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        # Add source host to hosts mapping if not already present
        if src_mac not in self.hosts or self.hosts[src_mac][0] is None:
            self.hosts[src_mac] = (dpid, in_port)
            self.logger.info(f"Learned MAC {src_mac} on Switch {dpid}, Port {in_port}")

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            # Handle ARP packets separately
            self.handle_arp(msg, pkt)
            return

        # Handle traffic after discovery is complete
        if self.discovery_complete:
            self.handle_unicast(msg, pkt)

    def handle_lldp_packet(self, msg, pkt):
        """Process LLDP packet and calculate the one-way link delay."""
        datapath = msg.datapath
        lldp_pkt = pkt.get_protocol(lldp.lldp)
        in_port = msg.match['in_port']

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
            key = (chassis_id, port_id)

            if key in self.lldp_delay:
                delay = time.time() - self.lldp_delay[key]
                self.logger.info(
                    f"One-way delay from Switch {chassis_id} to Switch {datapath.id}: {1000 * delay:.6f} milliseconds")
                # Store the delay
                self.topology[chassis_id][datapath.id] = delay
                self.topology[datapath.id][chassis_id] = delay  # Assuming symmetric delay

                # Store the port mappings
                self.link_to_port.setdefault(chassis_id, {})
                self.link_to_port[chassis_id][datapath.id] = (port_id, in_port)  # (src_port, dst_port)
                self.link_to_port.setdefault(datapath.id, {})
                self.link_to_port[datapath.id][chassis_id] = (in_port, port_id)

    def handle_arp(self, msg, pkt):
        """Handle ARP packets to prevent continuous flooding."""
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)

        src_mac = eth.src
        dst_mac = eth.dst
        src_ip = arp_pkt.src_ip
        dst_ip = arp_pkt.dst_ip

        # Learn the source MAC and IP
        self.hosts[src_mac] = (dpid, in_port)

        # Check if we know the destination MAC for the requested IP
        dst_mac_known = False
        for mac, (dpid_dst, port_dst) in self.hosts.items():
            if mac != src_mac and mac != 'ff:ff:ff:ff:ff:ff':
                # Assuming unique MAC addresses for hosts
                dst_mac_known = True
                break

        if dst_mac_known and self.discovery_complete:
            # Install flow entries for ARP packets
            self.install_arp_flow(datapath)
            # Forward the ARP packet along the path
            self.handle_unicast(msg, pkt)
        else:
            # Flood the ARP packet
            self.logger.info(f"Flooding ARP packet from {src_mac} at Switch {dpid}")
            out_port = datapath.ofproto.OFPP_FLOOD
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                in_port=in_port, actions=actions, data=msg.data)
            datapath.send_msg(out)

    def install_arp_flow(self, datapath):
        """Install flow entries to handle ARP packets."""
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 1, match, actions)

    def handle_unicast(self, msg, pkt):
        """Handle unicast packets after shortest paths are computed."""
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        src = eth.src
        dpid = msg.datapath.id
        in_port = msg.match['in_port']

        # Ignore multicast destination MAC addresses
        if self.is_multicast_mac(dst):
            # Handle multicast packets accordingly
            # For simplicity, we'll flood multicast packets
            self.logger.info(f"Flooding multicast packet from {src} to {dst} at Switch {dpid}")
            out_port = msg.datapath.ofproto.OFPP_FLOOD

            actions = [msg.datapath.ofproto_parser.OFPActionOutput(out_port)]
            out = msg.datapath.ofproto_parser.OFPPacketOut(
                datapath=msg.datapath, buffer_id=msg.buffer_id,
                in_port=in_port, actions=actions, data=msg.data)
            msg.datapath.send_msg(out)
            return

        self.mac_to_port.setdefault(dpid, {})

        # Learn the source MAC address
        self.mac_to_port[dpid][src] = in_port

        # Add source host to hosts mapping if not already present
        if src not in self.hosts or self.hosts[src][0] is None:
            self.hosts[src] = (dpid, in_port)
            self.logger.info(f"Learned MAC {src} on Switch {dpid}, Port {in_port}")

        # Learn the destination MAC address if possible
        if dst not in self.hosts:
            # Destination host not known yet; add it with unknown location
            self.hosts[dst] = (None, None)
            self.logger.info(f"Destination MAC {dst} is unknown, added to hosts with unknown location")

        dst_info = self.hosts.get(dst)
        if dst_info and dst_info[0] is not None:
            dst_dpid, dst_port = dst_info
            path_info = self.paths.get(dpid, {}).get(dst_dpid)
            if path_info:
                path = path_info[0]  # Get the path list
                self.logger.info(f"Installing path from {src} to {dst}: {path}")
                # Install flow entries along the path (both directions)
                self.install_path(path, src, dst)
                # Determine the next hop and output port
                if dpid == dst_dpid:
                    out_port = dst_port
                else:
                    next_hop = path[path.index(dpid) + 1]
                    out_port = self.link_to_port[dpid][next_hop][0]  # Port to next hop
            else:
                self.logger.warning(f"No path from Switch {dpid} to Switch {dst_dpid}")
                out_port = msg.datapath.ofproto.OFPP_FLOOD
                self.logger.info(f"Flooding packet from {src} to {dst} at Switch {dpid} (no path found)")
        else:
            # Destination MAC unknown or not learned yet, flood the packet
            self.logger.info(f"Flooding packet from {src} to {dst} at Switch {dpid} (destination unknown)")
            out_port = msg.datapath.ofproto.OFPP_FLOOD

        actions = [msg.datapath.ofproto_parser.OFPActionOutput(out_port)]
        out = msg.datapath.ofproto_parser.OFPPacketOut(
            datapath=msg.datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=msg.data)
        msg.datapath.send_msg(out)

    def install_path(self, path, src_mac, dst_mac):
        """Install flow entries along the path (both directions)."""

        # Install forward path (from src to dst)
        self.logger.info(f"Installing forward path from {src_mac} to {dst_mac}: {path}")
        for i in range(len(path) - 1):
            curr_switch = path[i]
            next_switch = path[i + 1]
            datapath = self.datapaths[curr_switch]
            out_port = self.link_to_port[curr_switch][next_switch][0]  # Port to next hop
            match = datapath.ofproto_parser.OFPMatch(eth_dst=dst_mac)
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)

        # Handle the last switch in the path (destination switch)
        dest_switch = path[-1]
        datapath = self.datapaths[dest_switch]
        dst_port = self.hosts[dst_mac][1] if self.hosts[dst_mac][1] else datapath.ofproto.OFPP_FLOOD
        match = datapath.ofproto_parser.OFPMatch(eth_dst=dst_mac)
        actions = [datapath.ofproto_parser.OFPActionOutput(dst_port)]
        self.add_flow(datapath, 1, match, actions)

        # Install reverse path (from dst to src)
        reverse_path = list(reversed(path))
        self.logger.info(f"Installing reverse path from {dst_mac} to {src_mac}: {reverse_path}")
        for i in range(len(reverse_path) - 1):
            curr_switch = reverse_path[i]
            next_switch = reverse_path[i + 1]
            datapath = self.datapaths[curr_switch]
            out_port = self.link_to_port[curr_switch][next_switch][0]  # Port to next hop
            match = datapath.ofproto_parser.OFPMatch(eth_dst=src_mac)
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)

        # Handle the last switch in the reverse path (source switch)
        src_switch = reverse_path[-1]
        datapath = self.datapaths[src_switch]
        src_port = self.hosts[src_mac][1] if self.hosts[src_mac][1] else datapath.ofproto.OFPP_FLOOD
        match = datapath.ofproto_parser.OFPMatch(eth_dst=src_mac)
        actions = [datapath.ofproto_parser.OFPActionOutput(src_port)]
        self.add_flow(datapath, 1, match, actions)

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
                weight = self.topology[current_node][neighbor]
                if weight is None:
                    continue  # Skip if delay not measured yet
                distance = current_distance + weight
                if distance < distances[neighbor]:
                    distances[neighbor] = distance
                    previous[neighbor] = current_node
                    heapq.heappush(queue, (distance, neighbor))

        paths = {}
        for dest in self.topology:
            if distances[dest] < float('inf'):
                path = self.build_path(previous, dest)
                paths[dest] = (path, distances[dest])
        return paths

    def print_shortest_paths(self):
        """Print the shortest paths between all pairs of switches."""
        self.logger.info("\nShortest paths between all pairs of switches:")
        for src in sorted(self.paths.keys()):
            for dest in sorted(self.paths[src].keys()):
                if src != dest:
                    path, total_delay = self.paths[src][dest]
                    self.logger.info(
                        f"Shortest path from Switch {src} to Switch {dest}: {path} with total delay {1000 * total_delay:.6f} milliseconds")

    def build_path(self, previous, dest):
        """Build the path based on Dijkstra's output."""
        path = []
        while dest is not None:
            path.insert(0, dest)
            dest = previous[dest]
        return path

    def is_multicast_mac(self, mac_address):
        """Check if a MAC address is a multicast address."""
        first_octet = int(mac_address.split(":")[0], 16)
        return (first_octet & 1) == 1
