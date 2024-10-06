from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import packet, ethernet, ether_types, arp
from ryu.topology import event
from ryu.topology import switches
from ryu.topology.api import get_all_switch, get_all_link, get_all_host
from collections import defaultdict
from ryu.lib import hub
import time

class ShortestPathSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'topology_api_app': switches.Switches}

    def __init__(self, *args, **kwargs):
        super(ShortestPathSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = kwargs['topology_api_app']
        self.datapaths = {}
        self.topology = defaultdict(dict)
        self.paths = {}
        self.hosts = {}
        self.lldp_delay = {}  # To store LLDP timestamps
        self.discovery_complete = False
        self.lldp_measurement_started = False  # Flag to indicate LLDP measurements have started
        self.switches = []
        self.links = []
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        # Install table-miss flow entry
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id and buffer_id != ofproto.OFP_NO_BUFFER:
            mod = parser.OFPFlowMod(
                datapath=datapath, buffer_id=buffer_id, priority=priority,
                match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority,
                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        self.logger.info("Switch entered. Gathering topology data.")
        switches = get_all_switch(self)
        self.switches = [switch.dp.id for switch in switches]

        # Clear previous topology data
        self.links.clear()
        self.topology.clear()

        links = get_all_link(self)
        for link in links:
            src = link.src.dpid
            dst = link.dst.dpid
            src_port = link.src.port_no
            dst_port = link.dst.port_no
            # Store the link information in both directions
            self.links.append((src, dst, {'src_port': src_port, 'dst_port': dst_port}))
            self.topology[src][dst] = {'port': src_port}
            self.topology[dst][src] = {'port': dst_port}  # For undirected graph

        # Discover hosts
        hosts = get_all_host(self)
        for host in hosts:
            self.hosts[host.mac] = (host.port.dpid, host.port.port_no)

        # Log discovered topology
        self.logger.info(f"Discovered Switches: {self.switches}")
        self.logger.info(f"Discovered Links: {self.links}")
        self.logger.info(f"Discovered Hosts: {list(self.hosts.keys())}")

    def _monitor(self):
        self.logger.info("Waiting for topology discovery to complete.")
        expected_switches = 4  # Adjust according to your topology
        expected_hosts = 4     # Adjust according to your topology

        # Wait for 10 seconds for topology discovery (switches, links, hosts)
        hub.sleep(10)

        # Check if discovery has completed
        while True:
            if len(self.switches) >= expected_switches and len(self.hosts) >= expected_hosts:
                break
            hub.sleep(1)  # Sleep for a short interval before checking again

        self.logger.info("All switches and hosts discovered. Starting LLDP measurements.")
        self.lldp_measurement_started = True  # Set flag to indicate LLDP measurements have started
        measurement_count = 0
        max_measurements = 1  # Only repeat LLDP measurements once

        while measurement_count < max_measurements:
            for dp in self.datapaths.values():
                self.send_lldp(dp)
            hub.sleep(10)  # Short interval between LLDP measurements
            measurement_count += 1

        # After measurements, calculate average delays
        self.calculate_average_delays()
        self.log_link_delays()

        # Compute shortest paths and enable packet forwarding
        self.compute_shortest_paths()
        self.discovery_complete = True
        self.logger.info("Discovery complete. Computed shortest paths.")

    def send_lldp(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        for port_no in datapath.ports:
            if port_no > ofproto.OFPP_MAX:
                continue
            # Build LLDP packet
            pkt = self.build_lldp_packet(datapath, port_no)
            # Send PacketOut message
            data = pkt.data
            actions = [parser.OFPActionOutput(port_no)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions,
                data=data)
            datapath.send_msg(out)
            # Record the timestamp with a key including src and port
            key = (datapath.id, port_no)
            self.lldp_delay[key] = time.time()

    def build_lldp_packet(self, datapath, port_no):
        from ryu.lib.packet import lldp

        dpid = datapath.id
        eth = ethernet.ethernet(
            dst=lldp.LLDP_MAC_NEAREST_BRIDGE,
            src=datapath.ports[port_no].hw_addr,
            ethertype=ether_types.ETH_TYPE_LLDP
        )

        chassis_id = lldp.ChassisID(
            subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED,
            chassis_id=str(dpid).encode('utf-8')
        )

        port_id = lldp.PortID(
            subtype=lldp.PortID.SUB_LOCALLY_ASSIGNED,
            port_id=str(port_no).encode('utf-8')
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
        if not self.discovery_complete:
            # Drop all packets until discovery is complete
            return

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # Ignore LLDP packets after discovery
            return

        # ARP Handling for host discovery
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt:
                src_mac = arp_pkt.src_mac
                src_ip = arp_pkt.src_ip
                self.hosts[src_mac] = (datapath.id, in_port)  # Learn host MAC to switch mapping
                self.logger.info(f"Discovered host: {src_mac} at {datapath.id}:{in_port}")
        
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Learn MAC address to avoid FLOOD next time
        self.mac_to_port[dpid][src] = in_port

        if dst in self.hosts:
            # Compute the path to the destination
            dst_dpid, dst_port = self.hosts[dst]
            path = self.paths.get(dpid, {}).get(dst_dpid)
            if path is None:
                self.logger.warning(f"No path from Switch {dpid} to Switch {dst_dpid}")
                out_port = ofproto.OFPP_FLOOD
            else:
                if len(path) > 1:
                    next_hop = path[1]
                    out_port = self.topology[dpid][next_hop]['port']
                else:
                    # Destination is directly connected
                    out_port = dst_port
                # Install flow entries along the path
                self.install_path_flow(src, dst, path)
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow to avoid future PacketIn events
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(eth_dst=dst)
            self.add_flow(datapath, priority=1, match=match, actions=actions)

        # Send the packet out
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)

    def calculate_average_delays(self):
        for src in self.topology:
            for dst in self.topology[src]:
                delays = self.topology[src][dst].get('delays', [])
                if delays:
                    avg_delay = sum(delays) / len(delays)
                    self.topology[src][dst]['delay'] = avg_delay
                else:
                    self.topology[src][dst]['delay'] = None  # If no delay was measured

    def log_link_delays(self):
        self.logger.info("\nCalculated Link Delays:")
        for src in sorted(self.topology.keys()):
            for dst in sorted(self.topology[src].keys()):
                if src < dst:  # To avoid duplicate entries
                    delay = self.topology[src][dst].get('delay')
                    if delay is not None:
                        self.logger.info(f"Switch {src} and Switch {dst}: {delay:.6f} seconds")
                    else:
                        self.logger.info(f"Switch {src} and Switch {dst}: Delay not measured")
        self.logger.info("\nReady for packet forwarding.")

    def compute_shortest_paths(self):
        self.paths = {}
        for src in self.topology:
            self.paths[src] = self.dijkstra(src)

    def dijkstra(self, src):
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
                edge = self.topology[current_node][neighbor]
                weight = edge.get('delay')
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
                paths[dest] = path
                self.logger.info(f"Shortest path from Switch {src} to Switch {dest}: {path} with distance {distances[dest]:.6f}")
        return paths

    def build_path(self, previous, dest):
        path = []
        while dest is not None:
            path.insert(0, dest)
            dest = previous[dest]
        return path

    def install_path_flow(self, src_mac, dst_mac, path):
        for i in range(len(path) - 1):
            curr_switch = path[i]
            next_switch = path[i + 1]
            datapath = self.datapaths[curr_switch]
            out_port = self.topology[curr_switch][next_switch]['port']
            match = datapath.ofproto_parser.OFPMatch(
                eth_dst=dst_mac)
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, priority=1, match=match, actions=actions)

        # Handle the last switch (destination switch)
        dest_switch = path[-1]
        if dest_switch in self.datapaths:
            datapath = self.datapaths[dest_switch]
            out_port = self.hosts[dst_mac][1]  # Host port on destination switch
            match = datapath.ofproto_parser.OFPMatch(
                eth_dst=dst_mac)
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, priority=1, match=match, actions=actions)
