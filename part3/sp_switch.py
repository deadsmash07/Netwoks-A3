from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import packet, ethernet, ether_types
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
        self.link_delays = defaultdict(dict)
        self.paths = {}
        self.hosts = {}
        self.lldp_delay = {}  # To store LLDP timestamps
        self.discovery_complete = False
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
        self.discovery_complete = False
        switches = get_all_switch(self)
        self.switches = [switch.dp.id for switch in switches]
        links = get_all_link(self)
        self.links = []
        for link in links:
            src = link.src.dpid
            dst = link.dst.dpid
            src_port = link.src.port_no
            dst_port = link.dst.port_no
            self.links.append((src, dst, {'src_port': src_port, 'dst_port': dst_port}))
            self.topology[src][dst] = {'port': src_port, 'delay': None}
            self.topology[dst][src] = {'port': dst_port, 'delay': None}  # For undirected graph

        hosts = get_all_host(self)
        for host in hosts:
            self.hosts[host.mac] = (host.port.dpid, host.port.port_no)
        self.logger.info(f"Switches: {self.switches}")
        self.logger.info(f"Links: {self.links}")
        self.logger.info(f"Hosts: {self.hosts}")

    def _monitor(self):
        hub.sleep(10)  # Wait for the topology to be discovered
        self.logger.info("Starting LLDP measurements.")
        while not self.discovery_complete:
            for dp in self.datapaths.values():
                self.send_lldp(dp)
            hub.sleep(5)  # Adjust the interval as needed

            # After initial measurements, build the network graph and compute paths
            all_delays_measured = all(
                self.topology[src][dst]['delay'] is not None
                for src in self.topology
                for dst in self.topology[src]
            )
            if all_delays_measured:
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
            # Record the timestamp
            self.lldp_delay[(datapath.id, port_no)] = time.time()

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
        # Existing code...
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            self.handle_lldp_packet(msg, pkt, eth, in_port)
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Learn MAC address to avoid FLOOD next time
        self.mac_to_port[dpid][src] = in_port

        if not self.discovery_complete:
            self.logger.info("Discovery not complete. Flooding packet.")
            out_port = ofproto.OFPP_FLOOD
        else:
            if dst in self.hosts:
                # Compute the path to the destination
                dst_dpid, dst_port = self.hosts[dst]
                path = self.paths.get(dpid).get(dst_dpid)
                if path is None:
                    self.logger.warning(f"No path from {dpid} to {dst_dpid}")
                    out_port = ofproto.OFPP_FLOOD
                else:
                    if len(path) > 1:
                        next_hop = path[1]
                        out_port = self.topology[dpid][next_hop]['port']
                    else:
                        # Destination is directly connected
                        out_port = self.hosts[dst][1]
                    # Install flow entries along the path
                    self.install_path_flow(src, dst, path)
            else:
                out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow to avoid future PacketIn events
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, priority=1, match=match, actions=actions)

        # Send the packet out
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)

    def handle_lldp_packet(self, msg, pkt, eth, in_port):
        from ryu.lib.packet import lldp
        lldp_pkt = pkt.get_protocol(lldp.lldp)
        if lldp_pkt:
            try:
                src_dpid = int(lldp_pkt.tlvs[0].chassis_id.decode('utf-8'))
                src_port = int(lldp_pkt.tlvs[1].port_id.decode('utf-8'))
            except Exception as e:
                self.logger.error(f"Error parsing LLDP packet: {e}")
                return
            dst_dpid = msg.datapath.id
            dst_port = in_port

            key = (src_dpid, src_port)
            if key in self.lldp_delay:
                delay = time.time() - self.lldp_delay[key]
                # Update the delay in the topology
                if dst_dpid in self.topology[src_dpid]:
                    self.topology[src_dpid][dst_dpid]['delay'] = delay
                if src_dpid in self.topology[dst_dpid]:
                    self.topology[dst_dpid][src_dpid]['delay'] = delay  # Symmetric delay
                self.logger.info(
                    f"Measured delay between {src_dpid}-{src_port} and {dst_dpid}-{dst_port}: {delay}")
                # Remove the timestamp to avoid stale entries
                del self.lldp_delay[key]

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
                weight = edge['delay']
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
                self.logger.info(f"Shortest path from {src} to {dest}: {path} with distance {distances[dest]}")
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
                eth_src=src_mac, eth_dst=dst_mac)
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, priority=1, match=match, actions=actions)

        # Handle the last switch (destination switch)
        dest_switch = path[-1]
        if dest_switch in self.datapaths:
            datapath = self.datapaths[dest_switch]
            out_port = self.hosts[dst_mac][1]  # Host port on destination switch
            match = datapath.ofproto_parser.OFPMatch(
                eth_src=src_mac, eth_dst=dst_mac)
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, priority=1, match=match, actions=actions)

    # Additional methods if necessary
