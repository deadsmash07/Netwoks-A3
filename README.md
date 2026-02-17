# SDN-based Intelligent Network Controller

OpenFlow controller built with **Ryu** for proactive L2 learning, shortest-path routing, and loop prevention. Developed for **COL334 Computer Networks**, IIT Delhi.

**Stack:** Python, Ryu, OpenFlow 1.0/1.3, Mininet

## Repository Structure

### Part 1 -- Hub and Learning Switch (OpenFlow 1.0)

Baseline implementations on a two-switch, five-host topology.

- `part1/p1_hub.py` -- Simple hub controller that floods every packet to all ports.
- `part1/p1_learning.py` -- L2 learning switch with proactive MAC-to-port table and flow pre-installation (achieves ~18.5 Gbit/s on iperf).
- `part1/p1_topo.py` -- Mininet topology (2 switches, 5 hosts).

### Part 2 -- Spanning Tree for Loop Avoidance (OpenFlow 1.3)

Handles cyclic topologies by computing a spanning tree and blocking redundant ports.

- `part2/p2_spanning_tree.py` -- Ryu app that discovers the topology via LLDP, builds a BFS spanning tree rooted at the lowest-DPID switch, and installs drop rules on non-tree ports.
- `p2_topo.py` -- Four-switch ring topology with one host per switch.

### Part 3 -- Shortest-Path Routing with Delay Measurement (OpenFlow 1.3)

Optimal forwarding based on measured link latencies.

- `part3/p3_spr.py` -- Ryu app that performs LLDP-based active delay probing, runs Dijkstra's algorithm using measured one-way delays as link weights, and installs per-destination flow entries along computed shortest paths.
- `part3/switch.py` -- Supporting switch logic.
- `p3_topo.py` -- Four-switch ring with bandwidth/delay constraints (TCLink).

## Prerequisites

- Python 3.8+
- [Ryu](https://ryu-sdn.org/) SDN framework (`pip install ryu`)
- [Mininet](http://mininet.org/) 2.3+
- Open vSwitch

Or install all Python dependencies at once:

```bash
pip install -r requirements.txt
```

## Running

Each part requires two terminals: one for the Ryu controller, one for Mininet.

### Part 1

```bash
# Terminal 1 -- start the learning switch (or p1_hub.py for the hub)
ryu-manager part1/p1_learning.py

# Terminal 2 -- start the Mininet topology
sudo mn --custom part1/p1_topo.py --topo customtopo1 \
  --controller=remote,ip=127.0.0.1,port=6633 \
  --switch ovsk,protocols=OpenFlow10 --mac --link=tc
```

### Part 2

```bash
# Terminal 1
ryu-manager --observe-links part2/p2_spanning_tree.py

# Terminal 2
sudo mn --custom p2_topo.py --topo customtopo2 \
  --controller=remote,ip=127.0.0.1,port=6633 \
  --switch ovsk,protocols=OpenFlow13
```

### Part 3

```bash
# Terminal 1
ryu-manager --observe-links part3/p3_spr.py

# Terminal 2
sudo mn --custom p3_topo.py --topo customtopo3 \
  --controller=remote,ip=127.0.0.1,port=6633 \
  --switch ovsk,protocols=OpenFlow13
```

After Mininet starts, test with:

```bash
mininet> pingall
mininet> iperf h1 h3
mininet> h1 traceroute h3
```

Clean up stale state between runs with `sudo mn -c`.
