from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.node import OVSSwitch, RemoteController

class CustomTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        
        # Add four hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        
        # Connect each host to its respective switch 
        self.addLink(h1, s1, bw=10)  # 10 Mbps link
        self.addLink(h2, s2, bw=10)  # 10 Mbps link
        self.addLink(h3, s3, bw=10)  # 10 Mbps link
        self.addLink(h4, s4, bw=5)    # 5 Mbps link

        # Connect switches 
        self.addLink(s1, s2, bw=5)
        self.addLink(s2, s3, bw=10)
        self.addLink(s3, s4, bw=10)
        self.addLink(s4, s1, bw=5)

def run():
    """Create the network, start it, and enter the CLI."""
    topo = CustomTopo()
    net = Mininet(topo=topo, link=TCLink, switch=OVSSwitch, build=False)
    net.addController('c0', controller=RemoteController, ip="127.0.0.1", protocol='tcp', port=6633)
    net.build()
    net.start()
    info('*** Running CLI\n')
    # Start CLI for further testing
    CLI(net)

    # Stop the network
    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
topos = {'customtopo3': (lambda: CustomTopo())}
