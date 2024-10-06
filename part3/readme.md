command for part3
```bash
sudo mn -c

sudo mn --custom p3_topo.py --topo customtopo3 --controller=remote,ip=127.0.0.1,port=6633 --switch ovsk,protocols=OpenFlow13
```

to run the ryu app
```bash
ryu-manager sp_switch.py
```
to analyse, run on separate terminal 
```bash
sudo ovs-ofctl dump-flows s1 -O OpenFlow13
```
various other commands to verify the routing after shortest path calculation:
```bash
mininet> h1 traceroute h3
mininet> h1 ping h3
```
to obtain the hosts mac address
```bash
h1 ifconfig
```