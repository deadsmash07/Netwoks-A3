### Commands to run the code
- it runs the switch

```bash
ryu-manager --ofp-tcp-listen-port 6633 switch.py
``` 
- To run the hub
```bash
ryu-manager --ofp-tcp-listen-port 6633 hub.py
```

to run the miniet topology
```bash
sudo mn --custom p1_topo.py --topo customtopo1 --controller=remote,ip=127.0.0.1,port=6633 --switch ovsk,protocols=OpenFlow10 --mac --link=tc
```

- to chekc what is asked in the assignemnt run either of switch or hub then  run the mininet and test for `pingall` or `iperf h1 h5` etc.