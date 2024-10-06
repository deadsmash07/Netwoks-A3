### Commands to run the code
- it runs the switch

```bash
ryu-manager p1_learning.py
``` 
- To run the hub
```bash
ryu-manager p1_hub.py
```

to run the miniet topology
```bash
sudo mn --custom p1_topo.py --topo customtopo1 --controller=remote,ip=127.0.0.1,port=6633 --switch ovsk,protocols=OpenFlow10 --mac --link=tc
```
to dump the flows
```bash
mininet> dpctl dump-flows
```

- to chekc what is asked in the assignemnt run either of switch or hub then  run the mininet and test for `pingall` or `iperf h1 h5` etc.

- add this at end of each topo `topos = {'customtopo1': (lambda: CustomTopo())}`