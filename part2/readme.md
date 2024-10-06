command for mini-project 2
```bash
sudo mn -c
sudo mn --custom p2_topo.py --topo customtopo2 --controller=remote,ip=127.0.0.1,port=6633 --switch ovsk,protocols=OpenFlow13
```
command for running ryu app
```bash
ryu-manager --observe-links p2_spanning_tree.py
```

- to chekc what is asked in the assignemnt run either of switch or hub then  run the mininet and test for `pingall` or `iperf h1 h5` etc.