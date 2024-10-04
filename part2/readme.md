command for mini-project 2
```bash
sudo mn -c
sudo mn --custom p2_topo.py --topo customtopo2 --controller=remote,ip=127.0.0.1,port=6633 --switch ovsk,protocols=OpenFlow13 --mac --link=tc
sudo mn --custom p2_topo.py --topo customtopo2 --controller=remote,ip=127.0.0.1,port=6633 --switch ovsk,protocols=OpenFlow13
```
command for running ryu app
```bash
ryu-manager --observe-links switch.py
```