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