# SuricataRuleTest

**SuricataRuleTest** is a (Hive) Cortex analyzer to test Suricata NIDS rules on a provided pcap file.

## Scenarios

One of the reasons I created this analyzer is that I needed a tool I could use to automate the pcap testing on my Suricata deployment. I also worked at companies where similar tests were done manually so I thought it is a good idea to create a tool like this.

I've written this tool with the following scenarios in mind:

1. In some networks, the traffic is not going through a NIDS (due to lack of money, processing power, etc) but Security Analysts can start a packet capture to collect network data originating from the machine under investigation. If a machine is under analyses it is not clear yet if it is infected, therefore you don't know whether the captured packet contains anything suspicious or not. In a scenario like this, you can upload the pcap into the Hive as an observable and you can execute this analyser on it. The packet is going to be tested with the provided rules and tell you whether the pcap contains anything malicious or not *(based on the rules)*. *(no clear infection)*
1. You found a malware in a system but no NIDS has created any alert. Maybe the malware hasn't started its communication yet, or it doesn't have a malicious communication function *(beaconing, spreading)* at all, or maybe the traffic originating from the system just isn't going through any NIDS *(due to your network design)*. Perhaps you were quick and isolated the machine so early it couldn't start its communication. You can execute the same malware in a safe environment, collect the packets *(a lot of test environment does not have a NIDS in it, or it is not up-to-date)* and you can test the given packet to find out whether there is anything malicious in it or not. *(clearly infected machine, no info about the network traffic)*
1. Did you found a pcap on the internet which contains some interesting traffic? Or are you analyzing a malware and it generates some network traffic? It would be good to know if you have detection for this activity already in place. You can just forward the found pcap the Hive and you can execute the analyser which is going to tell you whether you can detect this traffic on the network or not. *(known malicious network traffic)*

## Installation
Use the same installation method as needed for any other Cortex analyzer.

## Flavors
There are two flavors of this analyzer. One of them is for an environment in which TheHive/Cortex is running on the same host as the Suricata.
The other flavor is for an environment in which TheHive/Cortex is running on a different host than the Suricata. This version was requested because in many cases the above-mentioned tools are running in different docker instances or at least on different hosts. The second flavor can be used to SSH to the other system and execute the commands there (Cortex can SSH to the system that runs Suricata).

## Settings
--

## Manual
--
