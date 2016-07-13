Bitcoin Peer Forger (BPF)
========

BPF is a network security research tool which allows an on-path party to connect to a Bitcoin node from a large number of spoofed IP addresses. 
Note that to spoof these IP addresses the tool must be able (a). to read and (b). to inject traffic between the targeted node and the spoofed IP addresses (i.e. the tool must be on-path).

Why use BPF?
--------
BPF was developed to create Bitcoin peering traffic originating form many different IP addresses sources without actually having to own those IP addresses. 
For instance we used early versions of BPF to test the impact on a Bitcoin node of botnet of various sizes engaging in address stuffing to perform an eclipse attack. 

This research was published in [Eclipse Attacks on Bitcoin’s Peer-to-Peer Network](https://eprint.iacr.org/2015/263.pdf),
Ethan Heilman, Alison Kendler, Aviv Zohar, Sharon Goldberg.
ePrint Archive Report 2015/263. March 2015.

Project status 
--------
This project is in its early stages.

- [ ] Support for arbitary actions.
  - [ ] Break response code into multiple functions.
  - [ ] Function as passable argument to specify action after connection. 
- [ ] IPv6 support.
- [ ] Testnet support.
- [ ] Commandline interface rather than hardcoded parameters.
- [ ] Support for initating many connections over a short period of time.
- [ ] Retry failed connections.
- [ ] Better output and logging.
- [ ] Unittests.
- [ ] Documentation.
  - [X] Readme.
  - [ ] Examples.
- [X] Support for the loopback intreface.
- [X] Refactor.
