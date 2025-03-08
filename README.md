# SPOOFHOP

## What is Spoofhop?
Spoofhop is a DNS spoofing program for unix based systems that you can use for multiple things like:
* Routing your traffic through the program to block a list of well known advertising networks.
* Doing MITM attacks on network devices.
* Seeing if a certain domain is accessed.
* Testing application security by pretending to be a server.

## How does it work?
By creating a netfilter queue Spoofhop can analyze outgoing DNS queries, block them and respond to them with a spoofed IPv4 addresses
without the program not even knowing that its packet didn't go to the correct destination.

## Screenshot
<img src="https://github.com/SpoofIMEI/spoofhop/assets/72181445/35d3f785-f68a-436f-b8da-c6a5f099a280" width=600 heigth=750></img>

## Installation
```
git clone https://github.com/SpoofIMEI/spoofhop
cd spoofhop
pip install -r requirements.txt
```

## Usage
`sudo python3 spoofhop.py -s <spoof ip here> -d "annoyingwebsite.com:annoyingwebsite2.com"`

## DISCLAIMER
I am not responsible for any harm or damage done by this program. Everyone's responsible for their own use of the program.
