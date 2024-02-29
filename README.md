      ___           ___           ___           ___           ___           ___     
	     /\  \         /\  \         /\__\         /\__\         /\  \         /\  \    
	    /::\  \        \:\  \       /::|  |       /::|  |       /::\  \       /::\  \   
	   /:/\:\  \        \:\  \     /:|:|  |      /:|:|  |      /:/\:\  \     /:/\:\  \  
	  /::\~\:\  \       /::\  \   /:/|:|  |__   /:/|:|__|__   /::\~\:\  \   /::\~\:\  \ 
	 /:/\:\ \:\__\     /:/\:\__\ /:/ |:| /\__\ /:/ |::::\__\ /:/\:\ \:\__\ /:/\:\ \:\__\
	 \/__\:\ \/__/    /:/  \/__/ \/__|:|/:/  / \/__/~~/:/  / \/__\:\/:/  / \/__\:\/:/  /
	      \:\__\     /:/  /          |:/:/  /        /:/  /       \::/  /       \::/  / 
	       \/__/     \/__/           |::/  /        /:/  /        /:/  /         \/__/  
	                                 /:/  /        /:/  /        /:/  /                 
	                                 \/__/         \/__/         \/__/                  

	./ft_nmap {Target} -s [Scan type] -p [Ports specised] -t {thread number}
	
	Or
	
	./ft_nmap -f [file's path of target(s)]
	
	OPTION:

    -Target: name of address (ip v4 X.X.X.X or host name)

    -Scan:  (-s) 6 types of scan can be proceed simultaneous or singular (SYN, ACK, FIN, XMAS, NULL, UDP).
    if no scans are precised, ft_nmap will proceed all scans at once. You must precised the scans after -s flag using only comma to separate them.
            exemple:    =>  ./ft_nmap X.X.X.X -s SYN (simple scan)
                        =>  ./ft_nmap host_name.com -s SYN,XMAX,ACK,UDP (some scans simultaneous)
                        =>  ./ft_nmap google.com    (all 6 scans)

    -Ports: (-p) port(s) of target scanned. After the -p flag, you can enumerate the ports using comma as       delimiter    (80,443,225) or a range of ports, using minus as delimimiter: (10-560). Port minimun: 0, Port maximum: 65535. If no ports are precised, ft_nmap will scan from 1 to 1024 ports.
            exemple:    => ./ft_nmap scanme.nmap.org -p 1-10000 (range of port)
                        => ./ft_nmap parti-renaissance.fr -p 1,22,80,443 (range of port)
                        => ./ft_nmap insecure.org (default: 1 to 1024 ports)

    -Threads: (-t) number of threads being used by the program (default 1, min: 1, max: 255)
            exemple:    => ./ft_nmap linux.org -t 10 (using 10 threads)
                        => ./ft_nmap twitter.com (using 1 thread by default)

    -File of target: (-f) /path/of/file read by the program to scan multiple sources during one execution. You must write the list of targets with the correctly specified options as you would have written them when you called the program. You cannot call the program as such: ./ft_nmap <target> -f <file>. If you precised the -f flag, it will be the only flag considerate. 
            exemple:    => ./ft_nmap -f list_of_target
                        => cat list_of_target
                        $scanme.nmap.org -s SYN -p 20-30
                        $8.8.8.8 -t 10 -s UDP -p 1,22,50,90,1000
                        $insecure.org -p 1-65535 

