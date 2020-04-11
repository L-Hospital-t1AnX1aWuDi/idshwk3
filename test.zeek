global p:table[addr] of set[string]={};

event http_header(c: connection, is_orig: bool, name: string, value: string)
{   
    local ip_src=c$http$id$orig_h;
    local u_agent=c$http$user_agent;
	
    if ( ip_src !in p)
    {
        p[ip_src]=[to_lower(u_agent)];
    }
    else
    {	
    	add p[ip_src][to_lower(u_agent)];
    }       
}

event zeek_done()
{
    for ( k in p)
        if (|p[k]|>=3)
            print fmt("%s is a proxy", k);
}
© 2020 GitHub, Inc.
