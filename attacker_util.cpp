#include <attacker_util.h>

#include <linux/if_ether.h>

#include <linux/if.h>

char* CLibUtil::Strncpy(char *dst, char *src, size_t n)
{
    if (n == 0) 
    { 
        return dst; 
    }    
    
    if (NULL == dst || NULL == src)
        return NULL;

    while (--n)
    {
        *dst = *src;

        if (*dst == '\0') {
            return dst; 
        }    

        dst++;
        src++;
    }    

    *dst = '\0';

    return dst; 
}

/*see form ngx times*/
void CLibUtil::GetMtime(time_t sec, struct tm* gmt)
{
    int nyday;
    u_int n, nsec, nmin, nhour, nmday, nmon, 
          nyear, nwday, ndays, nleap;

    n = (u_int)sec;
    ndays = n / 86400; /*86400 = 24 * 60 * 60*/
    
    /*January 1, 1970 was Thursday*/
    nwday = (4 + ndays) % 7;

    n %= 86400;
    nhour = n / 3600; /*3600 = 60 * 60*/
    n %= 3600;
    nmin = n / 60;
    nsec = n % 60;

    /*the algorithm based on Gauss' formula*/
    ndays = ndays - (31 + 28) + 719527;

    /*
      * The "days" should be adjusted to 1 only, however, some March 1st's go
      * to previous year, so we adjust them to 2.  This causes also shift of the
      * last February days to next year, but we catch the case when "yday"
      *  becomes negative.
      */
    nyear = (ndays + 2) * 400 / (365 * 400 + 100 - 4 + 1);
    nyday = ndays - (365 * nyear + nyear / 4 - nyear / 100 + nyear / 400);

    if (nyday < 0)
    {
        nleap = (nyear % 4 == 0) && (nyear % 100 || (nyear % 400 == 0));
        nyday = 365 + nleap + nyday;
        nyear--;
    }

    /*
     * The empirical formula that maps "yday" to month.
     * There are at least 10 variants, some of them are:
     * mon = (yday + 31) * 15 / 459
     * mon = (yday + 31) * 17 / 520
     * mon = (yday + 31) * 20 / 612
     * */

    nmon = (nyday + 31) * 10 / 306;
    /* the Gauss' formula that evaluates days before the month */
    
    nmday = nyday - (367 * nmon / 12 - 30) + 1;

    if (nyday >= 306)
    {
        nyear++;
        nmon -= 10;

        /*
         * there is no "yday" in Win32 SYSTEMTIME
         *
         * yday -= 306;
         **/
    }
    else
    {
        nmon += 2;
        /*
         * there is no "yday" in Win32 SYSTEMTIME
         *
         * yday += 31 + 28 + leap;
         **/
    }

    gmt->tm_sec = nsec;
    gmt->tm_min = nmin;
    gmt->tm_hour = nhour;
    gmt->tm_mday = nmday;
    gmt->tm_mon = nmon;
    gmt->tm_year = nyear;
    gmt->tm_wday = nwday;
}



///////////////////////////////////////////////////////////////////////////////
//CNetUtil begin
//////////////////////////////////////////////////////////////////////////////

char CNetUtil::ms_cMacSeparator = ':';
u_char CNetUtil::ms_nFullStrAddr = false;
u_char CNetUtil::ms_nStrAddrMinLen = STRADDR_MIN_LEN;

inline void CNetUtil::_Mac4bitToChar(u_char b, char *s)
{
    switch(b)
    {
        case 0:
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
        case 8:
        case 9:
            *s = '0' + b;
            break;

        case 10:
        case 11:
        case 12:
        case 13:
        case 14:
        case 15:
            *s = 55 + b;
            break;

        default:
            break;
    }
}

char* CNetUtil::MacToStrMac(const u_char* mac, char* strmac, int strmac_len)
{
    if (strmac_len < 17)
        return NULL;

    return MacToStrMac(mac, strmac);
}

char* CNetUtil::MacToStrMac(const u_char* mac, char* strmac)
{
    int i;
    u_char h4;
    u_char l4;
    char *cp_strmac = strmac;

    if (NULL == mac || NULL == strmac)
        return NULL;

    for (i = 0; i < ETH_ALEN; i++)
    {
        h4 = mac[i] >> 4;   //mac[i]/16;
        l4 = mac[i] & 0xf;  //mac[i]%16;

        _Mac4bitToChar(h4, strmac);
        strmac++;
        _Mac4bitToChar(l4, strmac);
        strmac++;
        *strmac = GetMacSeparator();
        strmac++;
    }

    *(--strmac) = '\0';  /*override last ':' or '-'*/
    return cp_strmac;

}

u_char* CNetUtil::StrMacToMac(const char* strmac, u_char* mac)
{ 
    int n_separator = 0;  /*must have five separarators: 0-4*/
    int num = 0; /*not less than two*/
    u_char tmp_mac[ETH_ALEN];
    u_char val = 0;
    u_char tmp;

    if (NULL == strmac || NULL == mac)
        return NULL;

    /*first char is not separator*/
    if ( *strmac == GetMacSeparator())
        return NULL;

    while(*strmac != '\0')
    {
        tmp = *strmac;
        if (tmp == GetMacSeparator())
        {
            if (n_separator > 4)
                break;

            tmp_mac[n_separator] = val;
            n_separator += 1;
            val = 0;

            num = 0;
        }
        else
        {
            if (num >= 2)
                break;

            val *= 16;
            switch(tmp)
            {
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                    val += tmp - '0';
                    break;

                case 'a':
                case 'b':
                case 'c':
                case 'd':
                case 'e':
                case 'f':
                    val += tmp - 'a' + 10;
                    break;

                case 'A':
                case 'B':
                case 'C':
                case 'D':
                case 'E':
                case 'F':
                    val += tmp - 'A' + 10;
                    break;

                default:
                    return NULL;
            }

            num += 1;
        }

        strmac++;
    }

    if (5 != n_separator || num > 2 || num == 0 )
        return NULL;

    tmp_mac[n_separator] = val;

    CLibUtil::Memcpy(mac, tmp_mac, ETH_ALEN);
    return mac;
}

static inline char* _NetAddrToStrAddr(u_int addr, char *str, int strlen)
{
    u_char *p;

    if (NULL == str)
        return NULL;

    p = (u_char*)&addr;
    CLibUtil::Snprintf(str, strlen, "%u.%u.%u.%u",
            p[0], p[1], p[2], p[3]);

    return str;
}

char* CNetUtil::HostAddrToStrAddr(u_int addr, char *str)
{
    addr = htonl(addr);

    return _NetAddrToStrAddr(addr, str, FULL_STRADDR_MIN_LEN);
}

char* CNetUtil::HostAddrToStrAddr(u_int addr, char *str, int strlen)
{
    if (strlen < GetStrAddrMinLen())
        return NULL;
    
    addr = htonl(addr);
    return _NetAddrToStrAddr(addr, str, strlen);
}

char* CNetUtil::NetAddrToStrAddr(u_int addr, char *str)
{
    return _NetAddrToStrAddr(addr, str, FULL_STRADDR_MIN_LEN);
}

char* CNetUtil::NetAddrToStrAddr(u_int addr, char *str, int strlen)
{
    if (strlen < GetStrAddrMinLen())
        return NULL;

    return _NetAddrToStrAddr(addr, str, strlen);
}


static inline in_addr_t _StrAddrToHostAddr(const char *straddr, in_addr_t* addr)
{
    u_char      *p, c;
    in_addr_t    taddr;
    u_int octet, n;

    if (NULL == straddr || NULL == addr)
        return INVAILD_ADDR;

    taddr = 0; 
    octet = 0; 
    n = 0; 

    for (p = (u_char*)straddr; p != '\0' ; p++) {

        if (octet > 255) {
            return INVAILD_ADDR;
        }    

        c = *p;

        if (c >= '0' && c <= '9') {
            octet = octet * 10 + (c - '0');
            continue;
        }    

        if (c == '.') {
            taddr = (taddr << 8) + octet;
            octet = 0; 
            n++; 
            continue;
        }    

        return INVAILD_ADDR;
    }    

    if (n == 3) { 
        taddr = (taddr << 8) + octet;
        *addr = taddr;
        return taddr;
    }

    return INVAILD_ADDR;
}

in_addr_t CNetUtil::StrAddrToHostAddr(const char *straddr, in_addr_t* addr)
{
    return _StrAddrToHostAddr(straddr, addr);
}

in_addr_t CNetUtil::StrAddrToNetAddr(const char *straddr, in_addr_t* addr)
{
    _StrAddrToHostAddr(straddr, addr);
    *addr = htonl(*addr);
    return *addr;
}

int CNetUtil::GetInfindexWithFd(int fd, const char* infname)
{
    struct ifreq tIfr;

    if (NULL == infname || fd < 0) 
        return INVAILD_INFINDEX;

    tIfr.ifr_addr.sa_family = PF_PACKET;
    strncpy(tIfr.ifr_name, infname, IFNAMSIZ);
    if (CLibUtil::IOCtl(fd, SIOCGIFINDEX, &tIfr) != 0)
    {
        return INVAILD_INFINDEX;
    }

    return tIfr.ifr_ifindex;
}

/*if fail return INVAILD_INFINDEX */
int CNetUtil::GetInfindex(const char* infname)
{
    int fd;
    int ret;

    fd = CLibUtil::Socket(PF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return INVAILD_INFINDEX;

    ret = GetInfindexWithFd(fd, infname);

    close(fd);
    return ret;
}

/*if fail return NULL*/
u_char* CNetUtil::GetInfMacWithFd(int fd, const char* infname, u_char* mac)
{
    struct ifreq tIfr;

    if (fd < 0 || NULL == infname || NULL == mac)
        return NULL;

    CLibUtil::Memcpy(tIfr.ifr_name, infname, IFNAMSIZ);
    if (CLibUtil::IOCtl(fd, SIOCGIFHWADDR, &tIfr) < 0)   
    {
        //perror("ioctl error:");
        return NULL;
    }

    CLibUtil::Memcpy(mac, tIfr.ifr_hwaddr.sa_data, ETH_ALEN);

    return mac;

}

u_char* CNetUtil::GetInfMac(const char* infname, u_char* mac)
{
    int fd;
    u_char *pc;

    fd = CLibUtil::Socket(PF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return NULL;

    pc = GetInfMacWithFd(fd, infname, mac);

    close(fd);
    return pc;
}

in_addr_t CNetUtil::GetNetMaskWithFd(int fd, const char* ifname, in_addr_t netaddr)
{
    struct ifreq tIfr;
    struct sockaddr_in *tpSockaddr;

    if (fd < 0 || NULL == ifname)
        return INVAILD_NETMASK;

    CLibUtil::Strncpy(tIfr.ifr_name, const_cast<char*>(ifname), IFNAMSIZ);
    tpSockaddr = (struct sockaddr_in*)&(tIfr.ifr_addr);
    tpSockaddr->sin_addr.s_addr = netaddr;

    if (CLibUtil::IOCtl(fd, SIOCGIFNETMASK, &tIfr) < 0)   
    {
        //perror("ioctl error:");
        return INVAILD_NETMASK;
    }

    return tpSockaddr->sin_addr.s_addr;
}

in_addr_t CNetUtil::GetNetMask(const char* ifname, in_addr_t netaddr)
{
    int fd;
    in_addr_t mask;

    fd = CLibUtil::Socket(PF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return INVAILD_NETMASK;

    mask = GetNetMaskWithFd(fd, ifname, netaddr); 

    close(fd);
    return mask;
}


