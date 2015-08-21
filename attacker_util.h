#ifndef __ATTACKER_UTIL_H__
#define __ATTACKER_UTIL_H__

#include <attacker_types.h>
#include <sys/types.h>
#include <string.h>

#include <stdarg.h>
#include <stdio.h>

#include <arpa/inet.h>

#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <time.h>
#include <sys/time.h>

class CLibUtil
{
    public:
        static char* Strncpy(char *dst, char *src, size_t n);
        static int Strncmp(const char *s1, const char *s2, size_t n)
        {
            return strncmp(s1, s2, n);
        }

        static void* Memzero(void *s, size_t n) { return memset(s, 0x0, n); }
        static void* Memset(void *s, int c, size_t n) { return memset(s, c, n); }
        static void *Memcpy(void *dest, const void *src, size_t n) 
        {
            return memcpy(dest, src, n);
        }
        //#define Memset(s, c, n)  memset(s, c, n)
        //#define Memzero(s, n)  memset(s, 0x0, n)

        static int Snprintf(char *str, size_t size, const char *format, ...)
        {   
            int len;

            va_list args;
            va_start(args, format);
            len = vsnprintf(str, size, format, args); /*add '\0' to tailing of str*/
            va_end(args);

            return len;
        }

        static inline int Vsnprintf(char *str, size_t size, const char *format, va_list ap) 
        {
            int len;

            len = vsnprintf(str, size, format, ap); /*add '\0' to tailing of str*/
            
            return len;
        }
        
        static int GetHostName(char* name, size_t len) { return gethostname(name, len); }
        static int GetdomainName(char* name, size_t len) { return getdomainname(name, len); }

        static int IOCtl(int d, int request, ...)
        {
            int ret;

            va_list args;
            va_start(args, request);
            ret = ioctl(d, request, va_arg(args, uintptr_t)); 
            va_end(args);
            
            return ret;
        }
        
        static int Socket(int domain, int type, int protocol) 
        { 
            return socket(domain, type, protocol);
        }

        static int GetTimeofDay(struct timeval *tv, struct timezone *tz)
        {
            return gettimeofday(tv, tz);
        }
        static void GetMtime(time_t sec, struct tm* gmt);
        
        static uint16_t Htons(uint16_t hostshort) 
        {
            return htons(hostshort);
        }
        static uint32_t Htonl(uint32_t hostlong)
        {
            return htonl(hostlong);
        }
        static uint32_t Ntohl(uint32_t netlong)
        {
            return ntohl(netlong);
        }
        static uint16_t Ntohs(uint16_t netshort)
        {
            return ntohs(netshort);
        }

    private:
        CLibUtil() {}  /*don't construct*/
        CLibUtil(const CLibUtil& u) {}  /*don't construct*/
        CLibUtil& operator=(const CLibUtil &u) { return *this; }  /*don't construct*/
        ~CLibUtil() {}
};


#define INVAILD_ADDR (0)
#define INVAILD_NETMASK (0)
#define INVAILD_INFINDEX (-1)
#define STRADDR_MIN_LEN (8)
#define FULL_STRADDR_MIN_LEN (16)
#define IF_STATE_UP (1)
#define IF_STATE_DOWN (0)

class CNetUtil
{
    public:
        static void SetMacSeparator(char c) { ms_cMacSeparator = c; }
        static char GetMacSeparator() { return ms_cMacSeparator; }
        static char* MacToStrMac(const u_char* mac, char* strmac, int strmac_len);
        static char* MacToStrMac(const u_char* mac, char* strmac);
        static u_char* StrMacToMac(const char* strmac, u_char* mac);

        static u_char GetStrAddrMinLen() { return ms_nStrAddrMinLen; };
        static void SetStrAddrMinLen(u_char len) { ms_nStrAddrMinLen = len; };
        static bool IsFullStrAddrll() { return ms_nFullStrAddr; }
        static void SetFullStrAddrll(bool f) 
        {
            ms_nFullStrAddr = f; 
            if (f) 
                SetStrAddrMinLen(FULL_STRADDR_MIN_LEN); 
            else 
                SetStrAddrMinLen(STRADDR_MIN_LEN);
        }
        static char* HostAddrToStrAddr(u_int addr, char *str);
        static char* HostAddrToStrAddr(u_int addr, char *str, int srtlen);
        static char* NetAddrToStrAddr(u_int addr, char *str);
        static char* NetAddrToStrAddr(u_int addr, char *str, int strlen);
        static in_addr_t StrAddrToHostAddr(const char *straddr, u_int* addr); /*if str error, return 0;*/
        static in_addr_t StrAddrToNetAddr(const char *straddr, u_int* addr);

        /*if fail return INVAILD_INFINDEX */
        static int GetInfindex(const char* infname);
        static int GetInfindexWithFd(int fd, const char* infname);

        /*if fail return NULL*/
        static u_char* GetInfMac(const char* infname, u_char* mac);
        static u_char* GetInfMacWithFd(int fd, const char* infname, u_char* mac);

        /*if fail return INVAILD_NETMASK*/
        static in_addr_t GetNetMask(const char* ifname, in_addr_t netaddr);
        static in_addr_t GetNetMaskWithFd(int fd, const char* ifname, in_addr_t netaddr);
        
        /*running: IFF_UP, other: IFF_DOWN*/
        static int GetIFState(const char* ifname);
        static int GetIFStateWithFd(int fd, const char* ifname);
        

    private:
        CNetUtil() {}  /*don't construct*/
        CNetUtil(const CNetUtil& u) {}  /*don't construct*/
        CNetUtil& operator=(const CNetUtil &u) { return *this; }  /*don't construct*/
        ~CNetUtil() {}

        static inline void _Mac4bitToChar(u_char b, char *s);
        static char ms_cMacSeparator; /*not thread safe*/

        static u_char ms_nStrAddrMinLen;  /*1.1.1.1 = 8; 001.001.001.001 = 16*/
        static u_char ms_nFullStrAddr;  /*flag: full str(001.001.001.001) or str(1.1.1.1)*/
};

#endif
