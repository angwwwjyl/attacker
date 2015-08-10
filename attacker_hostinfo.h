#ifndef __ATTACKER_HOSTINFO_H__
#define __ATTACKER_HOSTINFO_H__

#include <linux/if_ether.h>
#include <arpa/inet.h>

#include <list>
#include <map>

#include <linux/if.h>

#define HOSTNAME_LEN (64)
#define HOSTNIS_LEN (64)
typedef struct HostBaseInfo
{
    char m_caName[HOSTNAME_LEN];
    char m_caNIS[HOSTNIS_LEN];
}HostBaseInfo_T;

#define LOOPBACK_DEVICE_NAME "lo"
typedef struct HostInetInfo
{
    in_addr_t m_nAddr;
    in_addr_t m_nMask;
    int m_nInfindex;
    char m_caIfname[IFNAMSIZ];
    u_char m_caMac[ETH_ALEN];
}HostInetInfo_T;


typedef std::map<in_addr_t, u_char[ETH_ALEN]> AddrMacMap_T;
typedef std::map<in_addr_t, AddrMacMap_T*> SubnetAddrMacMap_T;
typedef std::list<HostInetInfo*> InetInfoList_T;
class CHostInfo
{
    public:
        CHostInfo();
        ~CHostInfo();
        int QueryBaseInfo();
        int QueryInetInfo();

        HostBaseInfo_T* GetBaseInfo() { return &m_itBaseInfo; }
        InetInfoList_T* GetInetInfo() { return &m_ilInetInfo; }

        int QuerySubnetAddrMacInfo(in_addr_t netaddr, in_addr_t mask);
        SubnetAddrMacMap_T* GetSubnetAddrMacInfo()
        {
            return &m_imSubnetAddrMacInfo;
        }
        
    private:
        HostBaseInfo_T m_itBaseInfo;
        InetInfoList_T m_ilInetInfo;

        SubnetAddrMacMap_T m_imSubnetAddrMacInfo;
        
        #define ARP_SEND_THREAD_MAX_NUM 16 
        #define ARP_RECV_END_DONE   1
        #define ARP_RECV_END_UNDONE   0
        #define ARP_SEND_END_UNDONE   0

        u_int m_nArpSendThreadNum; 
        pthread_t m_ngArpSend[ARP_SEND_THREAD_MAX_NUM];
        u_int m_nArpSendEndFlag;    /* equal to m_nArpSendEndDone, sned end*/
        u_int m_nArpSendEndDone;   /*depend on m_nArpSendThreadNum*/ 
        u_int m_nArpRecvEnd; /*match with macro*/
};



#endif

