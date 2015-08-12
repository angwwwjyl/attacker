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

class CHostInfo;
typedef struct ArpSendThreadArg
{
    in_addr_t m_nAddrStart;
    in_addr_t m_nAddrEnd;
    CHostInfo *m_iHostInfo;  
}ArpSendThreadArg_T;


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
        
        SubnetAddrMacMap_T* GetSubnetAddrMacMap() { return &m_imSubnetAddrMacInfo;} 
        HostInetInfo* GetQuerySubnetInfo() { return m_iSubnetInfo; }

    private:
        HostBaseInfo_T m_itBaseInfo;
        InetInfoList_T m_ilInetInfo;

        SubnetAddrMacMap_T m_imSubnetAddrMacInfo;
        
        #define ARP_SEND_THREAD_MAX_NUM 16 
        #define ARP_RECV_END_DONE   1
        #define ARP_RECV_END_UNDONE   0
        #define ARP_SEND_END_UNDONE   0

        u_int m_nArpSendThreadNum; 
        pthread_t m_ngArpSendTids[ARP_SEND_THREAD_MAX_NUM];
        pthread_t m_nArpRecvTid;
        volatile u_int m_nArpSendEndFlag;    /* equal to m_nArpSendEndDone, sned end*/
        u_int m_nArpSendEndDone;   /*depend on m_nArpSendThreadNum*/ 
        u_int m_nArpRecvEnd; /*match with macro*/
        
        /*subnet: net byteorder*/
        int __FindNICBySubAddr(in_addr_t subnet, char* ifname);
        HostInetInfo* __FindHostInfoBySubAddr(in_addr_t subnet);
        void __SetThreadArgs(int nsubhost);
        int __CreateAndRunRecvThread(CHostInfo* hinfo);
        int __CreateAndRunSendThreads(CHostInfo* hinfo);

        /*function for thread excution*/
        static void* __RecvArpFunc(void *arg);
        static void* __SendArpFunc(void *arg);

        /*query ip-mac in this subnet used in thread*/
        HostInetInfo* m_iSubnetInfo;
        ArpSendThreadArg_T m_tgArpSendThreadArg[ARP_SEND_THREAD_MAX_NUM];
};



#endif

