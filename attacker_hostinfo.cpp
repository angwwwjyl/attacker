#include <attacker_hostinfo.h>

#include <attacker_util.h>
#include <attacker_log.h>

#include <sys/types.h>
#include <errno.h>
#include <pthread.h>
#include <sys/select.h>

#include <map>
#include <string>

CHostInfo::CHostInfo()
{
    QueryBaseInfo();

    /*about thread*/
    m_nArpSendThreadNum = 0;
    CLibUtil::Memzero(m_ngArpSendTids, sizeof(pthread_t)*ARP_SEND_THREAD_MAX_NUM);
    m_nArpSendEndFlag = ARP_SEND_END_UNDONE;
    m_nArpSendEndDone = 0;
    m_nArpRecvEnd = ARP_RECV_END_UNDONE;

}

CHostInfo::~CHostInfo()
{
    InetInfoList_T::iterator it;
    SubnetAddrMacMap_T::iterator subnetit;

    for (it = m_ilInetInfo.begin(); it != m_ilInetInfo.end(); ++it)
    {
        delete *it;
    }
    m_ilInetInfo.clear();

    /*subnet info*/
    for (subnetit = m_imSubnetAddrMacInfo.begin(); 
            subnetit != m_imSubnetAddrMacInfo.end(); ++subnetit)
    {
        subnetit->second->clear();
        delete subnetit->second;
    }
    m_imSubnetAddrMacInfo.clear();
}

int CHostInfo::QueryBaseInfo()
{
    int ret;

    ret = CLibUtil::GetHostName(m_itBaseInfo.m_caName, HOSTNAME_LEN);
    if (0 != ret)
    {
        return ret;
    }

    return CLibUtil::GetdomainName(m_itBaseInfo.m_caNIS, HOSTNIS_LEN);
}

int CHostInfo::QueryInetInfo()
{
    struct ifconf tIfconf; 
    int fd, i;
#define BUF_LEN (1024)
    char caBuf[BUF_LEN];
    int nRet = 0;
    int nIfconfnum;
    struct ifreq *tIfr;
    HostInetInfo_T *tInetInfo;

    /*temporary map for get infindex or mac*/
    std::map<std::string, int> iInfmap;
    std::map<std::string, u_char*> iMacmap;

    std::map<std::string, int>::iterator iInfmapIt;
    std::map<std::string, u_char*>::iterator iMacmapIt;

    InetInfoList_T::iterator iNetInfoListIt;

    fd = CLibUtil::Socket(PF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return errno;

    tIfconf.ifc_len = BUF_LEN;
    tIfconf.ifc_buf = caBuf;

    CLibUtil::Memset(caBuf, 0x0, BUF_LEN);

    nRet = CLibUtil::IOCtl(fd, SIOCGIFCONF, &tIfconf);
    //nRet = ioctl(fd, SIOCGIFCONF, &tIfconf);
    if (nRet < 0)
    {
        nRet = errno;
        goto lab_close;
    }

    nIfconfnum = tIfconf.ifc_len/sizeof(struct ifreq);
    tIfr = (struct ifreq*)tIfconf.ifc_buf;

    //printf("ifnum:%d len=%d\n", nIfconfnum, tIfconf.ifc_len);

    for(i=nIfconfnum; i > 0; i--, tIfr++)
    {
        if (0 == CLibUtil::Strncmp(tIfr->ifr_name, 
                    LOOPBACK_DEVICE_NAME, sizeof(LOOPBACK_DEVICE_NAME)))
            continue;

        tInetInfo = new HostInetInfo;
        
        CLibUtil::Strncpy(tInetInfo->m_caIfname, tIfr->ifr_name, IFNAMSIZ);
        tInetInfo->m_nAddr = ((struct sockaddr_in*)&(tIfr->ifr_addr))->sin_addr.s_addr;
        tInetInfo->m_nMask = CNetUtil::GetNetMaskWithFd(fd, 
                tInetInfo->m_caIfname, tInetInfo->m_nAddr);

        m_ilInetInfo.push_back(tInetInfo);

        iInfmap.insert(std::pair<std::string, int>(tInetInfo->m_caIfname, tInetInfo->m_nInfindex));
        iMacmap.insert(std::pair<std::string, u_char*>(tInetInfo->m_caIfname, tInetInfo->m_caMac));
    }

    for (iInfmapIt = iInfmap.begin(); iInfmapIt != iInfmap.end(); iInfmapIt++)
    {
        iInfmapIt->second = CNetUtil::GetInfindexWithFd(fd, iInfmapIt->first.data());
    }

    for (iMacmapIt = iMacmap.begin(); iMacmapIt != iMacmap.end(); iMacmapIt++)
    {
        CNetUtil::GetInfMacWithFd(fd, iMacmapIt->first.data(), iMacmapIt->second);
    }

    for(iNetInfoListIt = m_ilInetInfo.begin(); iNetInfoListIt != m_ilInetInfo.end(); iNetInfoListIt++)
    {
        tInetInfo = *iNetInfoListIt;
        
        tInetInfo->m_nInfindex = iInfmap[tInetInfo->m_caIfname]; 
        CLibUtil::Memcpy(tInetInfo->m_caMac, iMacmap[tInetInfo->m_caIfname], ETH_ALEN);
    }

lab_close:
    close(fd);
    return nRet;
}

#if 0
/*ugly show arp packet*/
static void ShowEthArpPkt(ETH_ARP_T* pkt)
{
    int i;
    int cnt = sizeof(ETH_ARP_T)/16;
    u_char *cp = (u_char*)pkt;

    //printf("cnt: %d  len:%d\n", cnt, sizeof(ETH_ARP_T));
    for(i = 0; i < cnt; ++i)
    {
        printf("%02x %02x %02x %02x %02x %02x %02x %02x     ",
                cp[0], cp[1], cp[2], cp[3],
                cp[4], cp[5], cp[6], cp[7]);
        cp += 8;
        printf("%02x %02x %02x %02x %02x %02x %02x %02x\n",
                cp[0], cp[1], cp[2], cp[3],
                cp[4], cp[5], cp[6], cp[7]);
        cp += 8;
    }
    printf("\n");
}
#endif 

/*for send arp using inet addr int eth network*/
int CHostInfo::SendEthInetArp(int fd, SendEthInetARPArg_T* arg)
{
    /*ATLogDebug(DEBUG_HOSTINFO, "%s:%d %s arg:%p", 
            __FILE__, __LINE__, __func__, arg);
    */
    ETH_ARP_T tArphd;
    ssize_t nSendLen;

    if (fd < 0 || NULL == arg)
    {
        ATLogError(AT::LOG_ERR, "%s:%d %s parameter error!",
                __FILE__, __LINE__, __func__);
        return -EINVAL;
    }
   
    CLibUtil::Memcpy(tArphd.eh.h_dest, arg->cpDstMac, ETH_ALEN);
    CLibUtil::Memcpy(tArphd.eh.h_source, arg->cpSrcMac, ETH_ALEN);
    tArphd.eh.h_proto = CLibUtil::Htons(ETH_P_ARP);

    tArphd.ah.ar_hrd = CLibUtil::Htons(ARPHRD_ETHER);
    tArphd.ah.ar_pro = CLibUtil::Htons(ETH_P_IP);
    tArphd.ah.ar_hln = ETH_ALEN;
    tArphd.ah.ar_pln = 4;
    //tArphd.ah.ar_op = CLibUtil::Htons(ARPOP_REQUEST);
    tArphd.ah.ar_op = arg->nArpOp; 

    CLibUtil::Memcpy(tArphd.smac, arg->cpSmac, ETH_ALEN);
    CLibUtil::Memcpy(tArphd.tmac, arg->cpTmac, ETH_ALEN);
    *(in_addr_t*)tArphd.sip = arg->nNetSip;
    *(in_addr_t*)tArphd.tip = arg->nNetTip;


    nSendLen = send(fd, &tArphd, sizeof(tArphd), 0);
    if (-1 == nSendLen)
    {
        ATLogError(AT::LOG_ERR, "%s:%d %s parameter error!",
                __FILE__, __LINE__, __func__);
        return -errno;
    }

    //ShowEthArpPkt(&tArphd);
    return 0;
}


/*Notice:ifname must has enough space
 * subnet: net byteorder
 * */
int CHostInfo::__FindNICBySubAddr(in_addr_t subnet, char* ifname)
{
    InetInfoList_T::iterator iHostsIt;
    HostInetInfo *tpHostInfo;

    if (NULL == ifname)
        return -EINVAL;

    for (iHostsIt = m_ilInetInfo.begin(); 
            iHostsIt != m_ilInetInfo.end(); ++iHostsIt)
    {
        tpHostInfo = *iHostsIt;
        if (subnet == (tpHostInfo->m_nAddr & tpHostInfo->m_nMask))
        {
            CLibUtil::Strncpy(ifname, tpHostInfo->m_caIfname, IFNAMSIZ);
            return 0;
        }
    }

    return -ENOENT;
}

/*subnet: net byteorder*/
HostInetInfo* CHostInfo::__FindHostInfoBySubAddr(in_addr_t subnet)
{
    InetInfoList_T::iterator iHostsIt;
    HostInetInfo *tpHostInfo;

    for (iHostsIt = m_ilInetInfo.begin(); 
            iHostsIt != m_ilInetInfo.end(); ++iHostsIt)
    {
        tpHostInfo = *iHostsIt;
        if (subnet == (tpHostInfo->m_nAddr & tpHostInfo->m_nMask))
        {
            return tpHostInfo;
        }
    }

    return NULL;
}


void* CHostInfo::__RecvArpFunc(void *arg)
{
    ATLogDebug(DEBUG_HOSTINFO, "%s:%d %s arg:%p", 
            __FILE__, __LINE__, __func__, arg);

    if ( NULL == arg)
        return NULL;

    CHostInfo* ipHostInfo = (CHostInfo*)arg;
    int fd;
    fd_set fds;
    struct timeval tTimeout;
    size_t nRecvLen;
    struct sockaddr_ll tSockaddrll;
    HostInetInfo* ipHostInet = ipHostInfo->m_iSubnetInfo;
    u_char cgBuf[ARP_RECV_BUF_LEN];
    ETH_ARP_T* tArpHdrData;
    in_addr_t nSubnetNetAddr;
    AddrMacMap_T* mpAddrMac; 
    char cgBufForStrAddr[24];
    char cgBufForStrMac[24];
    int nAfterSendEndDelay = ARP_SEND_END_DELAY;

    if (NULL == ipHostInfo)
    {
        ATLogError(AT::LOG_ERR, "%s:%d %s lack of subnet info!",
                __FILE__, __LINE__, __func__);
        return NULL;
    }

    nSubnetNetAddr = ipHostInet->m_nAddr & ipHostInet->m_nMask;
    mpAddrMac = ipHostInfo->FindAddrMacMapBySubnet(nSubnetNetAddr);
    if (NULL == mpAddrMac)
    {
        ATLogError(AT::LOG_ERR, "%s:%d %s lack of map for addr-mac!",
                __FILE__, __LINE__, __func__);
        return NULL;
    }

    fd = CLibUtil::Socket(PF_PACKET, SOCK_RAW, CLibUtil::Htons(ETH_P_ARP));
    if (fd < 0)
    {
        ATLogError(AT::LOG_ERR, "%s:%d %s socket error!",
                __FILE__, __LINE__, __func__);
        return NULL;
    }

    CLibUtil::Memzero(&tSockaddrll, sizeof(tSockaddrll));
    tSockaddrll.sll_family = PF_PACKET;
    tSockaddrll.sll_protocol = CLibUtil::Htons(ETH_P_ARP);
    tSockaddrll.sll_ifindex = ipHostInet->m_nInfindex;   
    tSockaddrll.sll_hatype = htons(ARPHRD_ETHER);
    tSockaddrll.sll_pkttype = PACKET_HOST;
    tSockaddrll.sll_halen = ETH_ALEN;
    CLibUtil::Memcpy(tSockaddrll.sll_addr, ipHostInet->m_caMac, ETH_ALEN);

    if (0 != bind(fd, (struct sockaddr*)&tSockaddrll, sizeof(tSockaddrll)))
    {
        ATLogError(AT::LOG_ERR, "%s:%d %s bind error!",
                __FILE__, __LINE__, __func__);
        goto lab_close;
    }
   
    tTimeout.tv_usec = 0;
    tTimeout.tv_sec = ARP_RECV_SELECT_TIMEOUT_SEC;
    for (; true ;)
    {
        if (ipHostInfo->IsArpSendEnd())
        {
            if (nAfterSendEndDelay <= 0)
                break;
            nAfterSendEndDelay--;
        }

        FD_ZERO(&fds);
        FD_SET(fd, &fds);

        if (select(fd+1, &fds, NULL, NULL, &tTimeout) < 0)
            continue;

        nRecvLen = recv(fd, cgBuf, ARP_RECV_BUF_LEN, 0); 
        if (nRecvLen < sizeof(ETH_ARP_T))
            continue;
        
        tArpHdrData = (struct eth_arp*)cgBuf;

        //ATLogDebug(DEBUG_HOSTINFO, "%s:%d %s arpop:%d", 
        //        __FILE__, __LINE__, __func__, CLibUtil::Ntohs(tArpHdrData->ah.ar_op));
        if (tArpHdrData->ah.ar_op != CLibUtil::Htons(ARPOP_REPLY))
        {
            continue;
        }


        //ATLogDebug(DEBUG_HOSTINFO, "%s:%d %s tip:%8x", 
        //        __FILE__, __LINE__, __func__, *((in_addr_t*)tArpHdrData->tip));
        /*this arp reply is not send to me*/
        if ( *((in_addr_t*)tArpHdrData->tip) != ipHostInet->m_nAddr)
        {
            continue;
        }

        /*not in local subnet*/
        if ( (*((in_addr_t*)tArpHdrData->sip) & ipHostInet->m_nMask) != nSubnetNetAddr)
        {
            continue;
        }
        
        if (ipHostInfo->AddAddrMacToMap(mpAddrMac, *(in_addr_t*)tArpHdrData->sip,
                    tArpHdrData->smac) != 0)
        {
            CNetUtil::NetAddrToStrAddr(*(in_addr_t*)tArpHdrData->sip, cgBufForStrAddr);
            CNetUtil::MacToStrMac(tArpHdrData->smac, cgBufForStrMac);
            ATLogError(AT::LOG_WARN, "%s:%d %s may be ipconfilct %s<-->%s",
                    __FILE__, __LINE__, __func__,
                    cgBufForStrAddr, cgBufForStrMac);

        }

    }

lab_close:
    close(fd);
    return NULL;
}

/*Notice: not check ifname*/
int CHostInfo::__CreateAndRunRecvThread(CHostInfo* hinfo)
{
    int ret;

    if (NULL == hinfo)
        return -EINVAL;

    ret = pthread_create(&m_nArpRecvTid, NULL, __RecvArpFunc, hinfo);     
    if (0 != ret)
        return -errno;

    pthread_detach(m_nArpRecvTid);

    return 0;
}

void* CHostInfo::__SendArpFunc(void *arg)
{
    ATLogDebug(DEBUG_HOSTINFO, "%s:%d %s arg:%p", 
            __FILE__, __LINE__, __func__, arg);
    
    ArpSendThreadArg_T* tpSendThreadArg = (ArpSendThreadArg_T*)arg;
    CHostInfo* ipHostInfo = tpSendThreadArg->m_iHostInfo;
    int fd = -1;
    struct sockaddr_ll tSockaddrll;
    SendEthInetARPArg_T tSendeEthInetArparg;
    in_addr_t nAddrend = tpSendThreadArg->m_nAddrEnd; 
    HostInetInfo* ipHostInet = ipHostInfo->m_iSubnetInfo;
    u_char cgDstMac[ETH_ALEN];
    u_char cgTmac[ETH_ALEN];

    if ( NULL == arg)
    {
        goto lab_end;
    }
    if (NULL == ipHostInfo)
    {
        goto lab_end;
    }

    ATLogDebug(DEBUG_HOSTINFO, "%s:%d %s stataddr:%08x, endaddr:%08x", 
            __FILE__, __LINE__, __func__, 
            tpSendThreadArg->m_nAddrStart, tpSendThreadArg->m_nAddrEnd);

    if ( tpSendThreadArg->m_nAddrEnd <= tpSendThreadArg->m_nAddrStart)
    {
            ATLogError(AT::LOG_ERR, "%s:%d %s statraddr more endaddr",
                    __FILE__, __LINE__, __func__);
            goto lab_end;
    }

    if (NULL == ipHostInet)
    {
        ATLogError(AT::LOG_ERR, "%s:%d %s lack of subnet info!",
                __FILE__, __LINE__, __func__);
        goto lab_end;
    }


    fd = CLibUtil::Socket(PF_PACKET, SOCK_RAW, CLibUtil::Htons(ETH_P_ARP));
    if (fd < 0)
    {
        ATLogError(AT::LOG_ERR, "%s:%d %s socket error!",
                __FILE__, __LINE__, __func__);
        goto lab_end;
    }

    CLibUtil::Memzero(&tSockaddrll, sizeof(tSockaddrll));
    tSockaddrll.sll_family = PF_PACKET;
    tSockaddrll.sll_protocol = CLibUtil::Htons(ETH_P_ARP);
    tSockaddrll.sll_ifindex = ipHostInet->m_nInfindex;   
    tSockaddrll.sll_hatype = htons(ARPHRD_ETHER);
    tSockaddrll.sll_pkttype = PACKET_HOST;
    tSockaddrll.sll_halen = ETH_ALEN;
    CLibUtil::Memcpy(tSockaddrll.sll_addr, ipHostInet->m_caMac, ETH_ALEN);

    if (0 != bind(fd, (struct sockaddr*)&tSockaddrll, sizeof(tSockaddrll)))
    {
        ATLogError(AT::LOG_ERR, "%s:%d %s bind error!",
                __FILE__, __LINE__, __func__);
        goto lab_end;
    }
   
    tSendeEthInetArparg.cpSrcMac = ipHostInet->m_caMac;
    CLibUtil::Memset(cgDstMac, 0XFF, ETH_ALEN);
    tSendeEthInetArparg.cpDstMac = cgDstMac;
    tSendeEthInetArparg.cpSmac = ipHostInet->m_caMac;
    CLibUtil::Memset(cgTmac, 0X0, ETH_ALEN);
    tSendeEthInetArparg.cpTmac = cgTmac;
    tSendeEthInetArparg.nNetSip = ipHostInet->m_nAddr;
    tSendeEthInetArparg.nArpOp = htons(ARPOP_REQUEST);
    for(in_addr_t i=tpSendThreadArg->m_nAddrStart+1; i <= nAddrend; i++)
    {
        tSendeEthInetArparg.nNetTip = htonl(i);
        ipHostInfo->SendEthInetArp(fd, &tSendeEthInetArparg);
    }
    
lab_end:
    if (fd != -1)
        close(fd);
    ipHostInfo->SetArpSendThreadDoneFlag(pthread_self());
    return NULL;
}

int CHostInfo::__CreateAndRunSendThreads(CHostInfo* hinfo)
{
    ATLogDebug(DEBUG_HOSTINFO, "%s:%d %s hinfo:%p", 
            __FILE__, __LINE__, __func__, hinfo);

    int ret;
    u_int i;
    int nHostCnt;
    int nHostCntPerthread;
    int nHostCntFraction;
    in_addr_t subnetaddr;
    ArpSendThreadArg_T *tThreadArg;

    if (NULL == hinfo)
        return -EINVAL;
   
    if (NULL == hinfo->m_iSubnetInfo)
        return -EINVAL;

    nHostCnt = ntohl(~hinfo->m_iSubnetInfo->m_nMask);
    nHostCntPerthread = nHostCnt / hinfo->m_nArpSendThreadNum;
    nHostCntFraction = nHostCnt % hinfo->m_nArpSendThreadNum - 1; /*not including xxx.xxx.xxx.255*/

    subnetaddr = ntohl(hinfo->m_iSubnetInfo->m_nAddr & 
            hinfo->m_iSubnetInfo->m_nMask); 
    for (i = 0; i < hinfo->m_nArpSendThreadNum-1; i++)
    {
        tThreadArg = &hinfo->m_tgArpSendThreadArg[i];
        tThreadArg->m_iHostInfo = this;
        tThreadArg->m_nAddrStart = subnetaddr + i * nHostCntPerthread;
        tThreadArg->m_nAddrEnd = subnetaddr + (i + 1) * nHostCntPerthread;

        ret = pthread_create(&m_ngArpSendTids[i], NULL, __SendArpFunc, tThreadArg);
        if (0 != ret)
            return -errno;

        pthread_detach(m_ngArpSendTids[i]);
    }
    tThreadArg = &hinfo->m_tgArpSendThreadArg[i];
    tThreadArg->m_iHostInfo = this;
    tThreadArg->m_nAddrStart = subnetaddr + i * nHostCntPerthread;
    tThreadArg->m_nAddrEnd = subnetaddr + (i + 1) * nHostCntPerthread + nHostCntFraction;

    ret = pthread_create(&m_ngArpSendTids[i], NULL, __SendArpFunc, tThreadArg);
    if (0 != ret)
        return -errno;
    pthread_detach(m_ngArpSendTids[i]);

    return 0;
}

void CHostInfo::__SetThreadArgs(int nsubhost)
{
    /*setting something about thread*/
    if (nsubhost <= 0xFF)
    {
        m_nArpSendThreadNum = 2;
    }
    else if (nsubhost <= 0xFFF)
    {
        m_nArpSendThreadNum = 6;
    }
    else if (nsubhost <= 0xFFFF)
    {
        m_nArpSendThreadNum = ARP_SEND_THREAD_MAX_NUM-8;
    }
    else if (nsubhost <= 0xFFFFF)
    {
        m_nArpSendThreadNum = ARP_SEND_THREAD_MAX_NUM-6;
    }
    else
    {
        m_nArpSendThreadNum = ARP_SEND_THREAD_MAX_NUM;
    }
    m_nArpSendEndDone = m_nArpSendThreadNum; 
    
    return;
}


/* netaddr and mask must be net byte order
 * addr: 10.1.5.0  mask:255.255.255.0*/
int CHostInfo::QuerySubnetAddrMacInfo(in_addr_t netaddr, in_addr_t mask)
{
    ATLogDebug(DEBUG_HOSTINFO, "%s:%d %s netaddr:%08x, mask:%08x", 
            __FILE__, __LINE__, __func__, 
            netaddr, mask);

    SubnetAddrMacMap_T::iterator it;
    in_addr_t nsubnet = netaddr & mask;
    AddrMacMap_T *imAddrmac;

    in_addr_t subnet = netaddr & mask;
    int ncount = ntohl(~mask);
    HostInetInfo* iSubnetInfo;
   
    if (mask == 0 || ncount < 2)
    {
        ATLogError(AT::LOG_ERR, "subhost count error! %s:%d %s", 
                __FILE__, __LINE__, __func__);
        return -EINVAL;
    }

    iSubnetInfo = __FindHostInfoBySubAddr(subnet);
    if (NULL == iSubnetInfo)
    {
        ATLogError(AT::LOG_ERR, "subnet is not exist! %s:%d %s", 
                __FILE__, __LINE__, __func__);
        return -ENOENT;
    }
    m_iSubnetInfo = iSubnetInfo;

    /*clear old data*/
    it = m_imSubnetAddrMacInfo.find( nsubnet );
    if (it != m_imSubnetAddrMacInfo.end())
    {
        it->second->clear();
        imAddrmac = it->second;
    }
    else
    {
        imAddrmac = new AddrMacMap_T;
        m_imSubnetAddrMacInfo.insert(
                std::pair<in_addr_t, AddrMacMap_T*>(nsubnet, imAddrmac));
    }
    ATLogDebug(DEBUG_HOSTINFO, "%s:%d %s subnet:%08x, addrmacmap:%p", 
            __FILE__, __LINE__, __func__,
            nsubnet, imAddrmac);
    
    __SetThreadArgs(ncount);

    __CreateAndRunRecvThread(this);

    __CreateAndRunSendThreads(this);

    sleep(10);

    ShowSubnetIpMac(subnet);

    return 0;
}


void CHostInfo::ShowSubnetIpMac(in_addr_t netsubnet)
{
    ATLogDebug(DEBUG_HOSTINFO, "%s:%d %s", 
            __FILE__, __LINE__, __func__); 

    SubnetAddrMacMap_T::iterator subnetit;
    AddrMacMap_T* imAddrMac;
    AddrMacMap_T::iterator iAddrMacIt;
    char cgBufForStrAddr[24];
    char cgBufForStrMac[24];

    subnetit = m_imSubnetAddrMacInfo.find(netsubnet);
    if (subnetit == m_imSubnetAddrMacInfo.end())
    {
        ATLogError(AT::LOG_ERR, "subnet is not exist! %s:%d %s", 
                __FILE__, __LINE__, __func__);
        return;
    }
    imAddrMac = subnetit->second;

    ATLogDebug(DEBUG_HOSTINFO, "%s:%d %s subnet:%08x, addrmacmap:%p", 
            __FILE__, __LINE__, __func__,
            subnetit->first, imAddrMac); 

    /*subnet info*/
    for (iAddrMacIt = imAddrMac->begin(); 
            iAddrMacIt != imAddrMac->end(); ++iAddrMacIt)
    {
        CNetUtil::NetAddrToStrAddr(iAddrMacIt->first, cgBufForStrAddr);
        CNetUtil::MacToStrMac(iAddrMacIt->second.m_cgMac, cgBufForStrMac);
        ATLogError(AT::LOG_INFO, "%s:%d %s: %s<-->%s", 
                __FILE__, __LINE__, __func__,
                cgBufForStrAddr, cgBufForStrMac);
    }
}
