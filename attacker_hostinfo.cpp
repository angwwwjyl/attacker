#include <attacker_hostinfo.h>

#include <attacker_util.h>

#include <sys/types.h>
#include <errno.h>

#include <map>
#include <string>

CHostInfo::CHostInfo()
{
    QueryBaseInfo();
}

CHostInfo::~CHostInfo()
{
    InetInfoList_T::iterator it;

    for (it = m_ilInetInfo.begin(); it != m_ilInetInfo.end(); it++)
    {
        delete *it;
    }

    m_ilInetInfo.clear();
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


/* netaddr and mask must be net byte order
 * addr: 10.1.5.0  mask:255.255.255.0*/
int CHostInfo::QuerySubnetAddrMacInfo(in_addr_t netaddr, in_addr_t mask)
{
    SubnetAddrMacMap_T::iterator it;
    in_addr_t nsubnet = netaddr & mask;

    /*clear old data*/
    it = m_imSubnetAddrMacInfo.find( nsubnet );
    if (it != m_imSubnetAddrMacInfo.end())
    {
        for (it=m_imSubnetAddrMacInfo.begin(); 
                it != m_imSubnetAddrMacInfo.end(); ++it) 
        {
            m_imSubnetAddrMacInfo.erase(it);
            delete it->second;
        }
    }

    


    return 0;
}
