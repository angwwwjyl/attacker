#if 0

/*test hostinfo
 *20150804
 * */
#include <attacker_arp.h> 
#include <attacker_hostinfo.h>
#include <attacker_util.h>

#include <iostream>
using namespace std;

int main(int argc, char **argv)
{
    CHostInfo ihi;
    HostBaseInfo *ibi;
    HostInetInfo *iii;
    InetInfoList_T *iil;
    InetInfoList_T::iterator it;

    ihi.QueryInetInfo();

    ibi = ihi.GetBaseInfo();
    iil = ihi.GetInetInfo();


    printf("name: %s    nis:%s\n", ibi->m_caName, ibi->m_caNIS);
    //printf("inet num: %d\n", iil->size());
    
    for (it = iil->begin(); it != iil->end(); it++)
    {
        iii = *it;

        char caStr[64];
        char *cp;

        printf("ifname:%s addr:%s\n",
                iii->m_caIfname, CNetUtil::NetAddrToStrAddr(iii->m_nAddr, caStr));
        
        cp = CNetUtil::MacToStrMac(iii->m_caMac, caStr); 
        //cout << cp << endl;
        printf("infindex:%d  mac:%s\n",
                iii->m_nInfindex, caStr);

        cout << endl;
    }


    return 0;
}
#endif

#if 0
/*
 * test log
 * 20150804
 * */
#include <attacker_log.h>
#include <iostream>

using namespace std;

int main()
{
#if 0
    int ret;

    AT::CDebugLogger idl;
    //AT::CDebugLogger idl("2.txt");
    AT::CRunningLogger irl;
    AT::CRunningLogger irlf("1.txt");

    irl.DoInit();
    irl.DoLog(2, "hello");
    irl.DoLog(2, "hedddddd\n");

    ret = irlf.DoInit();
    if(ret != 0)
    {
        perror("doinit");
        return -1;
    }
    irlf.DoLog(3, "ookkkkkk");

    idl.DoInit();
    idl.DoLog(0x10, "helloddd");
    idl.DoLog(0x20, "helloddd");
    idl.DoLog(0x40, "helloddd");
    idl.DoLog(0x80, "helloddd");
#endif
    
    ATLogErrorInit();

    cout << __FILE__ << __LINE__ << endl;

    ATLogError(AT::LOG_ERR, "%s, %d", __FILE__, __LINE__);

    return 0;
}
#endif

/*test hostinfo subnet ip-mac pairs
 * 20150812
 * */

#include <attacker_hostinfo.h>
#include <attacker_util.h>
#include <attacker_log.h>

#include <iostream>
using namespace std;

int main()
{
    int ret;

    ATLogDebugInit();
    ATLogErrorInit();

    CHostInfo ihi;
    //HostBaseInfo *ibi;
    HostInetInfo *iii;
    InetInfoList_T *iil;
    InetInfoList_T::iterator it;

    ihi.QueryInetInfo();
    //ibi = ihi.GetBaseInfo();
    iil = ihi.GetInetInfo();
    it = iil->begin();

    iii = *it;
    ret = ihi.QuerySubnetAddrMacInfo(iii->m_nAddr, iii->m_nMask);
    if (ret != 0)
    {
        cout << "ret:" << ret << endl;
        perror("subnet error");
    }

    return 0;
}
