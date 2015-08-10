#include <attacker_arp.h>
#include <attacker_util.h>

CARPAttacker::CARPAttacker(char* name)
    : CEtherAttacker(name)
{
    _DoInit();
}

void CARPAttacker::_DoInit()
{
    CLibUtil::Memset(m_cpSrcMac, 0xff, ETH_ALEN);
    CLibUtil::Memzero(m_cpTargetMac, ETH_ALEN);

    m_nSendIP = -1;
    m_nTargetIP = 0;
}

int CARPAttacker::DoAttack()
{
    return 0;
}

int CARPAttacker::StopAttack()
{
    return 0;
}
