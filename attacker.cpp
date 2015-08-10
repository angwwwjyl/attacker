#include <attacker.h>

CAttacker::CAttacker() 
{ 
    m_cpAttackName[0] = '\0';
    m_nPPS = 100;
    m_nDuration = 60;
}

CAttacker::CAttacker(char* name, u_int pps = 100, u_int duration = 60) 
{
    if (NULL != name)
    {
        CLibUtil::Strncpy(m_cpAttackName, name, ATTACKERNAME_LEN);
        m_cpAttackName[ATTACKERNAME_LEN-1] = '\0';  /*ensure end with '\0'*/
    }
    else
        m_cpAttackName[0] = '\0';
    m_nPPS = pps;
    m_nDuration = duration;
}


CEtherAttacker::CEtherAttacker() 
: CAttacker()
{
    _DoInit(); 
}

CEtherAttacker::CEtherAttacker(char *name)
    : CAttacker(name) 
{
    _DoInit();
}

void CEtherAttacker::_DoInit()
{
    CLibUtil::Memzero(m_cpSrcMac, ETH_ALEN);
    CLibUtil::Memset(m_cpDstMac, 0xff, ETH_ALEN);
    m_nHWProto = ETH_P_AARP;
}


CNetAttacker::CNetAttacker() 
: CEtherAttacker() 
{
    _DoInit(); 
}

CNetAttacker::CNetAttacker(char* name)
    : CEtherAttacker(name)
{
    _DoInit();
}

void CNetAttacker::_DoInit()
{
    m_nVersion = 4;
    m_nHdrLen = 5;  
    m_nDSF = 0;
    m_nTTL = 64;
    m_nProto = IPPROTO_UDP;
    m_nSRC = 0;
    m_nDST = -1; /*0xffffffff*/

    m_nIdentification = 0x2345;
    m_nFlagDF = 1;
    m_nFlagMF = 0;
    m_nFragOffset = 0;
}

CUDPAttacker::CUDPAttacker() 
    : CNetAttacker() 
{ 
    _DoInit(); 
}

CUDPAttacker::CUDPAttacker(char* name)
    : CNetAttacker(name) 
{
    _DoInit();
}

void CUDPAttacker::_DoInit()
{
    m_nSrcPort = 0;
    m_nDstPort = 0;
    m_nLen = 0;
}

CTCPAttacker::CTCPAttacker() 
    : CNetAttacker()
{
    _DoInit();
}

CTCPAttacker::CTCPAttacker(char* name) 
    : CNetAttacker(name)
{
    _DoInit();
}

void CTCPAttacker::_DoInit()
{
    m_nSrcPort = 0;
    m_nDstPort = 0;
    m_nSequence = 0x12345678;
    m_nAckNumber = 0x1;

    m_nCWR = 0;
    m_nECN = 0;
    m_nUrg = 0;
    m_nAck = 0;
    m_nPush = 0;
    m_nReset = 0;
    m_nSyn = 0;
    m_nFin = 0;

    m_nWidowSize = 256;
    m_nUrgPointer = 0;

    m_nHdrLen = 5;
}

CICMPAttacker::CICMPAttacker()
    : CNetAttacker()
{
    _DoInit();
}

CICMPAttacker::CICMPAttacker(char* name) 
    : CNetAttacker(name)
{
    _DoInit(); 
}

void CICMPAttacker::_DoInit()
{
    m_nType = 8; /*ping*/
    m_nCode = 0;

    m_nIdentifier = 0x8765;
    m_nSequence = 0x5678;
}

