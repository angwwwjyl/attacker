#ifndef __ATTACKER_ARP_H__
#define __ATTACKER_ARP_H__

#include <linux/if_ether.h>

#include <attacker.h>

class CARPAttacker : public CEtherAttacker
{
    public:
        CARPAttacker(char* name);
        int DoAttack();
        int StopAttack();

        u_char* GetSendMac() { return m_cpSendMac; }
        u_char* GetTargetMac() { return m_cpTargetMac; }
        u_int GetSendIP() { return m_nSendIP; }
        u_int GetTargetIP() { return m_nTargetIP; }
        void SetSendIP(u_int sip) { m_nSendIP = sip; }
        void SetTargetIP(u_int tip) { m_nTargetIP = tip; }

    private:
        u_char m_cpSendMac[ETH_ALEN];
        u_char m_cpTargetMac[ETH_ALEN];
        u_int m_nSendIP;
        u_int m_nTargetIP;

        void _DoInit();

};

#endif

