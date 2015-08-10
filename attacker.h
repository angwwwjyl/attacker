#ifndef __ATTACKER_H__
#define __ATTACKER_H__

#include <linux/if_ether.h>
#include <netinet/in.h>
#include <sys/types.h>

#include <attacker_util.h>

#define ATTACKERNAME_LEN (16)
class CAttacker
{
    public:
        CAttacker();
        CAttacker(char *name, u_int pps, u_int duration);

        virtual ~CAttacker() {};
        virtual int DoAttack() = 0;
        virtual int StopAttack() = 0;

        u_int GetPPS() { return m_nPPS; }
        void SetPPS(int pps) { m_nPPS = pps; }
        int GetDuration() { return m_nDuration; }
        void SetDuration(int duration) { m_nDuration = duration; }

    protected:
        u_int m_nPPS;  /*0: not limit*/
        u_int m_nDuration;  /*0: forever*/
        char m_cpAttackName[ATTACKERNAME_LEN];  /*not to use string here*/

};

class CEtherAttacker : public CAttacker
{
    public:
        CEtherAttacker();
        CEtherAttacker(char *name);
        virtual int DoAttack() = 0;
        virtual int StopAttack() = 0;

        u_char* GetSrcMac() { return m_cpSrcMac; } 
        u_char* GetDstMac() { return m_cpDstMac; } 
        u_short GetHWProto() { return m_nHWProto; }
        void SetHWProto(u_short proto) { m_nHWProto = proto; }

    protected:
        u_char m_cpSrcMac[ETH_ALEN]; 
        u_char m_cpDstMac[ETH_ALEN]; 
        u_short m_nHWProto;
        void _DoInit();
};


class CNetAttacker : public CEtherAttacker
{
    public:
        CNetAttacker();
        CNetAttacker(char* name);
        virtual int DoAttack() = 0;
        virtual int StopAttack() = 0;

    protected:
        u_char m_nVersion:4,
               m_nHdrLen:4;  /*unit: 4 bytes*/
        u_char m_nDSF; /*differentiated service field */
        u_char m_nTTL;
        u_char m_nProto;

        u_int m_nSRC;
        u_int m_nDST;

        u_short m_nTotalLen; /*ip header + ip data*/
        u_short m_nIdentification;
        u_short m_nFlagCE:1,  /*reserve*/
                m_nFlagDF:1, 
                m_nFlagMF:1, 
                m_nFragOffset:13; 

        void _DoInit();
};

class CUDPAttacker : public CNetAttacker
{
    public:
        CUDPAttacker();
        CUDPAttacker(char* name);
        virtual int DoAttack() = 0;
        virtual int StopAttack() = 0;

    protected:
        u_short m_nSrcPort;
        u_short m_nDstPort;
        u_short m_nLen; /*udp header + udp data*/

        void _DoInit();
};

class CTCPAttacker : public CNetAttacker
{
    public:
        CTCPAttacker();
        CTCPAttacker(char* name);
        virtual int DoAttack() = 0;
        virtual int StopAttack() = 0;

    protected:
        u_short m_nSrcPort;
        u_short m_nDstPort;
        u_int m_nSequence;
        u_int m_nAckNumber;
        
        u_short m_nCWR:1, /*congestion window reduced*/
                       m_nECN:1,  /*ECN-Echo*/
                       m_nUrg:1,
                       m_nAck:1,
                       m_nPush:1,
                       m_nReset:1,
                       m_nSyn:1,
                       m_nFin:1;

        u_short m_nWidowSize;
        u_short m_nUrgPointer;
        
        u_char m_nHdrLen:4, /*unit: 4 bytes*/
               m_nHdrLenReserve:4;

        void _DoInit();
};

class CICMPAttacker : public CNetAttacker
{
    public:
        CICMPAttacker();
        CICMPAttacker(char* name);
        virtual int DoAttack() = 0;
        virtual int StopAttack() = 0;

    protected:
        u_char m_nType;
        u_char m_nCode;
        u_short m_nIdentifier;
        u_short m_nSequence;

        void _DoInit();
};


#endif
