#ifndef __ATTACKER_FACTORY_H__
#define __ATTACKER_FACTORY_H__

#include <map>
#include <attacker.h>

typedef enum
{
    ARPFOOD_IDX,

}AttackerIndex_e;

typedef CAttacker* (*CreateAttackerFunc_t)();

/*singleton factory*/
class CAttackerFactory
{
    public:
        ~CAttackerFactory() { m_iAttackers.clear(); }
        static CAttackerFactory* GetInstance()
        {
            static CAttackerFactory iAttackerFactory;
            return &iAttackerFactory;
        }

        void RegisterAttacker(AttackerIndex_e index, CreateAttackerFunc_t pfCreate);
        void UnregisterAttacker(AttackerIndex_e index);
        CAttacker* DoCreate(AttackerIndex_e index);

    private:
        CAttackerFactory(); 
        CAttackerFactory(const CAttackerFactory& af) {}
        CAttackerFactory& operator=(const CAttackerFactory& af) { return *this; } 
        
        typedef std::map<AttackerIndex_e, CreateAttackerFunc_t> AttackerMaps_t; 
        AttackerMaps_t m_iAttackers;
};


#endif

