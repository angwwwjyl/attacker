#include <attacker_factory.h>

CAttackerFactory::CAttackerFactory()
{
}

void CAttackerFactory::RegisterAttacker(AttackerIndex_e index, CreateAttackerFunc_t pfCreate)
{
    m_iAttackers[index] = pfCreate; 
}

void CAttackerFactory::UnregisterAttacker(AttackerIndex_e index)
{
    m_iAttackers.erase(index);
}

CAttacker* CAttackerFactory::DoCreate(AttackerIndex_e index)
{
    if (m_iAttackers.find(index) == m_iAttackers.end())
        return NULL;

    return m_iAttackers[index]();
}

