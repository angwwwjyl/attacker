#include <attacker_log.h>

#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/stat.h>


AT::CDebugLogger g_iDebugLogger;
AT::CRunningLogger g_iRunningLogger;

const static char* gs_caLogLevelStr[AT::LOG_LEVEL_MAX] =
{ 
    "stderr", "emerg", "alert", "crit",
    "error", "warn", "notice", "info",
    "debug"
};

const static char* gs_caDebugStr[LOG_DEBUG_NUM] =
{
    "util", "hostinfo", "factory", "arp"
};

const static char  *gs_caWeek[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
//const static char  *gs_caMonths[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
//                               "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

int AT::CLogger::DoInit()
{
    int ret = 0;

    m_nPpid = getppid();
    m_nPid = getpid();
    m_nTid = std::this_thread::get_id();

    m_nMaxSize = 4096;  /*4M*/
    m_nCurSize = 0;

    if (m_caFileName[0] == '\0')
        m_nFd = STDOUT_FILENO;
    else
    {
        m_nFd = open(m_caFileName, O_WRONLY | O_APPEND | O_CREAT, 0666);
        if (m_nFd > 0)
        {
            struct stat tfstat;
            fstat(m_nFd, &tfstat); 
            m_nCurSize = tfstat.st_size; 
        }
        else
            ret = -errno;
    }

    return ret;
}


int AT::CDebugLogger::DoInit()
{
    int ret;

    ret = CLogger::DoInit();

    return ret;
}

int AT::CDebugLogger::DoLog(int level, const char* fmt, ...)
{
#define BUF_LEN 1024
    char cabuf[BUF_LEN];
    int nlen = 0;
    int nwlen = 0;
    va_list args;
    char* pfmt;
    int n;
    u_int nlevel;

    struct timeval tTV;
    struct tm tTM;

    if (m_nFd < 0)
        return -1025;

    if ((unsigned int)level < LOG_LEVEL_MAX)
        return -1027;

    /*judge space*/
    if ( m_nFd != STDOUT_FILENO && (m_nCurSize>>10) > m_nMaxSize)  /*m_nCurSize/1024*/
    {
        return -1026;
    }

    n = 0;
    nlevel = level;
    nlevel >>= LOG_DEBUG_SHIFT; 
    while(nlevel)
    {
        n++;
        nlevel >>= 1;
    }

    if (n >= LOG_DEBUG_NUM)
        return -1028;

    CLibUtil::GetTimeofDay(&tTV, NULL);
    CLibUtil::GetMtime(tTV.tv_sec, &tTM);
    nlen = CLibUtil::Snprintf(cabuf, BUF_LEN, "%s %s-%4d/%02d/%02d-%02d:%02d:%02d %d %d %d %s ",
            "[debug]", gs_caWeek[tTM.tm_wday],
            tTM.tm_year, tTM.tm_mon, tTM.tm_mday, tTM.tm_hour,
            tTM.tm_min, tTM.tm_sec, m_nPpid, m_nPid,
            m_nTid, gs_caDebugStr[n]);
    
    va_start(args, fmt);
    nlen += CLibUtil::Snprintf(cabuf+nlen, BUF_LEN-nlen, fmt, args); 
    va_end(args);

    pfmt = const_cast<char*>(fmt);
    while(*pfmt != '\0') pfmt++;
   
    if (nlen+1 < BUF_LEN && (--pfmt)[0] != '\n')
    {
        cabuf[nlen] = '\n';
        nlen++;
    }

#if 0
    if (nlen < BUF_LEN)
    {
        cabuf[nlen] = '\0';
        nlen++; /*tailing '\0'*/
    }
    else
    {
        cabuf[BUF_LEN-1] = '\0';
        nlen = BUF_LEN; /*tailing '\0'*/
    }
#endif

    nwlen = write(m_nFd, cabuf, nlen);
    if (m_nFd != STDOUT_FILENO && nwlen <= 0)
    {
        m_nCurSize += nwlen; 
    }
    
    return 0;
}

int AT::CRunningLogger::DoInit()
{
    int ret;

    ret = CLogger::DoInit();

    return ret;
}

int AT::CRunningLogger::DoLog(int level, const char* fmt, ...)
{
#define BUF_LEN 1024
    char cabuf[BUF_LEN];
    int nlen = 0;
    int nwlen = 0;
    va_list args;
    char* pfmt;

    struct timeval tTV;
    struct tm tTM;

    if (m_nFd < 0)
        return -1025;

    if ((unsigned int)level >= LOG_LEVEL_MAX)
        return -1027;

    /*judge space*/
    if ( m_nFd != STDOUT_FILENO && (m_nCurSize>>10) > m_nMaxSize)  /*m_nCurSize/1024*/
    {
        return -1026;
    }

    CLibUtil::GetTimeofDay(&tTV, NULL);
    CLibUtil::GetMtime(tTV.tv_sec, &tTM);
    nlen = CLibUtil::Snprintf(cabuf, BUF_LEN, 
            "[%s] %s-%4d/%02d/%02d-%02d:%02d:%02d %d %d %d ",
            gs_caLogLevelStr[level], gs_caWeek[tTM.tm_wday],
            tTM.tm_year, tTM.tm_mon, tTM.tm_mday, tTM.tm_hour,
            tTM.tm_min, tTM.tm_sec, m_nPpid, m_nPid,
            m_nTid);
    
    va_start(args, fmt);
    nlen += CLibUtil::Snprintf(cabuf+nlen, BUF_LEN-nlen, fmt, args); 
    va_end(args);

    pfmt = const_cast<char*>(fmt);
    while(*pfmt != '\0') pfmt++;
   
    if (nlen+1 < BUF_LEN && (--pfmt)[0] != '\n')
    {
        cabuf[nlen] = '\n';
        nlen++;
    }

#if 0
    if (nlen < BUF_LEN)
    {
        cabuf[nlen] = '\0';
        nlen++; /*tailing '\0'*/
    }
    else
    {
        cabuf[BUF_LEN-1] = '\0';
        nlen = BUF_LEN; /*tailing '\0'*/
    }
#endif


    nwlen = write(m_nFd, cabuf, nlen);
    if (m_nFd != STDOUT_FILENO && nwlen <= 0)
    {
        m_nCurSize += nwlen; 
    }

    return 0;
}

