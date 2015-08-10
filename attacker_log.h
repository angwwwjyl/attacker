#ifndef __ATTACKER_LOF_H__
#define __ATTACKER_LOF_H__


#include <thread>
#include <fstream>
#include <ostream>
#include <iostream>

#include <sys/types.h>
#include <unistd.h>

#include <attacker_types.h>
#include <attacker_util.h>

namespace AT
{

typedef enum
{
    LOG_STDERR=0,
    LOG_EMERG,
    LOG_ALERT,
    LOG_CRIT,
    LOG_ERR,
    LOG_WARN,
    LOG_NOTICE,
    LOG_INFO,
    LOG_DEBUG,
    LOG_LEVEL_MAX
}LoggerLevel_E;


#define DEBUG_UTIL      0x010
#define DEBUG_HOSTINFO  0x020
#define DEBUG_FACTORY   0x040
#define DEBUG_ARP       0x080

/*must match about*/
#define LOG_DEBUG_NUM 4
#define LOG_DEBUG_SHIFT 5  /*UTIL string addr is 0*/

/*log format: level time ppid pid tid ...
 *
 * eg: error fri-2015/07/06-01:23:20 2312 2314 320129332 ...
 * */
#define LOGGER_FILENAME_LEN (256)
class CLogger
{
    public:
        CLogger() : m_nFd(-1) { m_caFileName[0] = '\0'; }
        CLogger(const char* filename) : m_nFd(-1) 
        { 
            if (NULL != filename) 
                CLibUtil::Strncpy(m_caFileName, const_cast<char*>(filename), LOGGER_FILENAME_LEN);
            else
                m_caFileName[0] = '\0';
        }
        ~CLogger() { if (m_nFd > STDERR_FILENO) close(m_nFd); }

        pid_t GetPpid() { return m_nPpid; }
        void SetPpid(pid_t ppid) { m_nPpid = ppid; }

        pid_t GetPid() { return m_nPid; }
        void GetPid(pid_t pid) { m_nPid = pid; }

        std::thread::id GetTid() { return m_nTid; }
        void GetTid(std::thread::id tid) { m_nTid = tid; }

        int GetFd() { return m_nFd; }
        char* GetLogFileName() { return m_caFileName; }

        off_t GetCurSize() { return m_nCurSize; }
        int GetMaxSize() { return m_nMaxSize; }
        void SetMaxSize(int maxsize) { m_nMaxSize = maxsize; }

        virtual int DoInit();
        virtual int DoLog(int level, const char* fmt, ...) = 0;
        

    protected:
        pid_t m_nPpid; 
        pid_t m_nPid; 
        std::thread::id m_nTid; 
        int m_nFd;
        char m_caFileName[LOGGER_FILENAME_LEN];
        int m_nMaxSize;   /*unit: KB*/
        off_t m_nCurSize;
};


class CDebugLogger : public CLogger
{
    public:
        CDebugLogger() : CLogger() {}
        CDebugLogger(const char* filename) : CLogger(filename) {}

        int DoInit();
        int DoLog(int level, const char* fmt, ...);
};


class CRunningLogger : public CLogger
{
    public:
        CRunningLogger() : CLogger() {}
        CRunningLogger(const char* filename) : CLogger(filename) {}

        int DoInit();
        int DoLog(int level, const char* fmt, ...);
};



} /*namespace AT*/
#endif
