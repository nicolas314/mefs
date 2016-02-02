/*-------------------------------------------------------------------------*/
/**
   @file    logger.c
   @date    Sep 2007
   @brief

   Logging routines: allow to simultaneously output messages to console
   and to logfile.
*/
/*--------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------
   								Includes
 ---------------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

/*---------------------------------------------------------------------------
                            Constants & Defines
 ---------------------------------------------------------------------------*/
/** Maximum size of a log file name */
#define LOGFILENAME_SZ  1024
/** Maximum size of a single log message */
#define LOGSZ   1024

/** Default log file name */
char logger_filename[LOGFILENAME_SZ] = {"/tmp/mefs.log"} ;

/*---------------------------------------------------------------------------
							Private to this module
 ---------------------------------------------------------------------------*/

#define DATETIME_SZ 64
static char * datetime_now(void)
{
    static char datetime[DATETIME_SZ] ;
    time_t      t ;
    struct tm * tmp ;

    t = time(NULL);
    tmp = localtime(&t);
    strftime(datetime,
             DATETIME_SZ,
             "%Y-%m-%d %T",
             tmp);
    return datetime ;
}


/*---------------------------------------------------------------------------
  							Function codes
 ---------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------*/
/**
  @brief	Change default log file name
  @param    filename    New log file name
  @return   void

  Use this function to change the log file name.
 */
/*--------------------------------------------------------------------------*/
void logger_setname(char * filename)
{
    /* Set new log file name if non-NULL */
    if (filename && filename[0]) {
        strcpy(logger_filename, filename) ;
    }
    return ;
}

/*-------------------------------------------------------------------------*/
/**
  @brief	Main logging function
  @param    fmt     Formatting string a la printf
  @param    ...     Variable-length list
  @return   void

  Use this function as a printf. Your message will be printed out to
  stderr and logged to a file.
 */
/*--------------------------------------------------------------------------*/
void logger(char * fmt, ...)
{
    FILE *  lf ;
    char *  now ;
    char    logmsg[LOGSZ] ; 
    va_list ap ; 
 
    va_start(ap, fmt); 
    vsprintf(logmsg, fmt, ap) ; 
    va_end(ap) ; 

    now = datetime_now() ;
    fprintf(stderr, "%s %s\n", now, logmsg);

    if ((lf=fopen(logger_filename, "a"))!=NULL) {
        fprintf(lf, "%s %s\n", now, logmsg);
        fclose(lf);
    }
    return ;
}

#ifdef MAIN
int main(int argc, char * argv[])
{
    logger("hello %s %d %g\n", "world", 42, 1.5);
	return 0 ;
}
#endif

/* vim: set ts=4 et sw=4 tw=75 */
