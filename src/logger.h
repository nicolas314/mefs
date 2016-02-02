/*-------------------------------------------------------------------------*/
/**
   @file    logger.h
   @date    Sep 2007
   @version	$Revision: 1.2 $
   @brief

   Logging routines: allow to simultaneously output messages to console
   and to logfile.
*/
/*--------------------------------------------------------------------------*/

/*
	$Id: logger.h,v 1.2 2008/01/03 11:26:27 nicoldev Exp $
	$Date: 2008/01/03 11:26:27 $
*/
#ifndef _LOGGER_H_
#define _LOGGER_H_

/*-------------------------------------------------------------------------*/
/**
  @brief    Change default log file name
  @param    filename    New log file name
  @return   void

  Use this function to change the log file name.
 */
/*--------------------------------------------------------------------------*/
void logger_setname(char * filename);

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
void logger(char * fmt, ...);

#endif
/* vim: set ts=4 et sw=4 tw=75 */
