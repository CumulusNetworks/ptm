/* Copyright 2010 Cumulus Networks, LLC.  All rights reserved.
 * Copyright 2015,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 */

#ifndef _LOG_H_
#define _LOG_H_

#include "syslog.h"

extern int g_log_level;

/*
 * DLOG            Used for debug messages.  Information that is diagnostically 
 *                 helpful to people more than just developers (IT, sysadmins,
 *                 etc).
 * 
 * INFOLOG         Informational messages.  Generally useful information to log 
 *                 (service start/stop, configuration assumptions, etc).
 * 
 * WARNLOG         Warnings about problematic situations that do not, in 
 *                 themselves, create serious problems with the system, 
 *                 and are automatically recovered from.  May lead to 
 *                 ERRLOG/CRITLOG conditions down the road.
 * 
 * ERRLOG          Any error which is fatal to the operation but not the 
 *                 service or application (can't open a required file, missing 
 *                 data, etc). These errors will force user (administrator, 
 *                 or direct user) intervention.
 * 
 * CRITLOG         Critical conditions, often related to serious hardware 
 *                 or software failures.
 * 
 * LOG             Use for messages that should always appear, regardless
 *                 of current log level.
 */

#define INFOLOG(fmt, ...) if (LOG_INFO <= g_log_level) \
                                syslog(LOG_INFO, fmt, ##__VA_ARGS__)
#define WARNLOG(fmt, ...) if (LOG_WARNING <= g_log_level) \
                                syslog(LOG_WARNING, fmt, ##__VA_ARGS__)
#define ERRLOG(fmt, ...) if (LOG_ERR <= g_log_level) \
                                syslog(LOG_ERR, fmt, ##__VA_ARGS__)
#define CRITLOG(fmt, ...) if (LOG_CRIT <= g_log_level) \
                                syslog(LOG_CRIT, fmt, ##__VA_ARGS__)
#define LOG(fmt, ...) syslog(LOG_INFO, fmt, ##__VA_ARGS__)
#define DLOG(fmt, ...) if (LOG_DEBUG <= g_log_level) \
                                syslog(LOG_DEBUG, fmt, ##__VA_ARGS__)

#endif
