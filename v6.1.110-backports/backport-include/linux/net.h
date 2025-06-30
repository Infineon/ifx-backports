#ifndef __BACKPORT_LINUX_NET_H
#define __BACKPORT_LINUX_NET_H
#include_next <linux/net.h>
#include <linux/static_key.h>


#ifndef SOCKWQ_ASYNC_NOSPACE
#define SOCKWQ_ASYNC_NOSPACE   SOCK_ASYNC_NOSPACE
#endif
#ifndef SOCKWQ_ASYNC_WAITDATA
#define SOCKWQ_ASYNC_WAITDATA   SOCK_ASYNC_WAITDATA
#endif

#endif /* __BACKPORT_LINUX_NET_H */
