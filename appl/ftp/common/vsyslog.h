#ifndef __VSYSLOG_H__
#define __VSYSLOG_H__

#ifndef HAVE_VSYSLOG
void vsyslog(int pri, const char *fmt, ...);
#endif

#endif /* __VSYSLOG_H__ */
