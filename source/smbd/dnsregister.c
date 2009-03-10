/*
   Unix SMB/CIFS implementation.
   DNS-SD registration
   Copyright (C) Rishi Srivatsavai 2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <includes.h>

/* Uses DNS service discovery (libdns_sd) to
 * register the SMB service. SMB service is registered
 * on ".local" domain via Multicast DNS & any
 * other unicast DNS domains available.
 *
 * Users use the smbclient -B (Browse) option to
 * browse for advertised SMB services.
 */

#define DNS_REG_RETRY_INTERVAL (5*60)  /* in seconds */

#ifdef WITH_DNSSD_SUPPORT

#include <dns_sd.h>

struct dns_reg_state {
	DNSServiceRef srv_ref;
	struct timed_event *retry_handler;
};

void dns_register_close(struct dns_reg_state **dns_state_ptr)
{
	struct dns_reg_state *dns_state = *dns_state_ptr;

	if (dns_state == NULL) {
		return;
	}

	if (dns_state->srv_ref != NULL) {
		/* Close connection to the mDNS daemon */
		DNSServiceRefDeallocate(dns_state->srv_ref);
		dns_state->srv_ref = NULL;
	}

	/* Clear event handler */
	if (dns_state->retry_handler != NULL) {
		TALLOC_FREE(dns_state->retry_handler);
		dns_state->retry_handler = NULL;
	}

	talloc_free(dns_state);
	*dns_state_ptr = NULL;
}

static void dns_register_smbd_retry(struct event_context *ctx,
                                   struct timed_event *te,
                                   struct timeval now,
                                   void *private_data)
{
	struct dns_reg_state *dns_state = (struct dns_reg_state *)private_data;

	/* Clear previous registration state to force new
	 * registration attempt. Clears event handler.
	 */
	dns_register_close(&dns_state);
}

static void schedule_dns_register_smbd_retry(struct dns_reg_state *dns_state,
		struct timeval *timeout)
{
	struct timed_event * event;

	dns_state->srv_ref = NULL;
	event= event_add_timed(smbd_event_context(),
			NULL,
			timeval_current_ofs(DNS_REG_RETRY_INTERVAL, 0),
			dns_register_smbd_retry,
			dns_state);

	dns_state->retry_handler = event;
	get_timed_events_timeout(smbd_event_context(), timeout);
}

/* Kick off a mDNS request to register the "_smb._tcp" on the specified port.
 * We really ought to register on all the ports we are listening on. This will
 * have to be an exercise for some-one who knows the DNS registration API a bit
 * better.
 */
void dns_register_smbd(struct dns_reg_state ** dns_state_ptr,
		unsigned port,
		int *maxfd,
		fd_set *listen_set,
		struct timeval *timeout)
{
	int mdnsd_conn_fd;
	DNSServiceErrorType err;
	struct dns_reg_state *dns_state = *dns_state_ptr;

	if (dns_state == NULL) {
		dns_state = talloc_zero(NULL, struct dns_reg_state);
		*dns_state_ptr = dns_state;
		if (dns_state == NULL) {
			return;
		}
	}

	/* Quit if a re-try attempt has been scheduled.  */
	if (dns_state->retry_handler != NULL) {
		return;
	}

	/* If a registration is active add conn
	 * fd to select listen_set and return
	 */
	if (dns_state->srv_ref != NULL) {
		mdnsd_conn_fd = DNSServiceRefSockFD(dns_state->srv_ref);
		FD_SET(mdnsd_conn_fd, listen_set);
		return;
	}

	DEBUG(6, ("registering _smb._tcp service on port %d\n", port));

	/* Register service with DNS. Connects with the mDNS
	 * daemon running on the local system to perform DNS
	 * service registration.
	 */
	err = DNSServiceRegister(&dns_state->srv_ref, 0 /* flags */,
			kDNSServiceInterfaceIndexAny,
			NULL /* service name */,
			"_smb._tcp" /* service type */,
			NULL /* domain */,
			"" /* SRV target host name */,
			htons(port),
			0 /* TXT record len */,
			NULL /* TXT record data */,
			NULL /* callback func */,
			NULL /* callback context */);

	if (err != kDNSServiceErr_NoError) {
		/* Failed to register service. Schedule a re-try attempt.
		 */
		DEBUG(3, ("unable to register with mDNS (err %d)\n", err));
		schedule_dns_register_smbd_retry(dns_state, timeout);
		return;
	}

	mdnsd_conn_fd = DNSServiceRefSockFD(dns_state->srv_ref);
	FD_SET(mdnsd_conn_fd, listen_set);
	*maxfd = MAX(*maxfd, mdnsd_conn_fd);
	*timeout = timeval_zero();

}

/* Processes reply from mDNS daemon. Returns true if a reply was received */
bool dns_register_smbd_reply(struct dns_reg_state *dns_state,
		fd_set *lfds, struct timeval *timeout)
{
	int mdnsd_conn_fd = -1;

	if (dns_state->srv_ref == NULL) {
		return false;
	}

	mdnsd_conn_fd = DNSServiceRefSockFD(dns_state->srv_ref);

	/* Process reply from daemon. Handles any errors. */
	if ((mdnsd_conn_fd != -1) && (FD_ISSET(mdnsd_conn_fd,lfds)) ) {
		DNSServiceErrorType err;
		
		err = DNSServiceProcessResult(dns_state->srv_ref);
		if (err != kDNSServiceErr_NoError) {
			DEBUG(3, ("failed to process mDNS result (err %d), re-trying\n",
				    err));
			schedule_dns_register_smbd_retry(dns_state, timeout);
		}

		return true;
	}

	return false;
}

#else /* WITH_DNSSD_SUPPORT */

 void dns_register_smbd(struct dns_reg_state ** dns_state_ptr,
		unsigned port,
		int *maxfd,
		fd_set *listen_set,
		struct timeval *timeout)
{}

 void dns_register_close(struct dns_reg_state ** dns_state_ptr)
{}

 bool dns_register_smbd_reply(struct dns_reg_state *dns_state,
		fd_set *lfds, struct timeval *timeout)
{
	return false;
}

#endif /* WITH_DNSSD_SUPPORT */
