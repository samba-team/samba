/*
   MIT License

   Copyright (c) 2015 TOZNY
   Copyright (c) 2020 William Brown <william@blackhats.net.au>
   Copyright (c) 2024 David Mulder <dmulder@samba.org>

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
*/
//! Interface to the pluggable authentication module framework (PAM).
//!
//! The goal of this library is to provide a type-safe API that can be used to
//! interact with PAM.  The library is incomplete - currently it supports
//! a subset of functions for use in a pam authentication module.  A pam module
//! is a shared library that is invoked to authenticate a user, or to perform
//! other functions.
//!
//! For general information on writing pam modules, see
//! [The Linux-PAM Module Writers' Guide][module-guide]
//!
//! [module-guide]: http://www.linux-pam.org/Linux-PAM-html/Linux-PAM_MWG.html
//!
//! A typical authentication module will define an external function called
//! `pam_sm_authenticate()`, which will use functions in this library to
//! interrogate the program that requested authentication for more information,
//! and to render a result.  For a working example that uses this library, see
//! [toznyauth-pam][].
//!
//! [toznyauth-pam]: https://github.com/tozny/toznyauth-pam
//!
//! Note that constants that are normally read from pam header files are
//! hard-coded in the `constants` module.  The values there are taken from
//! a Linux system.  That means that it might take some work to get this library
//! to work on other platforms.

pub mod constants;
pub mod conv;
pub mod items;
#[doc(hidden)]
pub mod macros;
pub mod module;

use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::ffi::CStr;

use dbg::*;
use param::LoadParm;
use sock::{
    stream_and_timeout, PamAuthRequest, PamAuthResponse, Request, Response,
};

use crate::pam::constants::*;
use crate::pam::conv::PamConv;
use crate::pam::module::{PamHandle, PamHooks};
use crate::pam_hooks;
use constants::PamResultCode;

use std::thread;
use std::time::Duration;

fn install_subscriber(lp: &LoadParm, debug: bool) {
    debuglevel_set!(if debug { DBGLVL_DEBUG } else { DBGLVL_ERR });
    match lp.logfile() {
        Ok(Some(logfile)) => {
            debug_set_logfile(&logfile);
            setup_logging(env!("CARGO_PKG_NAME"), DEBUG_FILE)
        }
        _ => setup_logging(env!("CARGO_PKG_NAME"), DEBUG_STDOUT),
    }
}

#[derive(Debug)]
struct Options {
    debug: bool,
    use_first_pass: bool,
    ignore_unknown_user: bool,
}

impl TryFrom<&Vec<&CStr>> for Options {
    type Error = ();

    fn try_from(args: &Vec<&CStr>) -> Result<Self, Self::Error> {
        let opts: Result<BTreeSet<&str>, _> =
            args.iter().map(|cs| cs.to_str()).collect();
        let gopts = match opts {
            Ok(o) => o,
            Err(e) => {
                println!("Error in module args -> {:?}", e);
                return Err(());
            }
        };

        Ok(Options {
            debug: gopts.contains("debug"),
            use_first_pass: gopts.contains("use_first_pass"),
            ignore_unknown_user: gopts.contains("ignore_unknown_user"),
        })
    }
}

pub struct PamHimmelblau;

pam_hooks!(PamHimmelblau);

macro_rules! match_sm_auth_client_response {
    ($expr:expr, $opts:ident, $($pat:pat => $result:expr),*) => {
        match $expr {
            Ok(r) => match r {
                $($pat => $result),*
                Response::PamAuthStepResponse(PamAuthResponse::Success) => {
                    return PamResultCode::PAM_SUCCESS;
                }
                Response::PamAuthStepResponse(PamAuthResponse::Denied) => {
                    return PamResultCode::PAM_AUTH_ERR;
                }
                Response::PamAuthStepResponse(PamAuthResponse::Unknown) => {
                    if $opts.ignore_unknown_user {
                        return PamResultCode::PAM_IGNORE;
                    } else {
                        return PamResultCode::PAM_USER_UNKNOWN;
                    }
                }
                _ => {
                    // unexpected response.
                    DBG_ERR!("PAM_IGNORE, unexpected resolver response: {:?}", r);
                    return PamResultCode::PAM_IGNORE;
                }
            },
            Err(e) => {
                DBG_ERR!("PAM_IGNORE: {:?}", e);
                return PamResultCode::PAM_IGNORE;
            }
        }
    }
}

impl PamHooks for PamHimmelblau {
    fn acct_mgmt(
        pamh: &PamHandle,
        args: Vec<&CStr>,
        _flags: PamFlag,
    ) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        let lp = match LoadParm::new(None) {
            Ok(lp) => lp,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        install_subscriber(&lp, opts.debug);

        let tty = pamh.get_tty();
        let rhost = pamh.get_rhost();

        DBG_DEBUG!("{:?} {:?} {:?} {:?} acct_mgmt", args, opts, tty, rhost);

        let account_id = match pamh.get_user(None) {
            Ok(aid) => aid,
            Err(e) => {
                DBG_ERR!("get_user: {:?}", e);
                return e;
            }
        };

        let req = Request::PamAccountAllowed(account_id);

        let (mut stream, timeout) = match stream_and_timeout(&lp) {
            Ok(res) => res,
            Err(e) => {
                DBG_ERR!("Error stream_and_timeout: {:?}", e);
                return PamResultCode::PAM_SERVICE_ERR;
            }
        };

        match stream.send(&req, timeout) {
            Ok(r) => match r {
                Response::PamStatus(Some(true)) => {
                    DBG_DEBUG!("PamResultCode::PAM_SUCCESS");
                    PamResultCode::PAM_SUCCESS
                }
                Response::PamStatus(Some(false)) => {
                    DBG_DEBUG!("PamResultCode::PAM_AUTH_ERR");
                    PamResultCode::PAM_AUTH_ERR
                }
                Response::PamStatus(None) => {
                    if opts.ignore_unknown_user {
                        DBG_DEBUG!("PamResultCode::PAM_IGNORE");
                        PamResultCode::PAM_IGNORE
                    } else {
                        DBG_DEBUG!("PamResultCode::PAM_USER_UNKNOWN");
                        PamResultCode::PAM_USER_UNKNOWN
                    }
                }
                _ => {
                    // unexpected response.
                    DBG_ERR!(
                        "PAM_IGNORE, unexpected resolver response: {:?}",
                        r
                    );
                    PamResultCode::PAM_IGNORE
                }
            },
            Err(e) => {
                DBG_ERR!("PamResultCode::PAM_IGNORE: {:?}", e);
                PamResultCode::PAM_IGNORE
            }
        }
    }

    fn sm_authenticate(
        pamh: &PamHandle,
        args: Vec<&CStr>,
        _flags: PamFlag,
    ) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        let lp = match LoadParm::new(None) {
            Ok(lp) => lp,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        install_subscriber(&lp, opts.debug);

        let tty = pamh.get_tty();
        let rhost = pamh.get_rhost();

        DBG_DEBUG!(
            "{:?} {:?} {:?} {:?} sm_authenticate",
            args,
            opts,
            tty,
            rhost
        );

        let account_id = match pamh.get_user(None) {
            Ok(aid) => aid,
            Err(e) => {
                DBG_ERR!("get_user: {:?}", e);
                return e;
            }
        };

        let (mut stream, timeout) = match stream_and_timeout(&lp) {
            Ok(res) => res,
            Err(e) => {
                DBG_ERR!("Error stream_and_timeout: {:?}", e);
                return PamResultCode::PAM_SERVICE_ERR;
            }
        };

        // Later we may need to move this to a function and call it as a oneshot for auth methods
        // that don't require any authtoks at all. For example, imagine a user authed and they
        // needed to follow a URL to continue. In that case, they would fail here because they
        // didn't enter an authtok that they didn't need!
        let mut authtok = match pamh.get_authtok() {
            Ok(Some(v)) => Some(v),
            Ok(None) => {
                if opts.use_first_pass {
                    DBG_DEBUG!("Don't have an authtok, returning PAM_AUTH_ERR");
                    return PamResultCode::PAM_AUTH_ERR;
                }
                None
            }
            Err(e) => {
                DBG_ERR!("get_authtok: {:?}", e);
                return e;
            }
        };

        let conv = match pamh.get_item::<PamConv>() {
            Ok(conv) => conv,
            Err(e) => {
                DBG_ERR!("pam_conv: {:?}", e);
                return e;
            }
        };

        let mut req = Request::PamAuthenticateInit(account_id);

        loop {
            match_sm_auth_client_response!(stream.send(&req, timeout), opts,
                Response::PamAuthStepResponse(PamAuthResponse::Password) => {
                    let mut consume_authtok = None;
                    // Swap the authtok out with a None, so it can only be consumed once.
                    // If it's already been swapped, we are just swapping two null pointers
                    // here effectively.
                    std::mem::swap(&mut authtok, &mut consume_authtok);
                    let cred = if let Some(cred) = consume_authtok {
                        cred
                    } else {
                        match conv.send(PAM_PROMPT_ECHO_OFF, "Password: ") {
                            Ok(password) => match password {
                                Some(cred) => cred,
                                None => {
                                    DBG_DEBUG!("no password");
                                    return PamResultCode::PAM_CRED_INSUFFICIENT;
                                }
                            },
                            Err(err) => {
                                DBG_DEBUG!("unable to get password");
                                return err;
                            }
                        }
                    };

                    // Now setup the request for the next loop.
                    req = Request::PamAuthenticateStep(PamAuthRequest::Password { cred });
                    continue;
                },
                Response::PamAuthStepResponse(PamAuthResponse::MFACode {
                    msg,
                }) => {
                    match conv.send(PAM_TEXT_INFO, &msg) {
                        Ok(_) => {}
                        Err(err) => {
                            if opts.debug {
                                println!("Message prompt failed");
                            }
                            return err;
                        }
                    }
                    let cred = match conv.send(PAM_PROMPT_ECHO_OFF, "Code: ") {
                        Ok(password) => match password {
                            Some(cred) => cred,
                            None => {
                                DBG_DEBUG!("no mfa code");
                                return PamResultCode::PAM_CRED_INSUFFICIENT;
                            }
                        },
                        Err(err) => {
                            DBG_DEBUG!("unable to get mfa code");
                            return err;
                        }
                    };

                    // Now setup the request for the next loop.
                    req = Request::PamAuthenticateStep(PamAuthRequest::MFACode {
                        cred,
                    });
                    continue;
                },
                Response::PamAuthStepResponse(PamAuthResponse::MFAPoll {
                    msg,
                    polling_interval,
                }) => {
                    match conv.send(PAM_TEXT_INFO, &msg) {
                        Ok(_) => {}
                        Err(err) => {
                            if opts.debug {
                                println!("Message prompt failed");
                            }
                            return err;
                        }
                    }

                    let mut poll_attempt = 0;
                    loop {
                        thread::sleep(Duration::from_secs(polling_interval.into()));
                        req = Request::PamAuthenticateStep(
                            PamAuthRequest::MFAPoll { poll_attempt }
                        );

                        match_sm_auth_client_response!(
                            stream.send(&req, timeout), opts,
                            Response::PamAuthStepResponse(
                                    PamAuthResponse::MFAPollWait,
                            ) => {
                                // Continue polling if the daemon says to wait
                                poll_attempt += 1;
                                continue;
                            }
                        );
                    }
                },
                Response::PamAuthStepResponse(PamAuthResponse::SetupPin {
                    msg,
                }) => {
                    match conv.send(PAM_TEXT_INFO, &msg) {
                        Ok(_) => {}
                        Err(err) => {
                            if opts.debug {
                                println!("Message prompt failed");
                            }
                            return err;
                        }
                    }

                    let mut pin;
                    let mut confirm;
                    loop {
                        pin = match conv.send(PAM_PROMPT_ECHO_OFF, "New PIN: ") {
                            Ok(password) => match password {
                                Some(cred) => cred,
                                None => {
                                    DBG_DEBUG!("no pin");
                                    return PamResultCode::PAM_CRED_INSUFFICIENT;
                                }
                            },
                            Err(err) => {
                                DBG_DEBUG!("unable to get pin");
                                return err;
                            }
                        };

                        confirm = match conv.send(PAM_PROMPT_ECHO_OFF, "Confirm PIN: ") {
                            Ok(password) => match password {
                                Some(cred) => cred,
                                None => {
                                    DBG_DEBUG!("no confirmation pin");
                                    return PamResultCode::PAM_CRED_INSUFFICIENT;
                                }
                            },
                            Err(err) => {
                                DBG_DEBUG!("unable to get confirmation pin");
                                return err;
                            }
                        };

                        if pin == confirm {
                            break;
                        } else {
                            match conv.send(PAM_TEXT_INFO, "Inputs did not match. Try again.") {
                                Ok(_) => {}
                                Err(err) => {
                                    if opts.debug {
                                        println!("Message prompt failed");
                                    }
                                    return err;
                                }
                            }
                        }
                    }

                    // Now setup the request for the next loop.
                    req = Request::PamAuthenticateStep(PamAuthRequest::SetupPin {
                        pin,
                    });
                    continue;
                },
                Response::PamAuthStepResponse(PamAuthResponse::Pin) => {
                    let mut consume_authtok = None;
                    // Swap the authtok out with a None, so it can only be consumed once.
                    // If it's already been swapped, we are just swapping two null pointers
                    // here effectively.
                    std::mem::swap(&mut authtok, &mut consume_authtok);
                    let cred = if let Some(cred) = consume_authtok {
                        cred
                    } else {
                        match conv.send(PAM_PROMPT_ECHO_OFF, "PIN: ") {
                            Ok(password) => match password {
                                Some(cred) => cred,
                                None => {
                                    DBG_DEBUG!("no pin");
                                    return PamResultCode::PAM_CRED_INSUFFICIENT;
                                }
                            },
                            Err(err) => {
                                DBG_DEBUG!("unable to get pin");
                                return err;
                            }
                        }
                    };

                    // Now setup the request for the next loop.
                    req = Request::PamAuthenticateStep(PamAuthRequest::Pin { pin: cred });
                    continue;
                }
            );
        } // while true, continue calling PamAuthenticateStep until we get a decision.
    }

    fn sm_chauthtok(
        _pamh: &PamHandle,
        args: Vec<&CStr>,
        _flags: PamFlag,
    ) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        let lp = match LoadParm::new(None) {
            Ok(lp) => lp,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        install_subscriber(&lp, opts.debug);

        DBG_DEBUG!("{:?} {:?} sm_chauthtok", args, opts);

        PamResultCode::PAM_IGNORE
    }

    fn sm_close_session(
        _pamh: &PamHandle,
        args: Vec<&CStr>,
        _flags: PamFlag,
    ) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        let lp = match LoadParm::new(None) {
            Ok(lp) => lp,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        install_subscriber(&lp, opts.debug);

        DBG_DEBUG!("{:?} {:?} sm_close_session", args, opts);

        PamResultCode::PAM_SUCCESS
    }

    fn sm_open_session(
        pamh: &PamHandle,
        args: Vec<&CStr>,
        _flags: PamFlag,
    ) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        let lp = match LoadParm::new(None) {
            Ok(lp) => lp,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        install_subscriber(&lp, opts.debug);

        DBG_DEBUG!("{:?} {:?} sm_open_session", args, opts);

        let account_id = match pamh.get_user(None) {
            Ok(aid) => aid,
            Err(e) => {
                DBG_ERR!("get_user: {:?}", e);
                return e;
            }
        };

        let req = Request::PamAccountBeginSession(account_id);

        let (mut stream, timeout) = match stream_and_timeout(&lp) {
            Ok(res) => res,
            Err(e) => {
                DBG_ERR!("Error stream_and_timeout: {:?}", e);
                return PamResultCode::PAM_SERVICE_ERR;
            }
        };

        match stream.send(&req, timeout) {
            Ok(Response::Success) => PamResultCode::PAM_SUCCESS,
            other => {
                DBG_DEBUG!("PAM_IGNORE: {:?}", other);
                PamResultCode::PAM_IGNORE
            }
        }
    }

    fn sm_setcred(
        _pamh: &PamHandle,
        args: Vec<&CStr>,
        _flags: PamFlag,
    ) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        let lp = match LoadParm::new(None) {
            Ok(lp) => lp,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        install_subscriber(&lp, opts.debug);

        DBG_DEBUG!("{:?} {:?} sm_setcred", args, opts);

        PamResultCode::PAM_SUCCESS
    }
}
