/*
   MIT License

   Copyright (c) 2015 TOZNY

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
use crate::pam::constants::{
    PamItemType, PAM_AUTHTOK, PAM_OLDAUTHTOK, PAM_RHOST, PAM_RUSER,
    PAM_SERVICE, PAM_TTY, PAM_USER, PAM_USER_PROMPT,
};
pub use crate::pam::conv::PamConv;
use crate::pam::module::PamItem;

#[allow(dead_code)]
pub struct PamService {}

impl PamItem for PamService {
    fn item_type() -> PamItemType {
        PAM_SERVICE
    }
}

#[allow(dead_code)]
pub struct PamUser {}

impl PamItem for PamUser {
    fn item_type() -> PamItemType {
        PAM_USER
    }
}

#[allow(dead_code)]
pub struct PamUserPrompt {}

impl PamItem for PamUserPrompt {
    fn item_type() -> PamItemType {
        PAM_USER_PROMPT
    }
}

#[allow(dead_code)]
pub struct PamTty {}

impl PamItem for PamTty {
    fn item_type() -> PamItemType {
        PAM_TTY
    }
}

#[allow(dead_code)]
pub struct PamRUser {}

impl PamItem for PamRUser {
    fn item_type() -> PamItemType {
        PAM_RUSER
    }
}

#[allow(dead_code)]
pub struct PamRHost {}

impl PamItem for PamRHost {
    fn item_type() -> PamItemType {
        PAM_RHOST
    }
}

#[allow(dead_code)]
pub struct PamAuthTok {}

impl PamItem for PamAuthTok {
    fn item_type() -> PamItemType {
        PAM_AUTHTOK
    }
}

#[allow(dead_code)]
pub struct PamOldAuthTok {}

impl PamItem for PamOldAuthTok {
    fn item_type() -> PamItemType {
        PAM_OLDAUTHTOK
    }
}
