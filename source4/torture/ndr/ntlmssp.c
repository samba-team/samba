/*
   Unix SMB/CIFS implementation.
   test suite for ntlmssp ndr operations

   Copyright (C) Guenther Deschner 2010,2015

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

#include "includes.h"
#include "torture/ndr/ndr.h"
#include "librpc/gen_ndr/ndr_ntlmssp.h"
#include "torture/ndr/proto.h"

static const uint8_t ntlmssp_NEGOTIATE_MESSAGE_data[] = {
	0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x97, 0x82, 0x08, 0xe2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x01, 0xb0, 0x1d,
	0x00, 0x00, 0x00, 0x0f
};

static bool ntlmssp_NEGOTIATE_MESSAGE_check(struct torture_context *tctx,
					    struct NEGOTIATE_MESSAGE *r)
{
	torture_assert_str_equal(tctx, r->Signature, "NTLMSSP", "Signature");
	torture_assert_int_equal(tctx, r->MessageType, NtLmNegotiate, "MessageType");
	torture_assert_int_equal(tctx, r->NegotiateFlags, 0xe2088297, "NegotiateFlags");
	torture_assert_int_equal(tctx, r->DomainNameLen, 0, "DomainNameLen");
	torture_assert_int_equal(tctx, r->DomainNameMaxLen, 0, "DomainNameMaxLen");
	torture_assert(tctx, r->DomainName == NULL, "DomainName");
	torture_assert_int_equal(tctx, r->WorkstationLen, 0, "WorkstationLen");
	torture_assert_int_equal(tctx, r->WorkstationMaxLen, 0, "WorkstationMaxLen");
	torture_assert(tctx, r->Workstation == NULL, "Workstation");
	torture_assert_int_equal(tctx, r->Version.version.ProductMajorVersion, NTLMSSP_WINDOWS_MAJOR_VERSION_6, "ProductMajorVersion");
	torture_assert_int_equal(tctx, r->Version.version.ProductMinorVersion, NTLMSSP_WINDOWS_MINOR_VERSION_1, "ProductMinorVersion");
	torture_assert_int_equal(tctx, r->Version.version.ProductBuild, 0x1db0, "ProductBuild");
	torture_assert_int_equal(tctx, r->Version.version.Reserved[0], 0x00, "Reserved");
	torture_assert_int_equal(tctx, r->Version.version.Reserved[1], 0x00, "Reserved");
	torture_assert_int_equal(tctx, r->Version.version.Reserved[2], 0x00, "Reserved");
	torture_assert_int_equal(tctx, r->Version.version.NTLMRevisionCurrent, NTLMSSP_REVISION_W2K3, "NTLMRevisionCurrent");

	return true;
}

static const uint8_t ntlmssp_CHALLENGE_MESSAGE_data[] = {
	0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x0a, 0x00, 0x0a, 0x00, 0x38, 0x00, 0x00, 0x00, 0x95, 0x82, 0x89, 0xe2,
	0xed, 0xc8, 0x2b, 0x7d, 0x2e, 0xd7, 0xd0, 0xd9, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x78, 0x00, 0x78, 0x00, 0x42, 0x00, 0x00, 0x00,
	0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x53, 0x00, 0x41, 0x00,
	0x4d, 0x00, 0x42, 0x00, 0x41, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x53, 0x00,
	0x41, 0x00, 0x4d, 0x00, 0x42, 0x00, 0x41, 0x00, 0x01, 0x00, 0x10, 0x00,
	0x4d, 0x00, 0x54, 0x00, 0x48, 0x00, 0x45, 0x00, 0x4c, 0x00, 0x45, 0x00,
	0x4e, 0x00, 0x41, 0x00, 0x04, 0x00, 0x1c, 0x00, 0x62, 0x00, 0x65, 0x00,
	0x72, 0x00, 0x2e, 0x00, 0x72, 0x00, 0x65, 0x00, 0x64, 0x00, 0x68, 0x00,
	0x61, 0x00, 0x74, 0x00, 0x2e, 0x00, 0x63, 0x00, 0x6f, 0x00, 0x6d, 0x00,
	0x03, 0x00, 0x2e, 0x00, 0x6d, 0x00, 0x74, 0x00, 0x68, 0x00, 0x65, 0x00,
	0x6c, 0x00, 0x65, 0x00, 0x6e, 0x00, 0x61, 0x00, 0x2e, 0x00, 0x62, 0x00,
	0x65, 0x00, 0x72, 0x00, 0x2e, 0x00, 0x72, 0x00, 0x65, 0x00, 0x64, 0x00,
	0x68, 0x00, 0x61, 0x00, 0x74, 0x00, 0x2e, 0x00, 0x63, 0x00, 0x6f, 0x00,
	0x6d, 0x00, 0x00, 0x00, 0x00, 0x00
};

static bool ntlmssp_CHALLENGE_MESSAGE_check(struct torture_context *tctx,
					    struct CHALLENGE_MESSAGE *r)
{
	uint8_t chal[8] = { 0xed, 0xc8, 0x2b, 0x7d, 0x2e, 0xd7, 0xd0, 0xd9 };
	uint8_t data[8] = { 0 };

	torture_assert_str_equal(tctx, r->Signature, "NTLMSSP", "Signature");
	torture_assert_int_equal(tctx, r->MessageType, NtLmChallenge, "MessageType");
	torture_assert_int_equal(tctx, r->TargetNameLen, 10, "TargetNameLen");
	torture_assert_int_equal(tctx, r->TargetNameMaxLen, 10, "TargetNameMaxLen");
	torture_assert_str_equal(tctx, r->TargetName, "SAMBA", "TargetName");
	torture_assert_int_equal(tctx, r->NegotiateFlags, 0xe2898295, "NegotiateFlags");
	torture_assert_mem_equal(tctx, r->ServerChallenge, chal, 8, "ServerChallenge");
	torture_assert_mem_equal(tctx, r->Reserved, data, 8, "Reserved");
	torture_assert_int_equal(tctx, r->TargetInfoLen, 120, "TargetInfoLen");
	torture_assert_int_equal(tctx, r->TargetInfoMaxLen, 120, "TargetInfoMaxLen");
	torture_assert_int_equal(tctx, r->TargetInfo->count, 5, "TargetInfo->count");

	torture_assert_int_equal(tctx, r->TargetInfo->pair[0].AvId, MsvAvNbDomainName, "AvId");
	torture_assert_int_equal(tctx, r->TargetInfo->pair[0].AvLen, 10, "AvLen");
	torture_assert_str_equal(tctx, r->TargetInfo->pair[0].Value.AvNbDomainName, "SAMBA", "AvNbDomainName");

	torture_assert_int_equal(tctx, r->TargetInfo->pair[1].AvId, MsvAvNbComputerName, "AvId");
	torture_assert_int_equal(tctx, r->TargetInfo->pair[1].AvLen, 16, "AvLen");
	torture_assert_str_equal(tctx, r->TargetInfo->pair[1].Value.AvNbComputerName, "MTHELENA", "AvNbComputerName");

	torture_assert_int_equal(tctx, r->TargetInfo->pair[2].AvId, MsvAvDnsDomainName, "AvId");
	torture_assert_int_equal(tctx, r->TargetInfo->pair[2].AvLen, 28, "AvLen");
	torture_assert_str_equal(tctx, r->TargetInfo->pair[2].Value.AvDnsDomainName, "ber.redhat.com", "AvDnsDomainName");

	torture_assert_int_equal(tctx, r->TargetInfo->pair[3].AvId, MsvAvDnsComputerName, "AvId");
	torture_assert_int_equal(tctx, r->TargetInfo->pair[3].AvLen, 46, "AvLen");
	torture_assert_str_equal(tctx, r->TargetInfo->pair[3].Value.AvDnsComputerName, "mthelena.ber.redhat.com", "AvDnsComputerName");

	torture_assert_int_equal(tctx, r->TargetInfo->pair[4].AvId, MsvAvEOL, "AvId");
	torture_assert_int_equal(tctx, r->TargetInfo->pair[4].AvLen, 0, "AvLen");

	torture_assert_int_equal(tctx, r->Version.version.ProductMajorVersion, NTLMSSP_WINDOWS_MAJOR_VERSION_6, "ProductMajorVersion");
	torture_assert_int_equal(tctx, r->Version.version.ProductMinorVersion, NTLMSSP_WINDOWS_MINOR_VERSION_1, "ProductMinorVersion");
	torture_assert_int_equal(tctx, r->Version.version.ProductBuild, 0, "ProductBuild");
	torture_assert_int_equal(tctx, r->Version.version.Reserved[0], 0x00, "Reserved");
	torture_assert_int_equal(tctx, r->Version.version.Reserved[1], 0x00, "Reserved");
	torture_assert_int_equal(tctx, r->Version.version.Reserved[2], 0x00, "Reserved");
	torture_assert_int_equal(tctx, r->Version.version.NTLMRevisionCurrent, NTLMSSP_REVISION_W2K3, "NTLMRevisionCurrent");

	return true;
}

static const uint8_t ntlmssp_AUTHENTICATE_MESSAGE_data[] = {
	0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00,
	0x18, 0x00, 0x18, 0x00, 0x8c, 0x00, 0x00, 0x00, 0x0e, 0x01, 0x0e, 0x01,
	0xa4, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x0e, 0x00, 0x58, 0x00, 0x00, 0x00,
	0x1a, 0x00, 0x1a, 0x00, 0x66, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0c, 0x00,
	0x80, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00, 0xb2, 0x01, 0x00, 0x00,
	0x15, 0x82, 0x88, 0xe2, 0x06, 0x01, 0xb0, 0x1d, 0x00, 0x00, 0x00, 0x0f,
	0x50, 0xe2, 0xb2, 0xa7, 0xf5, 0x83, 0x3e, 0xda, 0x71, 0xa7, 0xe8, 0x6e,
	0x95, 0x1e, 0x3a, 0x57, 0x57, 0x00, 0x32, 0x00, 0x4b, 0x00, 0x38, 0x00,
	0x44, 0x00, 0x4f, 0x00, 0x4d, 0x00, 0x41, 0x00, 0x64, 0x00, 0x6d, 0x00,
	0x69, 0x00, 0x6e, 0x00, 0x69, 0x00, 0x73, 0x00, 0x74, 0x00, 0x72, 0x00,
	0x61, 0x00, 0x74, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x57, 0x00, 0x32, 0x00,
	0x4b, 0x00, 0x38, 0x00, 0x52, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0xcf, 0xfb, 0x39,
	0x5a, 0xb3, 0x4c, 0x58, 0x86, 0x35, 0xa3, 0xe7, 0x1e, 0x00, 0x98, 0x43,
	0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x96, 0x79, 0x02, 0x77,
	0x1e, 0x54, 0xcb, 0x01, 0x3c, 0x21, 0x0a, 0xe9, 0xde, 0x61, 0xc0, 0x7e,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x53, 0x00, 0x41, 0x00,
	0x4d, 0x00, 0x42, 0x00, 0x41, 0x00, 0x01, 0x00, 0x10, 0x00, 0x4d, 0x00,
	0x54, 0x00, 0x48, 0x00, 0x45, 0x00, 0x4c, 0x00, 0x45, 0x00, 0x4e, 0x00,
	0x41, 0x00, 0x04, 0x00, 0x1c, 0x00, 0x62, 0x00, 0x65, 0x00, 0x72, 0x00,
	0x2e, 0x00, 0x72, 0x00, 0x65, 0x00, 0x64, 0x00, 0x68, 0x00, 0x61, 0x00,
	0x74, 0x00, 0x2e, 0x00, 0x63, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x03, 0x00,
	0x2e, 0x00, 0x6d, 0x00, 0x74, 0x00, 0x68, 0x00, 0x65, 0x00, 0x6c, 0x00,
	0x65, 0x00, 0x6e, 0x00, 0x61, 0x00, 0x2e, 0x00, 0x62, 0x00, 0x65, 0x00,
	0x72, 0x00, 0x2e, 0x00, 0x72, 0x00, 0x65, 0x00, 0x64, 0x00, 0x68, 0x00,
	0x61, 0x00, 0x74, 0x00, 0x2e, 0x00, 0x63, 0x00, 0x6f, 0x00, 0x6d, 0x00,
	0x08, 0x00, 0x30, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x0a, 0xfd, 0x3b, 0x2c,
	0xad, 0x43, 0x46, 0x8b, 0x49, 0x01, 0x6c, 0xa5, 0xf3, 0xbc, 0xd2, 0x13,
	0xbb, 0x70, 0xe2, 0x65, 0x96, 0xba, 0x0d, 0x8d, 0x5d, 0x31, 0xe6, 0x47,
	0x94, 0x61, 0xed, 0x28, 0x0a, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x09, 0x00, 0x1a, 0x00, 0x63, 0x00, 0x69, 0x00, 0x66, 0x00, 0x73, 0x00,
	0x2f, 0x00, 0x6d, 0x00, 0x74, 0x00, 0x68, 0x00, 0x65, 0x00, 0x6c, 0x00,
	0x65, 0x00, 0x6e, 0x00, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0xa4, 0x23, 0xd4, 0x5c, 0x16, 0x52, 0x8d, 0x56, 0x34, 0x2d,
	0x1c, 0xff, 0x86, 0x17, 0xc9, 0x4f
};

static bool ntlmssp_AUTHENTICATE_MESSAGE_check(struct torture_context *tctx,
					       struct AUTHENTICATE_MESSAGE *r)
{
	uint8_t lm_challenge_response[24] = { 0 };
	struct NTLMv2_RESPONSE v2;
	struct AV_PAIR_LIST AvPairs;
	uint8_t Response[16] = {
		0x38, 0xcf, 0xfb, 0x39, 0x5a, 0xb3, 0x4c, 0x58,
		0x86, 0x35, 0xa3, 0xe7, 0x1e, 0x00, 0x98, 0x43
	};
	uint8_t ChallengeFromClient[8] = {
		0x3c, 0x21, 0x0a, 0xe9, 0xde, 0x61, 0xc0, 0x7e
	};
	uint8_t MachineId[32] = {
		0x0a, 0xfd, 0x3b, 0x2c, 0xad, 0x43, 0x46, 0x8b,
		0x49, 0x01, 0x6c, 0xa5, 0xf3, 0xbc, 0xd2, 0x13,
		0xbb, 0x70, 0xe2, 0x65, 0x96, 0xba, 0x0d, 0x8d,
		0x5d, 0x31, 0xe6, 0x47, 0x94, 0x61, 0xed, 0x28
	};
	uint8_t EncryptedRandomSessionKey[16] = {
		0xA4, 0x23, 0xD4, 0x5C, 0x16, 0x52, 0x8D, 0x56,
		0x34, 0x2D, 0x1C, 0xFF, 0x86, 0x17, 0xC9, 0x4F
	};

	torture_assert_str_equal(tctx, r->Signature, "NTLMSSP", "Signature");
	torture_assert_int_equal(tctx, r->MessageType, NtLmAuthenticate, "MessageType");
	torture_assert_int_equal(tctx, r->LmChallengeResponseLen, 24, "LmChallengeResponseLen");
	torture_assert_int_equal(tctx, r->LmChallengeResponseMaxLen, 24, "LmChallengeResponseMaxLen");
	torture_assert_mem_equal(tctx, r->LmChallengeResponse->v1.Response, lm_challenge_response, 24, "LmChallengeResponse");

	torture_assert_int_equal(tctx, r->NtChallengeResponseLen, 270, "NtChallengeResponseLen");
	torture_assert_int_equal(tctx, r->NtChallengeResponseMaxLen, 270, "NtChallengeResponseMaxLen");

	v2 = r->NtChallengeResponse->v2;

	torture_assert_mem_equal(tctx, v2.Response, Response, 16, "v2.Response");
	torture_assert_int_equal(tctx, v2.Challenge.RespType, 1, "RespType");
	torture_assert_int_equal(tctx, v2.Challenge.HiRespType, 1, "HiRespType");
	torture_assert_int_equal(tctx, v2.Challenge.Reserved1, 0, "Reserved1");
	torture_assert_int_equal(tctx, v2.Challenge.Reserved2, 0, "Reserved2");
	/* 	TimeStamp                : Tue Sep 14 17:06:53 2010 CEST */
	torture_assert_mem_equal(tctx, v2.Challenge.ChallengeFromClient, ChallengeFromClient, 8, "v2.Challenge.ChallengeFromClient");
	torture_assert_int_equal(tctx, v2.Challenge.Reserved3, 0, "Reserved3");

	AvPairs = v2.Challenge.AvPairs;

	torture_assert_int_equal(tctx, AvPairs.count, 8, "AvPairs.count");

	torture_assert_int_equal(tctx, AvPairs.pair[0].AvId, MsvAvNbDomainName, "AvId");
	torture_assert_int_equal(tctx, AvPairs.pair[0].AvLen, 10, "AvLen");
	torture_assert_str_equal(tctx, AvPairs.pair[0].Value.AvNbDomainName, "SAMBA", "Value.AvNbDomainName");

	torture_assert_int_equal(tctx, AvPairs.pair[1].AvId, MsvAvNbComputerName, "AvId");
	torture_assert_int_equal(tctx, AvPairs.pair[1].AvLen, 16, "AvLen");
	torture_assert_str_equal(tctx, AvPairs.pair[1].Value.AvNbComputerName, "MTHELENA", "Value.AvNbComputerName");

	torture_assert_int_equal(tctx, AvPairs.pair[2].AvId, MsvAvDnsDomainName, "AvId");
	torture_assert_int_equal(tctx, AvPairs.pair[2].AvLen, 28, "AvLen");
	torture_assert_str_equal(tctx, AvPairs.pair[2].Value.AvDnsDomainName, "ber.redhat.com", "Value.AvDnsDomainName");

	torture_assert_int_equal(tctx, AvPairs.pair[3].AvId, MsvAvDnsComputerName, "AvId");
	torture_assert_int_equal(tctx, AvPairs.pair[3].AvLen, 46, "AvLen");
	torture_assert_str_equal(tctx, AvPairs.pair[3].Value.AvDnsComputerName, "mthelena.ber.redhat.com", "Value.AvDnsComputerName");

	torture_assert_int_equal(tctx, AvPairs.pair[4].AvId, MsvAvSingleHost, "AvId");
	torture_assert_int_equal(tctx, AvPairs.pair[4].AvLen, 48, "AvLen");
	torture_assert_int_equal(tctx, AvPairs.pair[4].Value.AvSingleHost.Size, 48, "Value.AvSingleHost.Size");
	torture_assert_int_equal(tctx, AvPairs.pair[4].Value.AvSingleHost.Z4, 0, "Value.AvSingleHost.Z4");
	torture_assert_int_equal(tctx, AvPairs.pair[4].Value.AvSingleHost.token_info.Flags, 0, "Value.AvSingleHost.token_info.Flags");
	torture_assert_int_equal(tctx, AvPairs.pair[4].Value.AvSingleHost.token_info.TokenIL, 0x00003000, "Value.AvSingleHost.token_info.TokenIL");
	torture_assert_mem_equal(tctx, AvPairs.pair[4].Value.AvSingleHost.token_info.MachineId, MachineId, 32, "Value.AvSingleHost.token_info.MachineId");
	torture_assert_int_equal(tctx, AvPairs.pair[4].Value.AvSingleHost.remaining.length, 0, "Value.AvSingleHost.remaining.length");

	torture_assert_int_equal(tctx, AvPairs.pair[5].AvId, MsvChannelBindings, "AvId");
	torture_assert_int_equal(tctx, AvPairs.pair[5].AvLen, 16, "AvLen");
	torture_assert_mem_equal(tctx, AvPairs.pair[5].Value.ChannelBindings, lm_challenge_response, 16, "Value.ChannelBindings");

	torture_assert_int_equal(tctx, AvPairs.pair[6].AvId, MsvAvTargetName, "AvId");
	torture_assert_int_equal(tctx, AvPairs.pair[6].AvLen, 26, "AvLen");
	torture_assert_str_equal(tctx, AvPairs.pair[6].Value.AvTargetName, "cifs/mthelena", "Value.AvTargetName");

	torture_assert_int_equal(tctx, AvPairs.pair[7].AvId, MsvAvEOL, "AvId");
	torture_assert_int_equal(tctx, AvPairs.pair[7].AvLen, 0, "AvLen");

	torture_assert_int_equal(tctx, r->DomainNameLen, 14, "DomainNameLen");
	torture_assert_int_equal(tctx, r->DomainNameMaxLen, 14, "DomainNameMaxLen");
	torture_assert_str_equal(tctx, r->DomainName, "W2K8DOM", "DomainName");

	torture_assert_int_equal(tctx, r->UserNameLen, 26, "UserNameLen");
	torture_assert_int_equal(tctx, r->UserNameMaxLen, 26, "UserNameMaxLen");
	torture_assert_str_equal(tctx, r->UserName, "Administrator", "UserName");

	torture_assert_int_equal(tctx, r->WorkstationLen, 12, "WorkstationLen");
	torture_assert_int_equal(tctx, r->WorkstationMaxLen, 12, "WorkstationMaxLen");
	torture_assert_str_equal(tctx, r->Workstation, "W2K8R2", "Workstation");

	torture_assert_int_equal(tctx, r->EncryptedRandomSessionKeyLen, 16, "EncryptedRandomSessionKeyLen");
	torture_assert_int_equal(tctx, r->EncryptedRandomSessionKeyMaxLen, 16, "EncryptedRandomSessionKeyMaxLen");
	torture_assert_mem_equal(tctx, r->EncryptedRandomSessionKey->data, EncryptedRandomSessionKey, 16, "EncryptedRandomSessionKeyMaxLen");

	torture_assert_int_equal(tctx, r->NegotiateFlags, 0xe2888215, "NegotiateFlags");

	torture_assert_int_equal(tctx, r->Version.version.ProductMajorVersion, NTLMSSP_WINDOWS_MAJOR_VERSION_6, "ProductMajorVersion");
	torture_assert_int_equal(tctx, r->Version.version.ProductMinorVersion, NTLMSSP_WINDOWS_MINOR_VERSION_1, "ProductMinorVersion");
	torture_assert_int_equal(tctx, r->Version.version.ProductBuild, 0x1db0, "ProductBuild");
	torture_assert_int_equal(tctx, r->Version.version.Reserved[0], 0x00, "Reserved");
	torture_assert_int_equal(tctx, r->Version.version.Reserved[1], 0x00, "Reserved");
	torture_assert_int_equal(tctx, r->Version.version.Reserved[2], 0x00, "Reserved");
	torture_assert_int_equal(tctx, r->Version.version.NTLMRevisionCurrent, NTLMSSP_REVISION_W2K3, "NTLMRevisionCurrent");

	return true;
}

struct torture_suite *ndr_ntlmssp_suite(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "ntlmssp");

	torture_suite_add_ndr_pull_test(suite, NEGOTIATE_MESSAGE, ntlmssp_NEGOTIATE_MESSAGE_data, ntlmssp_NEGOTIATE_MESSAGE_check);
	torture_suite_add_ndr_pull_test(suite, CHALLENGE_MESSAGE, ntlmssp_CHALLENGE_MESSAGE_data, ntlmssp_CHALLENGE_MESSAGE_check);
	torture_suite_add_ndr_pull_test(suite, AUTHENTICATE_MESSAGE, ntlmssp_AUTHENTICATE_MESSAGE_data, ntlmssp_AUTHENTICATE_MESSAGE_check);

	torture_suite_add_ndr_pull_validate_test(suite,
					    NEGOTIATE_MESSAGE,
					    ntlmssp_NEGOTIATE_MESSAGE_data,
					    ntlmssp_NEGOTIATE_MESSAGE_check);

	torture_suite_add_ndr_pull_validate_test(suite,
					    CHALLENGE_MESSAGE,
					    ntlmssp_CHALLENGE_MESSAGE_data,
					    ntlmssp_CHALLENGE_MESSAGE_check);

	return suite;
}
