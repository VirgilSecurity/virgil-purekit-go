/*
 * Copyright (C) 2015-2018 Virgil Security Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

package passw0rd

import (
	"encoding/asn1"

	"github.com/passw0rd/phe-go"

	"github.com/pkg/errors"
)

func MarshalUpdateToken(a, b []byte) (res []byte) {
	token := phe.UpdateToken{
		A: a,
		B: b,
	}

	res, err := asn1.Marshal(token)

	if err != nil {
		panic(err)
	}
	return res
}

func UnmarshalUpdateToken(updateToken []byte) (token *phe.UpdateToken, err error) {

	token = &phe.UpdateToken{}
	rest, err := asn1.Unmarshal(updateToken, token)

	if len(rest) != 0 || err != nil {
		return nil, errors.Wrap(err, "invalid token")
	}

	return
}

type DbRecord struct {
	Version        int
	NS, NC, T0, T1 []byte
}

func MarshalRecord(version int, rec *phe.EnrollmentRecord) ([]byte, error) {
	dbRec := DbRecord{
		Version: version,
		NS:      rec.NS,
		NC:      rec.NC,
		T0:      rec.T0,
		T1:      rec.T1,
	}

	res, err := asn1.Marshal(dbRec)

	if err != nil {
		panic(err)
	}
	return res, nil
}

func UnmarshalRecord(record []byte) (version int, rec *phe.EnrollmentRecord, err error) {

	dbRecord := &DbRecord{}
	rest, err := asn1.Unmarshal(record, dbRecord)

	if len(rest) != 0 || err != nil {
		return 0, nil, errors.Wrap(err, "invalid db record")
	}

	return dbRecord.Version, &phe.EnrollmentRecord{
		NS: dbRecord.NS,
		NC: dbRecord.NC,
		T0: dbRecord.T0,
		T1: dbRecord.T1,
	}, nil
}
