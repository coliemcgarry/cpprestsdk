/*
 * Copyright (c) 2014, Peter Thorson. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the WebSocket++ Project nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL PETER THORSON BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef WEBSOCKETPP_COMMON_SECURITY_CONTEXT_HPP
#define WEBSOCKETPP_COMMON_SECURITY_CONTEXT_HPP

#include <websocketpp/base64/base64.hpp>

#ifdef _WIN32

#define SECURITY_WIN32

#include <sspi.h>

#define SEC_SUCCESS(Status) ((Status) >= 0)

#pragma comment(lib, "Secur32.lib")

namespace websocketpp {
    namespace lib {
        namespace security {
            class SecurityContext
            {
            public:
                using Ptr = std::shared_ptr<SecurityContext>;

                SecurityContext(const std::string& proxyName, const std::string& authScheme) :
                    proxyName(proxyName), authScheme(authScheme)
                {
                    TimeStamp           Lifetime;
                    SECURITY_STATUS     ss;

                    ss = ::AcquireCredentialsHandleW(
                        NULL,
                        (SEC_WCHAR *)authScheme.c_str(),
                        SECPKG_CRED_OUTBOUND,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        &hCred,
                        &Lifetime);

                    if (!(SEC_SUCCESS(ss)))
                    {
                        return;
                    }

                    freeCredentials = true;
                }
                ~SecurityContext()
                {
                    if (freeCredentials) {
                        ::FreeCredentialsHandle(&hCred);
                    }
                }

                bool SecurityContext::nextAuthToken(const std::string& challenge)
                {
                    TimeStamp           Lifetime;
                    SECURITY_STATUS     ss;
                    SecBufferDesc       OutBuffDesc;
                    SecBuffer           OutSecBuff;
                    ULONG               ContextAttributes;

                    OutBuffDesc.ulVersion = SECBUFFER_VERSION;
                    OutBuffDesc.cBuffers = 1;
                    OutBuffDesc.pBuffers = &OutSecBuff;

                    OutSecBuff.cbBuffer = 0;
                    OutSecBuff.BufferType = SECBUFFER_TOKEN;
                    OutSecBuff.pvBuffer = 0;

                    std::string target;

                    if (authScheme == "Negotiate")
                        target = "http/" + proxyName; // Service Principle Name

                    if (challenge.empty())
                    {
                        ss = ::InitializeSecurityContextW(
                            &hCred,
                            NULL,
                            (SEC_WCHAR *)target.c_str(), //.c_str(), // pszTarget,
                            ISC_REQ_ALLOCATE_MEMORY, //ISC_REQ_CONFIDENTIALITY ,
                            0,
                            SECURITY_NETWORK_DREP, //SECURITY_NATIVE_DREP,
                            NULL,
                            0,
                            &hContext,
                            &OutBuffDesc,
                            &ContextAttributes,
                            &Lifetime);
                    }
                    else
                    {
                        auto decodedChallenge = base64_decode(challenge);

                        SecBufferDesc     InBuffDesc;
                        SecBuffer         InSecBuff;

                        InBuffDesc.ulVersion = 0;
                        InBuffDesc.cBuffers = 1;
                        InBuffDesc.pBuffers = &InSecBuff;

                        InSecBuff.cbBuffer = (unsigned long)decodedChallenge.size();
                        InSecBuff.BufferType = SECBUFFER_TOKEN;
                        InSecBuff.pvBuffer = (BYTE *)&decodedChallenge[0];

                        ss = ::InitializeSecurityContextW(
                            &hCred,
                            &hContext,
                            (SEC_WCHAR *)target.c_str(),
                            ISC_REQ_ALLOCATE_MEMORY, //ISC_REQ_CONFIDENTIALITY ,
                            0,
                            SECURITY_NETWORK_DREP, // SECURITY_NATIVE_DREP,
                            &InBuffDesc,
                            0,
                            &hContext,
                            &OutBuffDesc,
                            &ContextAttributes,
                            &Lifetime);
                    }

                    if ((SEC_I_COMPLETE_NEEDED == ss) || (SEC_I_COMPLETE_AND_CONTINUE == ss))
                    {
                        ss = ::CompleteAuthToken(&hContext, &OutBuffDesc);

                        if (!SEC_SUCCESS(ss))
                        {
                            return false;
                        }
                    }

                    if (!OutSecBuff.pvBuffer)
                    {
                        return false;
                    }

                    //auto itFirst = (unsigned char *)OutSecBuff.pvBuffer;
                    //auto itLast = (unsigned char *)OutSecBuff.pvBuffer + OutSecBuff.cbBuffer;
                    //
                    //const std::vector<unsigned char> data(itFirst, itLast);

                    updatedToken = base64_encode((const unsigned char*) OutSecBuff.pvBuffer, (size_t) OutSecBuff.cbBuffer); //  utility::conversions::to_base64(data);

                    ::FreeContextBuffer(OutSecBuff.pvBuffer);

                    bool continueAuthFlow = ((SEC_I_CONTINUE_NEEDED == ss) || (SEC_I_COMPLETE_AND_CONTINUE == ss));

                    return continueAuthFlow;
                }

                const std::string& SecurityContext::getUpdatedToken() const
                {
                    return updatedToken;
                }

            private:
                SecHandle               hContext;
                CredHandle              hCred;
                std::string       proxyName;
                std::string       authScheme;
                std::string       updatedToken;

                bool                    freeCredentials = false;
            };
        }
    }
}
#endif // WIN32
#endif // WEBSOCKETPP_COMMON_SECURITY_CONTEXT_HPP
