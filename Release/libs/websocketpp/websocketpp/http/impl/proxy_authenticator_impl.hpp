/*
 * Copyright (c) 2016, Peter Thorson. All rights reserved.
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

#ifndef HTTP_PROXY_AUTHENTICATOR_IMPL_HPP
#define HTTP_PROXY_AUTHENTICATOR_IMPL_HPP

#include <string>
#include <algorithm>
#include <locale>
#include <cctype>

namespace {
    static inline std::vector<std::string> split(const std::string& input, char delim = ' ')
    {
        std::stringstream ss(input);
        std::string line;
        std::vector<std::string> lines;

        while (std::getline(ss, line, delim))
            lines.push_back(line);

        return lines;
    }

    static std::string toLower(const std::string& input)
    {
        auto result = input;

        std::transform(result.begin(), result.end(), result.begin(), ::tolower);

        return result;
    }

    static std::string normalizeScheme(const std::string& scheme)
    {
        static std::map<std::string, std::string> normalizedSchemeName =
        {
            { "negotiate",  "Negotiate" },
            { "ntlm",       "NTLM" },
        };

        auto it = normalizedSchemeName.find(toLower(scheme));

        if (it != normalizedSchemeName.end())
            return it->second;

        return "";
    }

    //
    // This validates the initial scheme provided by the server, supporting the following formats
    //
    //   Proxy-Authenticate: NTLM
    //   Proxy-Authenticate: Negotiate
    //   Proxy-Authenticate: NTLM,Negotiate
    //
    static std::vector<std::string> getAuthSchemes(const std::string& proxy_auth_headers)
    {
        std::vector<std::string> schemes;

        auto headers = split(proxy_auth_headers, ',');

        for (auto header : headers)
        {
            std::vector<std::string> schemeParts = split(header, ',');

            for (auto scheme : schemeParts)
            {
                auto normalizedScheme = normalizeScheme(scheme);

                if (!normalizedScheme.empty())
                    schemes.push_back(normalizedScheme);
            }
        }

        return schemes;
    }

    static std::string selectAuthScheme(const std::string& proxy_auth_headers)
    {
        std::vector<std::string> authSchemes = getAuthSchemes(proxy_auth_headers);

        std::vector<std::string> authSchemePriority{ "Negotiate", "NTLM" }; // Normalized scheme's in priority order

        for (auto priority : authSchemePriority)
        {
            for (auto scheme : authSchemes)
            {
                if (priority == scheme)
                    return scheme;
            }
        }

        return "";
    }

    static std::string getAuthChallenge(const std::string& authScheme, const std::string& proxy_auth_headers_collection)
    {
        std::vector<std::string> proxy_auth_headers = split(proxy_auth_headers_collection, ',');

        for (auto header : proxy_auth_headers)
        {
            auto thisScheme = header.substr(0, authScheme.length());

            if (toLower(thisScheme) == toLower(authScheme))
            {
                auto parts = split(header, ' ');

                if (parts.size() == 2)
                {
                    return parts[1];
                }
            }
        }
        return "";
    }
}

namespace websocketpp {
    namespace http {
        namespace proxy {

                template <typename security_context>
                bool proxy_authenticator<security_context>::next_token(const std::string& auth_headers)
                {
                    if (!m_security_context) {
                        m_auth_scheme = selectAuthScheme(auth_headers);

                        if (m_auth_scheme.empty()) {
                            return false;
                        }

                        m_security_context = lib::make_shared<security_context>(m_proxy, m_auth_scheme);
                    }

                    if (!m_security_context) {
                        return false;
                    }

                    auto challenge = getAuthChallenge(m_auth_scheme, auth_headers);

                    m_security_context->nextAuthToken(challenge);

                    m_auth_token = m_security_context->getUpdatedToken();

                    return m_auth_token.empty() ? false : true;
                }
        }   // namespace proxy
    }       // namespace http
}           // namespace websocketpp

//#include <websocketpp/http/impl/proxy_authenticator.hpp>

#endif // HTTP_PROXY_AUTHENTICATOR_IMPL_HPP
