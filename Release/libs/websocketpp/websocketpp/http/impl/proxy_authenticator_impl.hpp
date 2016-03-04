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

namespace websocketpp {
    namespace http {
        namespace proxy {
            namespace auth_parser {
                /**
                * Ref: https://tools.ietf.org/html/rfc7235 "2.1 Challenge and Response"
                *
                * challenge   = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
                *
                * and in our case auth-scheme is one of "NTLM", "Negotiate", "Basic" or "Digest"
                *
                * auth-param     = token BWS "=" BWS ( token / quoted-string )
                *
                * BWS is basically 'optional' white space
                *
                * token68        = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
                */

                inline bool icompareCh(char lhs, char rhs) {
                    return(::toupper(lhs) == ::toupper(rhs));
                }
                inline bool icompare(const std::string& s1, const std::string& s2) {
                    return((s1.size() == s2.size()) &&
                        std::equal(s1.begin(), s1.end(), s2.begin(), icompareCh));
                }

                /// Read and return the next token in the stream
                inline bool is_token68_char(unsigned char c) {
                    if (::isalpha(c)) return true;
                    if (::isdigit(c)) return true;

                    switch (c) {
                    case '-': return true;
                    case '.': return true;
                    case '_': return true;
                    case '~': return true;
                    case '+': return true;
                    case '/': return true;
                    case '=': return true; // padding char (not strictly part of the 68!)
                    }

                    return false;
                }
                /// Is the character a non-token
                inline bool is_not_token68_char(unsigned char c) {
                    return !is_token68_char(c);
                }
                template <typename InputIterator>
                std::pair<std::string, InputIterator> extract_token68(InputIterator begin,
                    InputIterator end)
                {
                    InputIterator it = std::find_if(begin, end, &is_not_token68_char);
                    return std::make_pair(std::string(begin, it), it);
                }

                class AuthScheme
                {
                public:
                    AuthScheme(const std::string& name="") : m_name(name), m_type(Unknown)
                    {
                        if (icompare(m_name, "basic"))      m_type = Basic;
                        if (icompare(m_name, "digest"))     m_type = Digest;
                        if (icompare(m_name, "ntlm"))       m_type = NTLM;
                        if (icompare(m_name, "negotiate"))  m_type = Negotiate;
                    }

                    std::string get_name()      const { return m_name;      }
                    std::string get_challenge() const { return m_challenge; }

                    bool is_known()     const { return m_type == Unknown   ? false : true; }
                    bool is_basic()     const { return m_type == Basic     ? true : false; }
                    bool is_digest()    const { return m_type == Digest    ? true : false; }
                    bool is_ntlm()      const { return m_type == NTLM      ? true : false; }
                    bool is_negotiate() const { return m_type == Negotiate ? true : false; }

                    static bool comparePriority(AuthScheme const& lhs, AuthScheme const& rhs) {
                        return lhs.m_type > rhs.m_type;
                    }

                    template <typename InputIterator>
                    inline InputIterator parse(InputIterator begin, InputIterator end) {
                        switch (m_type)
                        {
                        case Basic:     return parse_basic(begin, end);
                        case NTLM:      return parse_ntlm_negotiate(begin, end);
                        case Negotiate: return parse_ntlm_negotiate(begin, end);
                        }

                        return begin;
                    }

                private:
                    enum scheme_type { Unknown, Basic, Digest, NTLM, Negotiate };

                    typedef std::pair<std::string, std::string> KeyValue;

                    std::string m_name;
                    scheme_type m_type;
                    std::vector<KeyValue> m_params;
                    std::string m_challenge;

                    template <typename InputIterator>
                    inline InputIterator parse_basic(InputIterator begin, InputIterator end) {
                        auto cursor = http::parser::extract_all_lws(begin, end);

                        while (cursor != end) {
                            auto next = http::parser::extract_token(cursor, end);

                            if (!next.first.empty()) {
                                if (AuthScheme(next.first).is_known()) {
                                    return cursor;
                                }

                                auto key = next.first;

                                cursor = next.second;

                                if (*cursor != '=') {
                                    return cursor;
                                }

                                // Advance past the '='
                                ++cursor;

                                if (cursor == end) {
                                    return cursor;
                                }

                                next = http::parser::extract_quoted_string(cursor, end);

                                if (next.first.empty()) {
                                    next = http::parser::extract_token(cursor, end);
                                }

                                if (next.first.empty()) {
                                    return cursor;
                                }

                                m_params.push_back(KeyValue(key, next.first));

                                cursor = next.second;

                                if (cursor != end && *cursor == ',') {
                                    ++cursor;
                                }
                            }
                        }

                        return cursor;
                    }

                    template <typename InputIterator>
                    InputIterator parse_ntlm_negotiate(InputIterator begin, InputIterator end) {
                        auto cursor = http::parser::extract_all_lws(begin, end);

                        auto next = extract_token68(cursor, end);

                        if (!next.first.empty()) {
                            m_challenge = next.first;

                            cursor = next.second;
                        }

                        return cursor;
                    }

                };

                typedef std::vector<AuthScheme> AuthSchemes;

                template <typename InputIterator>
                inline std::pair<AuthScheme, InputIterator> parse_auth_scheme(InputIterator begin, InputIterator end) {
                    auto cursor = begin;

                    auto next = http::parser::extract_token(cursor, end);

                    AuthScheme scheme(next.first);

                    if (scheme.is_known() && next.second != end) {
                        cursor = next.second;
                        cursor = http::parser::extract_all_lws(cursor, end);

                        cursor = scheme.parse(cursor, end);
                    }

                    return std::make_pair(scheme, cursor);
                }

                template <typename InputIterator>
                inline AuthSchemes parse_auth_schemes(InputIterator begin, InputIterator end) {
                    AuthSchemes auth_schemes;

                    InputIterator cursor = begin;

                    while (cursor != end) {
                        auto next = parse_auth_scheme(cursor, end);

                        if (!next.first.is_known()) {
                            return AuthSchemes();
                        }

                        auth_schemes.push_back(next.first);

                        cursor = next.second;

                        if (cursor != end) {
                            if (*cursor != ',') {
                                return AuthSchemes();
                            }
                            ++cursor;

                            cursor = http::parser::extract_all_lws(cursor + 1, end);
                        }
                    }

                    return auth_schemes;
                }

                AuthScheme select_auth_scheme(std::string const & auth_headers)
                {
                    auto auth_schemes = parse_auth_schemes(auth_headers.begin(), auth_headers.end());

                    if (auth_schemes.empty()) {
                        return AuthScheme();
                    }

                    std::stable_sort(auth_schemes.begin(), auth_schemes.end(), AuthScheme::comparePriority);

                    return auth_schemes.front();
                }

                AuthScheme parse_auth_scheme(std::string const & auth_header) {
                    auto result = parse_auth_scheme(auth_header.begin(), auth_header.end());

                    return result.first;
                }
            }

            //
            // 'proxy_authenticator' implementation
            //
            template <typename security_context>
            bool proxy_authenticator<security_context>::next_token(const std::string& auth_headers)
            {
                auth_parser::AuthScheme auth_scheme;

                if (!m_security_context) {
                    auth_scheme = auth_parser::select_auth_scheme(auth_headers);

                    if (!auth_scheme.is_known()) {
                        return false;
                    }

                    m_auth_scheme_name = auth_scheme.get_name();

                    m_security_context = lib::make_shared<security_context>(m_proxy, m_auth_scheme_name);
                }
                else {
                    auth_scheme = auth_parser::parse_auth_scheme(auth_headers);
                }

                if (!m_security_context || !auth_scheme.is_known()) {
                    return false;
                }

                m_security_context->nextAuthToken(auth_scheme.get_challenge());

                m_auth_token       = m_security_context->getUpdatedToken();

                return m_auth_token.empty() ? false : true;
            }
        }   // namespace proxy
    }       // namespace http
}           // namespace websocketpp

//#include <websocketpp/http/impl/proxy_authenticator.hpp>

#endif // HTTP_PROXY_AUTHENTICATOR_IMPL_HPP
