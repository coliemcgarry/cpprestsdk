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

#ifndef HTTP_PROXY_AUTHENTICATOR_HPP
#define HTTP_PROXY_AUTHENTICATOR_HPP

#include <string>

//#include <websocketpp/http/response.hpp>

namespace websocketpp {
namespace http {
namespace proxy {

/// Implements Proxy Authentication 
/**
 *
 */
class proxy_authenticator {
public:
    typedef lib::shared_ptr<proxy_authenticator> ptr;

    proxy_authenticator(const std::string& proxy) : m_proxy(proxy) {

        tokens.push_back("NTLM TlRMTVNTUAABAAAAB7IIogUABQA2AAAADgAOACgAAAAGAbEdAAAAD0NNQ0dBUlJZLUc2NVpIQ0lTQ08=");
        tokens.push_back("NTLM TlRMTVNTUAADAAAAAAAAAFgAAAAAAAAAWAAAAAAAAABYAAAAAAAAAFgAAAAAAAAAWAAAAAAAAABYAAAABcKIogYBsR0AAAAP1+Twk7iR2Eoju93dlWLb5w==");

    }

    std::string get_proxy() {
        return m_proxy;
    }

    std::string next_token(const std::string& auth_headers) {
        auto result = currentToken >= 0 ? tokens[currentToken] : std::string();

        if(currentToken < 2)
            currentToken++;

        return result;
    }

    void set_authenticated() {
    }

    std::string get_auth_token() {
        auto result = currentToken >= 0 ? tokens[currentToken] : std::string();

        return result;
    }

private:
    std::string m_proxy;

    std::vector<std::string> tokens;
    int currentToken = -1;
};

} // namespace proxy
} // namespace http
} // namespace websocketpp

//#include <websocketpp/http/impl/proxy_authenticator.hpp>

#endif // HTTP_PROXY_AUTHENTICATOR_HPP
