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
* The initial version of this Security Context policy was contributed to the WebSocket++
* project by Colie McGarry.
*/

#ifndef WEBSOCKETPP_CONFIG_ASIO_TLS_CLIENT_PROXY_AUTHENTICATED_HPP
#define WEBSOCKETPP_CONFIG_ASIO_TLS_CLIENT_PROXY_AUTHENTICATED_HPP

#include <websocketpp/config/core_client.hpp>
#include <websocketpp/transport/asio/endpoint.hpp>
#include <websocketpp/transport/asio/security/tls.hpp>

// Pull in non-tls config
#include <websocketpp/config/asio_no_tls_client.hpp>

#include <websocketpp/http/proxy_authenticator.hpp>
#include <websocketpp/common/impl/security_context.hpp>

// Define TLS config
namespace websocketpp {
namespace config {

/// Client config with asio transport and TLS enabled
struct asio_tls_client_authenticated_proxy : public core_client {
    typedef asio_tls_client_authenticated_proxy type;
    typedef core_client base;

    typedef base::concurrency_type concurrency_type;

    typedef base::request_type request_type;
    typedef base::response_type response_type;

    typedef base::message_type message_type;
    typedef base::con_msg_manager_type con_msg_manager_type;
    typedef base::endpoint_msg_manager_type endpoint_msg_manager_type;

    typedef base::alog_type alog_type;
    typedef base::elog_type elog_type;

    typedef base::rng_type rng_type;

    typedef websocketpp::lib::security::platform::SecurityContext security_context;
    typedef websocketpp::http::proxy::proxy_authenticator<security_context> proxy_authenticator_type;

    struct transport_config : public base::transport_config {
        typedef type::concurrency_type concurrency_type;
        typedef type::alog_type alog_type;
        typedef type::elog_type elog_type;
        typedef type::request_type request_type;
        typedef type::response_type response_type;
        typedef websocketpp::transport::asio::tls_socket::endpoint socket_type;
        typedef type::proxy_authenticator_type proxy_authenticator_type;
    };

    typedef websocketpp::transport::asio::endpoint<transport_config>
        transport_type;
};

} // namespace config
} // namespace websocketpp

#endif // WEBSOCKETPP_CONFIG_ASIO_TLS_CLIENT_HPP
