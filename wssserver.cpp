#include <iostream>
#include <string>
#include <winsock2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <websocket.h>

extern "C"
{
#include <openssl/applink.c>
};

const int PORT = 52500;
const std::string PEM_CERT_FILE = "server.pem";
const std::string PEM_KEY_FILE = "key.pem";
const std::string PEM_PASS_PHRASE = "test";
const int BUFFER_SIZE = 1024;

int verify_callback(int preverify, X509_STORE_CTX* x509_ctx) {
    std::cout << "Verifying " << preverify << std::endl;
    return 1;
    char buf[256];
    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 256);
    std::cout << "Verifying " << buf << std::endl;

    if (preverify == 1) {
        std::cout << "Verification passed." << std::endl;
        return 1;
    }

    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);
    std::cout << "Verification failed at depth " << depth << " with error " << X509_verify_cert_error_string(err) << std::endl;
    return 0;
}
int password_cb2(char* buf, int size, int rwflag, void* userdata) {
    std::string passphrase = PEM_PASS_PHRASE;
    strncpy(buf, passphrase.c_str(), size);
    buf[size - 1] = '\0';
    return strlen(buf);
}

void handle_error(const char* error_message) {
    std::cerr << error_message << ": " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
    exit(1);
}

void handle_socket_error(const char* error_message) {
    std::cerr << error_message << ": " << WSAGetLastError() << std::endl;
    WSACleanup();
    exit(1);
}

int main() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    WSADATA wsa_data;
    int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (result != 0) {
        handle_socket_error("WSAStartup failed");
    }

    SOCKET server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket == INVALID_SOCKET) {
        handle_socket_error("socket failed");
    }

    u_long iMode = 0;
    ioctlsocket(server_socket, FIONBIO, &iMode);

    sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.S_un.S_addr = INADDR_ANY;
    result = bind(server_socket, reinterpret_cast<sockaddr*>(&server_address), sizeof(server_address));
    if (result == SOCKET_ERROR) {
        handle_socket_error("bind failed");
    }

    result = listen(server_socket, SOMAXCONN);
    if (result == SOCKET_ERROR) {
        handle_socket_error("listen failed");
    }

    SSL_CTX* ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    if (ssl_ctx == nullptr) {
        handle_error("SSL_CTX_new failed");
    }

    result = SSL_CTX_use_certificate_file(ssl_ctx, PEM_CERT_FILE.c_str(), SSL_FILETYPE_PEM);
    if (result != 1) {
        handle_error("SSL_CTX_use_certificate_file failed");
    }
    //result = SSL_CTX_use_certificate_chain_file(ssl_ctx, PEM_CERT_FILE.c_str());
    //if (result != 1) {
    //    handle_error("SSL_CTX_use_certificate_file failed");
    //}

    SSL_CTX_set_default_passwd_cb(ssl_ctx, password_cb2);
    result = SSL_CTX_use_PrivateKey_file(ssl_ctx, PEM_KEY_FILE.c_str(), SSL_FILETYPE_PEM);
    if (result != 1) {
        handle_error("SSL_CTX_use_PrivateKey_file failed");
    }

    result = SSL_CTX_check_private_key(ssl_ctx);
    if (result != 1) {
        handle_error("SSL_CTX_check_private_key failed");
    }

    RSA* rsa = RSA_generate_key(512, RSA_F4, NULL, NULL);
    SSL_CTX_set_tmp_rsa(ssl_ctx, rsa);
    RSA_free(rsa);

    //SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, 0);
    SSL_CTX_set_verify_depth(ssl_ctx, 0);

    while (true) {
        sockaddr_in client_address;
        int client_address_length = sizeof(client_address);
        SOCKET client_socket = accept(server_socket, reinterpret_cast<sockaddr*>(&client_address), &client_address_length);
        if (client_socket == INVALID_SOCKET) {
            handle_socket_error("accept failed");
        }

        SSL* ssl = SSL_new(ssl_ctx);
        if (ssl == nullptr) {
            handle_error("SSL_new failed");
        }

        result = SSL_set_fd(ssl, client_socket);
        if (result != 1) {
            handle_error("SSL_set_fd failed");
        }

        result = SSL_accept(ssl);
        if (result != 1) {
            printf("Unable to accept SSL connection: %d\n",result);
            int error = SSL_get_error(ssl, result);
            switch (error) {
            case SSL_ERROR_WANT_READ:
                printf("Unable to accept SSL connection: SSL_ERROR_WANT_READ\n");
                // The operation needs to wait for more data from the socket
                break;
            case SSL_ERROR_WANT_WRITE:
                printf("Unable to accept SSL connection: SSL_ERROR_WANT_WRITE\n");
                // The operation needs to write more data to the socket
                break;
            case SSL_ERROR_SYSCALL:
                printf("Unable to accept SSL connection: SSL_ERROR_SYSCALL\n");
                // A system call error occurred
                break;
            case SSL_ERROR_SSL:
                printf("Unable to accept SSL connection: SSL_ERROR_SSL\n");
                // An error occurred in the SSL library
                break;
            default:
                // An unknown error occurred
                printf("Unable to accept SSL connection: unknown error\n");
                break;
            }
            handle_error("SSL_accept failed");
        }

        printf("SSL_accept done\n\n");

        char buffer[BUFFER_SIZE];
        result = SSL_read(ssl, buffer, BUFFER_SIZE);
        if (result <= 0) {
            handle_error("SSL_read failed");
        }

        std::cout << "Received: " << buffer << std::endl;

        ws_req_t ws_req;
        parse_websocket_request(buffer, &ws_req);
        print_websocket_request(&ws_req);

        std::string str = generate_websocket_response(&ws_req);

        result = SSL_write(ssl, str.c_str(), str.length());
        if (result <= 0) {
            handle_error("SSL_write failed");
        }

        printf("SSL handshake done\n\n");

        int ntoread = 2;
        memset(buffer, 0, BUFFER_SIZE);
        result = SSL_read(ssl, buffer, ntoread);
        if (result <= 0) {
            handle_error("SSL_read failed");
        }
        
        std::cout << "Received: " << buffer << std::endl;

        frame_t frame;
        if (parse_frame_header(buffer, &frame) != 0) {
            handle_error("parse_frame_header failed");
        }

        LOG("FIN         = %lu", frame.fin);
        LOG("OPCODE      = %lu", frame.opcode);
        LOG("MASK        = %lu", frame.mask);
        LOG("PAYLOAD_LEN = %lu", frame.payload_len);
        
        if (frame.payload_len == 126)
        {
            ntoread = 2;
            memset(buffer, 0, BUFFER_SIZE);
            SSL_read(ssl, buffer, ntoread);
            frame.payload_len = ntohs(*(uint16_t*)buffer);
            ntoread = 4;
        }
        else if (frame.payload_len == 127)
        {
            ntoread = 8;
            memset(buffer, 0, BUFFER_SIZE);
            SSL_read(ssl, buffer, ntoread);
            frame.payload_len = myntohll(*(uint64_t*)buffer);
            ntoread = 4;
        }
        else if (frame.payload_len < 126)
        {
            ntoread = 4;
        }
        else
        {
            LOG("PAYLOAD_LEN = %lu", frame.payload_len);
            continue;
            handle_error("frame.payload_len error");
        }

        LOG("---- STEP 3 ----");
        memset(buffer, 0, BUFFER_SIZE);
        SSL_read(ssl, buffer, ntoread);
        memcpy(frame.masking_key, buffer, ntoread);

        if (frame.payload_len == 0)
        {
            printf("frame.payload_len == 0 no handle yet \n\n");
            continue;
        }
        else
        {
            ntoread = frame.payload_len;
            LOG("PAYLOAD_LEN Before STEP 4 = %lu", frame.payload_len);
        }

        LOG("---- STEP 4 ----");
        if (frame.payload_len > 0) {
            //if (frame.payload_data) {
            //    delete[] frame.payload_data;
            //    frame.payload_data = NULL;
            //}
            frame.payload_data = new char[frame.payload_len];
            SSL_read(ssl, frame.payload_data, frame.payload_len);
            unmask_payload_data(&frame);
        }

        /*recv a whole frame*/
        if (frame.fin == 1 && frame.opcode == 0x8) {
            //0x8 denotes a connection close
            //frame_buffer_t* fb = frame_buffer_new(1, 8, 0, NULL);
            //send_a_frame(conn, fb);
            LOG("send a close frame");
            //frame_buffer_free(fb);
            break;
        }
        else if (frame.fin == 1 && frame.opcode == 0x9) {
            //0x9 denotes a ping
            //TODO
            //make a pong
            LOG("TODO: make a pong");
        }
        else {
            //execute custom operation
            LOG("TODO: maybe execute custom operation");
        }

        if (frame.opcode == 0x1) { //0x1 denotes a text frame
            LOG("text frame : %s", frame.payload_data);
        }
        if (frame.opcode == 0x2) { //0x2 denotes a binary frame
            LOG("binary frame len %lu : %s", frame.payload_len, frame.payload_data);
        }

        frame_buffer_t* fb = frame_buffer_new(1, 1, frame.payload_len, frame.payload_data);
        int bytes_sent = SSL_write(ssl, fb->data, fb->len);
        LOG("SSL_write bytes_sent=%d, frame.payload_len=%lu, frame.payload_data=%s", bytes_sent, frame.payload_len, frame.payload_data);
        frame_buffer_free(fb);

        LOG("connection disconnected");
        SSL_free(ssl);
        closesocket(client_socket);
    }

    LOG("servet stopped");
    SSL_CTX_free(ssl_ctx);
    WSACleanup();
    return 0;
}
