# TCP echo server.
add_executable(tcp_echo "tcp_echo/main.cpp")
target_link_libraries(tcp_echo PRIVATE onion::onion)
