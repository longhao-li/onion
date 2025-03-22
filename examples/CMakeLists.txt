# TCP echo server.
add_executable(tcp_echo_server tcp_echo_server.cpp)
target_link_libraries(tcp_echo_server PRIVATE onion)

# UDP echo server.
add_executable(udp_echo_server udp_echo_server.cpp)
target_link_libraries(udp_echo_server PRIVATE onion)
