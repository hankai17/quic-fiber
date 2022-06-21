# quic-fiber
A QUIC implementation in C++11 coroutine. 
This project using [my_sylar](https://github.com/hankai17/my_sylar) lib and refering [quic-go](https://github.com/lucas-clemente/quic-go)

# TODO List
1. tls1.3 handshake
2. session's life cycle and some class/struct reconstruction 
3. API/function/frame optimization for sending interval & cpu usage
4. test

# Done
1. reliable & flow control & congestion control
2. stream's life cycle
3. user layer read/write/close
4. drawing script for more info(recv/send data & congestion win & send ack & so on)
