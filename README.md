# quic-fiber
  A QUIC implementation in C++11 coroutine. 
This project using [my_sylar](https://github.com/hankai17/my_sylar) lib and refering [quic-go](https://github.com/lucas-clemente/quic-go)
and this is a toy version for verifying tcp transfer control etc. There is no license for this project. 
If you have any questions or interest in this project, please submit issue and pr.

# Done
1. reliable, flow control, and congestion control(reno, cubic, [BBR](https://github.com/hankai17/quic-fiber/tree/bbr))
2. user layer read/write/close
3. drawing script for more info

# TODO
1. TLS1.3 handshake
2. session life cycle and some frame's func
3. refactoring struct/class/API/func/frame
4. tests

![congestion.png](https://github.com/hankai17/quic-fiber/blob/main/reno.png)
![congestion.png](https://github.com/hankai17/quic-fiber/blob/main/cubic.png)

