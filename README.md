LTNG
====

A lighting fast web server!

I've mostly started this project for learning purposes. However, since I'm attempting to learn more about writing really high performance, really robust, really secure code, LTNG will probably alse be pretty awesome by the time it's stable. That's the goal anyway.

There's some key functionality that I'm shooting for:

* Event-driven with epoll (epoll is super fast)
* Threaded using edge-triggered events (level triggered + threads = blegh)
* SPDY support (because SPDY is awesome)
* Reverse proxy capability (because static files alone are kinda boring)
* Completely asynchronous I/O (if there are performance gains there)
* Robustness, load should cripple the hardware before LTNG ;D

I hope to work on this as much as possible, but due to school and work that probably won't be more than a days worth of work per week.
