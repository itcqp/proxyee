package com.github.monkeywie.proxyee.connect;

import io.netty.channel.Channel;
import io.netty.util.Attribute;
import io.netty.util.AttributeKey;

import java.util.ArrayDeque;
import java.util.Queue;

/**
 * 同一客户端 TCP 连接上 HTTP/1.1 只能串行下发多个响应；多上游 HTTP/2 流并发写同一 {@link Channel} 会导致编码错乱与对端 RST（见 debug 交错 streamLogId）。
 * <p>仅在客户端 I/O 线程调用 {@link #enterOrEnqueue} / {@link #completeCurrentResponse}。
 */
public final class ClientResponseGate {

    private static final AttributeKey<ClientResponseGate> ATTR =
            AttributeKey.valueOf("cursor.proxy.clientResponseGate");

    public static ClientResponseGate forChannel(Channel ch) {
        Attribute<ClientResponseGate> attr = ch.attr(ATTR);
        ClientResponseGate g = attr.get();
        if (g != null) {
            return g;
        }
        ClientResponseGate ng = new ClientResponseGate();
        if (!attr.compareAndSet(null, ng)) {
            return attr.get();
        }
        return ng;
    }

    private final Queue<Runnable> waiting = new ArrayDeque<>();
    private boolean inFlight;

    private ClientResponseGate() {}

    public synchronized void enterOrEnqueue(Runnable beginResponse) {
        if (!inFlight) {
            inFlight = true;
            beginResponse.run();
        } else {
            waiting.add(beginResponse);
        }
    }

    public synchronized void completeCurrentResponse() {
        Runnable next = waiting.poll();
        if (next != null) {
            next.run();
        } else {
            inFlight = false;
        }
    }
}
