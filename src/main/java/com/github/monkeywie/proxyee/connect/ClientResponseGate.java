package com.github.monkeywie.proxyee.connect;

import io.netty.channel.Channel;
import io.netty.util.Attribute;
import io.netty.util.AttributeKey;

import java.io.FileWriter;
import java.util.ArrayDeque;
import java.util.Queue;

/**
 * 同一客户端 TCP 连接上 HTTP/1.1 只能串行下发多个响应；多上游 HTTP/2 流并发写同一 {@link Channel} 会导致编码错乱与对端 RST（见 debug 交错 streamLogId）。
 * <p>仅在客户端 I/O 线程调用 {@link #enterOrEnqueue} / {@link #completeCurrentResponse}。
 */
public final class ClientResponseGate {

    private static final AttributeKey<ClientResponseGate> ATTR =
            AttributeKey.valueOf("cursor.proxy.clientResponseGate");
    private static final String DEBUG_SESSION_LOG_PATH = "D:/devin/playgame/proxyee63/debug-3d2f37.log";
    private static final String DEBUG_SESSION_ID = "3d2f37";

    public static ClientResponseGate forChannel(Channel ch) {
        Attribute<ClientResponseGate> attr = ch.attr(ATTR);
        ClientResponseGate g = attr.get();
        if (g != null) {
            return g;
        }
        ClientResponseGate ng = new ClientResponseGate(ch.id().asShortText());
        if (!attr.compareAndSet(null, ng)) {
            return attr.get();
        }
        return ng;
    }

    private final Queue<Runnable> waiting = new ArrayDeque<>();
    private final String gateId;
    private boolean inFlight;

    private ClientResponseGate(String gateId) {
        this.gateId = gateId;
    }

    public synchronized void enterOrEnqueue(Runnable beginResponse) {
        if (!inFlight) {
            // #region agent log
            dbg("gate-" + gateId, "H14",
                    "ClientResponseGate.enterOrEnqueue",
                    "gate_enter_start",
                    "{\"inFlightBefore\":false,\"queueSizeBefore\":" + waiting.size() + "}");
            // #endregion
            inFlight = true;
            beginResponse.run();
        } else {
            waiting.add(beginResponse);
            // #region agent log
            dbg("gate-" + gateId, "H14",
                    "ClientResponseGate.enterOrEnqueue",
                    "gate_enter_queued",
                    "{\"inFlightBefore\":true,\"queueSizeAfter\":" + waiting.size() + "}");
            // #endregion
        }
    }

    public synchronized void completeCurrentResponse() {
        Runnable next = waiting.poll();
        if (next != null) {
            // #region agent log
            dbg("gate-" + gateId, "H14",
                    "ClientResponseGate.completeCurrentResponse",
                    "gate_complete_dequeue_next",
                    "{\"queueSizeAfterPoll\":" + waiting.size() + "}");
            // #endregion
            next.run();
        } else {
            inFlight = false;
            // #region agent log
            dbg("gate-" + gateId, "H14",
                    "ClientResponseGate.completeCurrentResponse",
                    "gate_complete_idle",
                    "{\"queueSizeAfterPoll\":0}");
            // #endregion
        }
    }

    private static void dbg(String runId, String hypothesisId, String loc, String msg, String data) {
        try (FileWriter fw = new FileWriter(DEBUG_SESSION_LOG_PATH, true)) {
            fw.write("{\"sessionId\":\"" + DEBUG_SESSION_ID
                    + "\",\"runId\":\"" + esc(runId)
                    + "\",\"hypothesisId\":\"" + esc(hypothesisId)
                    + "\",\"location\":\"" + esc(loc)
                    + "\",\"message\":\"" + esc(msg)
                    + "\",\"data\":" + (data != null ? data : "null")
                    + ",\"timestamp\":" + System.currentTimeMillis() + "}\n");
        } catch (Exception ignored) {
        }
    }

    private static String esc(String s) {
        if (s == null) {
            return "null";
        }
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }
}
