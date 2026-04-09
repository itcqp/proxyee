package com.github.monkeywie.proxyee.connect;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

/** 本会话调试 NDJSON（{@code debug-d04054.log}）。 */
public final class SessionDebugLog {

    public static final String PATH =
            Paths.get(System.getProperty("user.dir", "."), "debug-d04054.log").toAbsolutePath().toString();

    private static final String SESSION = "d04054";

    private SessionDebugLog() {}

    public static String esc(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    public static void line(String hypothesisId, String location, String message, String dataJsonObject) {
        try {
            String line =
                    "{\"sessionId\":\""
                            + SESSION
                            + "\",\"timestamp\":"
                            + System.currentTimeMillis()
                            + ",\"hypothesisId\":\""
                            + esc(hypothesisId)
                            + "\",\"location\":\""
                            + esc(location)
                            + "\",\"message\":\""
                            + esc(message)
                            + "\",\"data\":"
                            + dataJsonObject
                            + "}\n";
            Files.write(Paths.get(PATH), line.getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (Throwable ignored) {
        }
    }
}
