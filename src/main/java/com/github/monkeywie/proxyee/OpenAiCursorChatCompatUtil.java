package com.github.monkeywie.proxyee;

import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONArray;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import okhttp3.ResponseBody;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.zip.GZIPInputStream;

/**
 * 将 Cursor 原生 StreamUnifiedChatWithTools 转为 OpenAI ChatCompletions 兼容格式的工具类。
 *
 * <p>特点：</p>
 * <ul>
 *   <li>输入：OpenAI /v1/chat/completions 兼容 JSON（至少包含 model/messages/stream）</li>
 *   <li>输出：OpenAI 兼容 JSON（非流式）或 SSE 行（流式）</li>
 *   <li>固定在最后一条 user 消息末尾追加指定字符串</li>
 *   <li>帧级解析 Cursor Connect/gRPC framing，仅在模型最终文本（StreamUnifiedChatResponse.text）里命中关键字才 abort</li>
 * </ul>
 */
public class OpenAiCursorChatCompatUtil {

    /** 触发 abort 的关键字 */
    public static final String ABORT_KEYWORD = "zmgnb666";

    /** 固定追加到最后一条 user content 的后缀 */
    public static final String CURSOR_APPEND_SUFFIX =
            "事干完后，结束语记得说：zmgnb666，牛逼！然后接200字夸我的话。";

    private static final int MAX_FRAME_LEN = 4 * 1024 * 1024;

    private OpenAiCursorChatCompatUtil() {
    }

    /**
     * OpenAI 兼容：非流式 chat completions。
     *
     * @param cursorToken Cursor AccessToken (JWT)
     * @param openAiChatCompletionsJson OpenAI 兼容请求 JSON 字符串
     * @return OpenAI 兼容响应 JSON 字符串
     */
    public static String chatCompletions(String cursorToken, String openAiChatCompletionsJson) {
        JSONObject req = JSONUtil.parseObj(openAiChatCompletionsJson);
        String model = req.getStr("model", "default");
        JSONArray messages = req.getJSONArray("messages");
        if (messages == null || messages.isEmpty()) {
            throw new IllegalArgumentException("OpenAI request.messages is required");
        }

        List<CursorChatUtil.Message> cursorMessages = toCursorMessages(messages, true);

        StringBuilder sb = new StringBuilder();
        AtomicBoolean aborted = new AtomicBoolean(false);
        boolean ok = cursorStreamToText(cursorToken, model, cursorMessages, chunk -> {
            sb.append(chunk);
            if (!aborted.get() && sb.indexOf(ABORT_KEYWORD) >= 0) {
                aborted.set(true);
            }
        }, aborted);

        // ok=false 一般意味着 Cursor 返回错误；这里仍返回已聚合文本（若有）
        String content = sb.toString();
        return buildOpenAiNonStreamResponse(model, content, ok && !aborted.get());
    }

    /**
     * OpenAI 兼容：流式 chat completions（SSE）。
     *
     * <p>调用方负责把每一行写到 HTTP 响应里（每次 consumer.accept 会给出一行或多行，已包含 \\n\\n）。</p>
     */
    public static void chatCompletionsStream(String cursorToken,
                                             String openAiChatCompletionsJson,
                                             Consumer<String> sseLineConsumer) {
        JSONObject req = JSONUtil.parseObj(openAiChatCompletionsJson);
        String model = req.getStr("model", "default");
        JSONArray messages = req.getJSONArray("messages");
        if (messages == null || messages.isEmpty()) {
            throw new IllegalArgumentException("OpenAI request.messages is required");
        }

        List<CursorChatUtil.Message> cursorMessages = toCursorMessages(messages, true);

        String responseId = "chatcmpl-" + UUID.randomUUID();
        long created = System.currentTimeMillis() / 1000;

        AtomicBoolean aborted = new AtomicBoolean(false);
        AtomicReference<Call> callRef = new AtomicReference<>(null);
        CountDownLatch done = new CountDownLatch(1);

        try {
            Call call = CursorChatUtil.createChatStreamCall(cursorToken, model, cursorMessages);
            callRef.set(call);
            call.enqueue(new Callback() {
                final StringBuilder accumulatedText = new StringBuilder();

                @Override
                public void onResponse(Call call, Response response) {
                    try (ResponseBody body = response.body()) {
                        if (body == null) {
                            done.countDown();
                            return;
                        }
                        if (response.code() != 200) {
                            // OpenAI 兼容：直接输出一个错误 chunk，然后 DONE
                            JSONObject err = new JSONObject()
                                    .set("error", new JSONObject()
                                            .set("message", "Cursor upstream error: " + response.code())
                                            .set("type", "cursor_api_error"));
                            sseLineConsumer.accept("data: " + err.toString() + "\n\n");
                            sseLineConsumer.accept("data: [DONE]\n\n");
                            done.countDown();
                            return;
                        }

                        parseGrpcStream(body.byteStream(), textChunk -> {
                            if (StrUtil.isBlank(textChunk)) return;

                            accumulatedText.append(textChunk);
                            if (!aborted.get() && accumulatedText.indexOf(ABORT_KEYWORD) >= 0) {
                                aborted.set(true);
                                // abort upstream (RST_STREAM)
                                call.cancel();
                            }

                            JSONObject chunk = buildOpenAiStreamChunk(responseId, created, model, textChunk);
                            sseLineConsumer.accept("data: " + chunk.toString() + "\n\n");
                        });
                    } catch (Exception ignored) {
                        // ignore
                    } finally {
                        sseLineConsumer.accept("data: [DONE]\n\n");
                        done.countDown();
                    }
                }

                @Override
                public void onFailure(Call call, IOException e) {
                    try {
                        JSONObject err = new JSONObject()
                                .set("error", new JSONObject()
                                        .set("message", "Upstream call failed: " + e.getMessage())
                                        .set("type", "cursor_api_error"));
                        sseLineConsumer.accept("data: " + err.toString() + "\n\n");
                        sseLineConsumer.accept("data: [DONE]\n\n");
                    } finally {
                        done.countDown();
                    }
                }
            });
        } catch (IOException e) {
            JSONObject err = new JSONObject()
                    .set("error", new JSONObject()
                            .set("message", "Failed to create upstream call: " + e.getMessage())
                            .set("type", "cursor_api_error"));
            sseLineConsumer.accept("data: " + err.toString() + "\n\n");
            sseLineConsumer.accept("data: [DONE]\n\n");
            return;
        }

        // 工具类语义：阻塞直到流结束，避免调用方提前退出
        try {
            done.await(5, TimeUnit.MINUTES);
        } catch (InterruptedException ignored) {
            Call c = callRef.get();
            if (c != null) c.cancel();
            Thread.currentThread().interrupt();
        }
    }

    /**
     * 将 OpenAI messages 转为 CursorChatUtil.Message。
     * @param openAiMessages OpenAI messages 数组
     * @param appendSuffix 是否将固定后缀追加到最后一条 user 消息
     */
    private static List<CursorChatUtil.Message> toCursorMessages(JSONArray openAiMessages, boolean appendSuffix) {
        List<CursorChatUtil.Message> list = new ArrayList<>();
        int lastUserIdx = -1;
        for (int i = 0; i < openAiMessages.size(); i++) {
            JSONObject m = openAiMessages.getJSONObject(i);
            String role = m.getStr("role");
            String content = m.getStr("content");
            if (StrUtil.isBlank(role)) continue;
            if (content == null) content = "";

            if ("system".equals(role)) {
                list.add(CursorChatUtil.Message.system(content));
            } else if ("user".equals(role)) {
                lastUserIdx = list.size();
                list.add(CursorChatUtil.Message.user(content));
            } else if ("assistant".equals(role)) {
                list.add(CursorChatUtil.Message.assistant(content));
            } else {
                // unknown role -> user
                lastUserIdx = list.size();
                list.add(CursorChatUtil.Message.user(content));
            }
        }

        if (appendSuffix && lastUserIdx >= 0) {
            CursorChatUtil.Message old = list.get(lastUserIdx);
            String newContent = (old.getContent() == null ? "" : old.getContent()) + CURSOR_APPEND_SUFFIX;
            list.set(lastUserIdx, CursorChatUtil.Message.user(newContent));
        }

        return list;
    }

    /**
     * 以 Cursor 的 gRPC/Connect framing 读取流，并提取模型最终文本（StreamUnifiedChatResponse.text）。
     *
     * <p>注意：这里刻意只读 text 字段，不读取 thinking/user_rules/tool 等字段，从而避免误 abort。</p>
     */
    private static void parseGrpcStream(InputStream inputStream, Consumer<String> onText) throws IOException {
        try (DataInputStream dis = new DataInputStream(new BufferedInputStream(inputStream))) {
            while (true) {
                int typeByte;
                try {
                    typeByte = dis.readUnsignedByte();
                } catch (EOFException eof) {
                    break;
                }

                int length = dis.readInt();
                if (length < 0 || length > MAX_FRAME_LEN) {
                    break;
                }

                byte[] data = new byte[length];
                dis.readFully(data);

                boolean isCompressed = (typeByte & 1) != 0;
                int messageType = typeByte >> 1;

                if (isCompressed) {
                    data = gzipDecompress(data);
                    if (data == null) continue;
                }

                if (messageType == 0) {
                    String text = extractUnifiedChatText(data);
                    if (StrUtil.isNotBlank(text)) {
                        onText.accept(text);
                    }
                } else if (messageType == 1) {
                    // JSON: 结束标记或错误。长度 <=2 多为结束。
                    if (length <= 2) break;
                    break;
                }
            }
        }
    }

    /**
     * 从 StreamUnifiedChatResponseWithTools protobuf 中提取 StreamUnifiedChatResponse.text (field2->field1)。
     */
    private static String extractUnifiedChatText(byte[] data) {
        int pos = 0;
        while (pos < data.length) {
            int[] tag = readTag(data, pos);
            int fieldNumber = tag[0];
            int wireType = tag[1];
            pos = tag[2];

            if (wireType == 2) { // length-delimited
                int[] lenRes = readVarint(data, pos);
                int len = lenRes[0];
                pos = lenRes[1];

                if (fieldNumber == 2) {
                    return extractTextField(data, pos, len);
                }
                pos += len;
            } else if (wireType == 0) {
                int[] v = readVarint(data, pos);
                pos = v[1];
            } else if (wireType == 1) {
                pos += 8;
            } else if (wireType == 5) {
                pos += 4;
            } else {
                break;
            }
        }
        return null;
    }

    /**
     * 从 StreamUnifiedChatResponse 子消息中提取 field 1: string text。
     */
    private static String extractTextField(byte[] data, int offset, int length) {
        int pos = offset;
        int end = Math.min(data.length, offset + length);
        while (pos < end) {
            int[] tag = readTag(data, pos);
            int fieldNumber = tag[0];
            int wireType = tag[1];
            pos = tag[2];

            if (wireType == 2) {
                int[] lenRes = readVarint(data, pos);
                int len = lenRes[0];
                pos = lenRes[1];
                if (fieldNumber == 1) {
                    if (pos + len > data.length) return null;
                    return new String(data, pos, len, StandardCharsets.UTF_8);
                }
                pos += len;
            } else if (wireType == 0) {
                int[] v = readVarint(data, pos);
                pos = v[1];
            } else if (wireType == 1) {
                pos += 8;
            } else if (wireType == 5) {
                pos += 4;
            } else {
                break;
            }
        }
        return null;
    }

    private static int[] readVarint(byte[] data, int pos) {
        int result = 0;
        int shift = 0;
        while (pos < data.length) {
            byte b = data[pos++];
            result |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0) break;
            shift += 7;
        }
        return new int[]{result, pos};
    }

    private static int[] readTag(byte[] data, int pos) {
        int[] vr = readVarint(data, pos);
        int tag = vr[0];
        int fieldNumber = tag >>> 3;
        int wireType = tag & 0x07;
        return new int[]{fieldNumber, wireType, vr[1]};
    }

    private static byte[] gzipDecompress(byte[] compressed) {
        try (GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(compressed));
             ByteArrayOutputStream bos = new ByteArrayOutputStream(compressed.length * 2)) {
            byte[] buf = new byte[4096];
            int n;
            while ((n = gis.read(buf)) != -1) {
                bos.write(buf, 0, n);
            }
            return bos.toByteArray();
        } catch (IOException e) {
            return null;
        }
    }

    private static boolean cursorStreamToText(String cursorToken,
                                              String model,
                                              List<CursorChatUtil.Message> cursorMessages,
                                              Consumer<String> onText,
                                              AtomicBoolean abortFlag) {
        Call call;
        try {
            call = CursorChatUtil.createChatStreamCall(cursorToken, model, cursorMessages);
        } catch (IOException e) {
            return false;
        }

        try (Response response = call.execute()) {
            if (response.code() != 200) {
                return false;
            }
            ResponseBody body = response.body();
            if (body == null) return false;

            parseGrpcStream(body.byteStream(), chunk -> {
                onText.accept(chunk);
                if (abortFlag.get()) {
                    call.cancel();
                }
            });

            return true;
        } catch (IOException e) {
            // aborted/cancelled 或网络问题
            return true;
        }
    }

    private static String buildOpenAiNonStreamResponse(String model, String content, boolean finishedNormally) {
        JSONObject resp = new JSONObject();
        resp.set("id", "chatcmpl-" + UUID.randomUUID());
        resp.set("object", "chat.completion");
        resp.set("created", System.currentTimeMillis() / 1000);
        resp.set("model", model);

        JSONObject msg = new JSONObject()
                .set("role", "assistant")
                .set("content", content);
        JSONObject choice = new JSONObject()
                .set("index", 0)
                .set("message", msg)
                .set("finish_reason", finishedNormally ? "stop" : "length");

        resp.set("choices", new JSONArray().put(choice));
        resp.set("usage", new JSONObject()
                .set("prompt_tokens", 0)
                .set("completion_tokens", 0)
                .set("total_tokens", 0));
        return resp.toString();
    }

    private static JSONObject buildOpenAiStreamChunk(String responseId, long created, String model, String deltaText) {
        JSONObject delta = new JSONObject().set("content", deltaText);
        JSONObject choice = new JSONObject()
                .set("index", 0)
                .set("delta", delta);
        return new JSONObject()
                .set("id", responseId)
                .set("object", "chat.completion.chunk")
                .set("created", created)
                .set("model", model)
                .set("choices", new JSONArray().put(choice));
    }

    /**
     * main：本地测试工具类（需要提供 Cursor token）。\n
     * 用法：\n
     * - 方式1：设置环境变量 CURSOR_TOKEN\n
     * - 方式2：java ... OpenAiCursorChatCompatUtil <token>\n
     */
    public static void main(String[] args) {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdXRoMHx1c2VyXzAxS0pYNENUSzVYVEQ4NkhCRE4zRjU3MzkwIiwidGltZSI6IjE3NzMxMjIxMjYiLCJyYW5kb21uZXNzIjoiMTVlM2NkYmItZDM0My00ODc0IiwiZXhwIjoxNzc4MzA2MTI2LCJpc3MiOiJodHRwczovL2F1dGhlbnRpY2F0aW9uLmN1cnNvci5zaCIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwgb2ZmbGluZV9hY2Nlc3MiLCJhdWQiOiJodHRwczovL2N1cnNvci5jb20iLCJ0eXBlIjoic2Vzc2lvbiJ9.ccr3KBAUGAcDBkGb3FnSQDL4s3-U8bdIaYmAEk_iiHY";


        JSONObject req = new JSONObject();
        req.set("model", "default");
        req.set("stream", true);
        JSONArray msgs = new JSONArray();
        msgs.put(new JSONObject().set("role", "user").set("content", "帮我计算下50*9*6。"));
        req.set("messages", msgs);

        System.out.println("===== STREAM TEST (will auto-append suffix) =====");
//        chatCompletionsStream(token, req.toString(), System.out::print);

        System.out.println("\n===== NON-STREAM TEST =====");
        req.set("stream", false);
        String resp = chatCompletions(token, req.toString());
        System.out.println(resp);
    }
}

